use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wg_basic::{doctor::DoctorReport, state::StateStore};

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "wg-basic-doctor-readonly-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn doctor_json_does_not_change_database_or_host_network_state() {
    let temporary = TempDirectory::new();
    let database = temporary.0.join("state.db");
    let socket = temporary.0.join("netd.sock");
    drop(StateStore::initialize(&database).unwrap());

    let mut netd = ChildGuard(
        Command::new(BINARY)
            .args(["netd", "--socket"])
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "netd did not bind its private socket"
        );
        if let Some(status) = netd.0.try_wait().unwrap() {
            panic!("netd exited before binding: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }

    let database_before = std::fs::read(&database).unwrap();
    let entries_before = entries(&temporary.0);
    let routes_before = std::fs::read("/proc/net/route").unwrap();
    let links_before = link_state_snapshot();
    let forwarding_before = std::fs::read("/proc/sys/net/ipv4/ip_forward").unwrap();

    let output = Command::new(BINARY)
        .args(["doctor", "--state"])
        .arg(&database)
        .args(["--socket"])
        .arg(&socket)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.stderr.is_empty(), "doctor emitted unexpected stderr");
    let report: DoctorReport = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(report.exit_code()));
    assert!(report.checks.iter().any(|check| {
        check.id == wg_basic::doctor::DoctorCheckId::State
            && check.disposition == wg_basic::doctor::DoctorDisposition::Pass
    }));
    assert!(report.checks.iter().any(|check| {
        check.id == wg_basic::doctor::DoctorCheckId::NetworkOwnership
            && check.disposition == wg_basic::doctor::DoctorDisposition::Pass
    }));

    assert_eq!(std::fs::read(&database).unwrap(), database_before);
    assert_eq!(entries(&temporary.0), entries_before);
    assert_eq!(std::fs::read("/proc/net/route").unwrap(), routes_before);
    assert_eq!(link_state_snapshot(), links_before);
    assert_eq!(
        std::fs::read("/proc/sys/net/ipv4/ip_forward").unwrap(),
        forwarding_before
    );
}

fn entries(directory: &Path) -> Vec<std::ffi::OsString> {
    let mut result = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    result.sort();
    result
}

fn link_state_snapshot() -> Vec<(String, Vec<(String, String)>)> {
    let mut links = std::fs::read_dir("/sys/class/net")
        .unwrap()
        .map(|entry| {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            let root = Path::new("/sys/class/net").join(&name);
            let mut attributes = ["ifindex", "iflink", "ifalias", "operstate", "mtu"]
                .into_iter()
                .map(|attribute| {
                    let value = std::fs::read_to_string(root.join(attribute))
                        .unwrap_or_default()
                        .trim()
                        .to_owned();
                    (attribute.to_owned(), value)
                })
                .collect::<Vec<_>>();
            attributes.sort();
            (name, attributes)
        })
        .collect::<Vec<_>>();
    links.sort_by(|left, right| left.0.cmp(&right.0));
    links
}

#[cfg(feature = "linux-integration")]
#[test]
fn doctor_plan_only_diagnoses_managed_drift_without_mutating_the_namespace() {
    use std::os::unix::fs::MetadataExt;
    use wg_basic::{
        domain::{ClientRoutePolicy, DesiredGeneration, NetworkPrefix},
        management::set_password_at,
        product::{AdvertisedEndpoint, ProductService, ServerSetupCommand},
    };

    let uid = std::fs::metadata("/proc/self").unwrap().uid();
    assert_eq!(uid, 0, "linux-integration doctor test must run as root");
    let temporary = TempDirectory::new();
    let database = temporary.0.join("state.db");
    let socket = temporary.0.join("netd.sock");
    let namespace = format!(
        "wgd{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    assert!(Command::new("ip")
        .args(["netns", "add", &namespace])
        .status()
        .unwrap()
        .success());
    let namespace_guard = NamespaceGuard(namespace.clone());
    assert!(Command::new("ip")
        .args(["-n", &namespace, "link", "set", "lo", "up"])
        .status()
        .unwrap()
        .success());

    drop(StateStore::initialize(&database).unwrap());
    set_password_at(&database, "admin", "doctor test password").unwrap();
    let store = StateStore::open(&database).unwrap();
    let principal = store.principals().unwrap()[0].id;
    ProductService::new(&store)
        .setup_server(ServerSetupCommand {
            principal_id: principal,
            expected_generation: DesiredGeneration::default(),
            interface_name: "wg0".parse().unwrap(),
            tunnel_prefix: NetworkPrefix::new("10.239.0.0/24".parse().unwrap()),
            server_address: None,
            listen_port: 51820,
            advertised_endpoint: AdvertisedEndpoint::new("198.18.0.1", 51820).unwrap(),
            egress_interface: "lo".parse().unwrap(),
            ipv4_forwarding_required: false,
            masquerade: false,
            default_client_route_policy: ClientRoutePolicy::default(),
        })
        .unwrap();
    drop(store);

    let mut netd = ChildGuard(
        Command::new("ip")
            .args(["netns", "exec", &namespace, BINARY, "netd", "--socket"])
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&socket, &mut netd.0);
    let before = namespace_network_snapshot(&namespace);
    let database_before = std::fs::read(&database).unwrap();

    let output = Command::new(BINARY)
        .args(["doctor", "--state"])
        .arg(&database)
        .args(["--socket"])
        .arg(&socket)
        .arg("--json")
        .output()
        .unwrap();
    let report: DoctorReport = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(report.exit_code()));
    assert_disposition(
        &report,
        wg_basic::doctor::DoctorCheckId::NetworkOwnership,
        wg_basic::doctor::DoctorDisposition::Warn,
    );
    assert_disposition(
        &report,
        wg_basic::doctor::DoctorCheckId::Rtnetlink,
        wg_basic::doctor::DoctorDisposition::Pass,
    );
    assert_disposition(
        &report,
        wg_basic::doctor::DoctorCheckId::Nftables,
        wg_basic::doctor::DoctorDisposition::Pass,
    );
    assert_eq!(namespace_network_snapshot(&namespace), before);
    assert_eq!(std::fs::read(&database).unwrap(), database_before);

    let state = wg_basic::state::inspect_readonly(&database).unwrap();
    let intent = wg_basic::management::project_diagnostic_intent(
        state.metadata.installation_id,
        state.desired.generation,
        &state.desired.state,
        &state.product,
    )
    .unwrap()
    .unwrap();
    assert!(matches!(
        wg_basic::protocol::request(
            &socket,
            wg_basic::protocol::RequestOperation::ApplyInstallationNetworkIntent { intent },
            91,
        )
        .unwrap(),
        wg_basic::protocol::ResponseBody::InstallationNetworkApplied(_)
    ));
    let before = namespace_network_snapshot(&namespace);
    let database_before = std::fs::read(&database).unwrap();
    let output = Command::new(BINARY)
        .args(["doctor", "--state"])
        .arg(&database)
        .args(["--socket"])
        .arg(&socket)
        .arg("--json")
        .output()
        .unwrap();
    let report: DoctorReport = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(report.exit_code()));
    assert_disposition(
        &report,
        wg_basic::doctor::DoctorCheckId::NetworkOwnership,
        wg_basic::doctor::DoctorDisposition::Pass,
    );
    assert_eq!(namespace_network_snapshot(&namespace), before);
    assert_eq!(std::fs::read(&database).unwrap(), database_before);

    assert!(Command::new("ip")
        .args(["-n", &namespace, "link", "del", "wg0"])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ip")
        .args(["-n", &namespace, "link", "add", "wg0", "type", "dummy"])
        .status()
        .unwrap()
        .success());
    let before = namespace_network_snapshot(&namespace);
    let database_before = std::fs::read(&database).unwrap();
    let output = Command::new(BINARY)
        .args(["doctor", "--state"])
        .arg(&database)
        .args(["--socket"])
        .arg(&socket)
        .arg("--json")
        .output()
        .unwrap();
    let report: DoctorReport = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(report.exit_code()));
    assert_disposition(
        &report,
        wg_basic::doctor::DoctorCheckId::NetworkOwnership,
        wg_basic::doctor::DoctorDisposition::Fail,
    );
    assert_eq!(namespace_network_snapshot(&namespace), before);
    assert_eq!(std::fs::read(&database).unwrap(), database_before);

    drop(netd);
    drop(namespace_guard);
}

#[cfg(feature = "linux-integration")]
fn assert_disposition(
    report: &DoctorReport,
    id: wg_basic::doctor::DoctorCheckId,
    expected: wg_basic::doctor::DoctorDisposition,
) {
    let check = report.checks.iter().find(|check| check.id == id).unwrap();
    assert_eq!(check.disposition, expected, "{}", check.summary);
}

#[cfg(feature = "linux-integration")]
struct NamespaceGuard(String);

#[cfg(feature = "linux-integration")]
impl Drop for NamespaceGuard {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).status();
    }
}

#[cfg(feature = "linux-integration")]
fn namespace_network_snapshot(namespace: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let links = Command::new("ip")
        .args(["-n", namespace, "-j", "link"])
        .output()
        .unwrap();
    assert!(links.status.success());
    let routes = Command::new("ip")
        .args(["-n", namespace, "-j", "route", "show", "table", "all"])
        .output()
        .unwrap();
    assert!(routes.status.success());
    let nft = Command::new("ip")
        .args(["netns", "exec", namespace, "nft", "-j", "list", "ruleset"])
        .output()
        .unwrap();
    assert!(nft.status.success());
    (links.stdout, routes.stdout, nft.stdout)
}

#[cfg(feature = "linux-integration")]
fn wait_for_socket(socket: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "netd did not bind its private socket"
        );
        if let Some(status) = child.try_wait().unwrap() {
            panic!("netd exited before binding: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}
