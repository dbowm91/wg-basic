#![cfg(all(target_os = "linux", feature = "linux-integration"))]

use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wg_basic::{
    domain::{ClientRoutePolicy, DesiredGeneration, NetworkPrefix},
    management::set_password_at,
    product::{AdvertisedEndpoint, ProductService, ServerSetupCommand},
    state::StateStore,
};

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "wg-basic-maintenance-{}-{}",
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
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Namespace(String);
impl Namespace {
    fn new() -> Self {
        let name = format!(
            "wgp{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        assert!(Command::new("ip")
            .args(["netns", "add", &name])
            .status()
            .unwrap()
            .success());
        assert!(Command::new("ip")
            .args(["-n", &name, "link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success());
        Self(name)
    }
}
impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).status();
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
fn purge_requires_confirmed_disabled_noop_network_and_preserves_operator_files() {
    let uid = std::fs::metadata("/proc/self").unwrap().uid();
    assert_eq!(uid, 0, "rootful maintenance fixture must run as root");
    let temp = Temp::new();
    let namespace = Namespace::new();
    let state = temp.0.join("state.db");
    let socket = temp.0.join("netd.sock");
    let mut netd = ChildGuard(
        Command::new("ip")
            .args(["netns", "exec", &namespace.0, BINARY, "netd", "--socket"])
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "netd did not bind its socket");
        assert!(netd.0.try_wait().unwrap().is_none(), "netd exited early");
        thread::sleep(Duration::from_millis(10));
    }

    drop(StateStore::initialize(&state).unwrap());
    set_password_at(&state, "admin", "maintenance fixture password").unwrap();
    let store = StateStore::open(&state).unwrap();
    let principal = store.principals().unwrap()[0].id;
    ProductService::new(&store)
        .setup_server(ServerSetupCommand {
            principal_id: principal,
            expected_generation: DesiredGeneration::default(),
            interface_name: "wg0".parse().unwrap(),
            tunnel_prefix: NetworkPrefix::new("10.238.0.0/24".parse().unwrap()),
            ipv6_tunnel_prefix: None,
            server_address: None,
            ipv6_server_address: None,
            listen_port: 51820,
            advertised_endpoint: AdvertisedEndpoint::new("198.18.0.1", 51820).unwrap(),
            egress_interface: "lo".parse().unwrap(),
            ipv4_forwarding_required: false,
            ipv6_forwarding_required: false,
            masquerade: false,
            default_client_route_policy: ClientRoutePolicy::default(),
        })
        .unwrap();
    let identity = store.installation_metadata().unwrap().installation_id;
    drop(store);
    let runtime = wg_basic::management::ManagementRuntime::open(&state, &socket).unwrap();
    let applied = runtime.reconcile_current().unwrap().unwrap();
    assert!(applied.converged);
    drop(runtime);

    let refusal = Command::new(BINARY)
        .args([
            "state",
            "purge",
            "--confirm-installation-id",
            &identity.to_string(),
            "--state",
        ])
        .arg(&state)
        .args(["--socket"])
        .arg(&socket)
        .output()
        .unwrap();
    assert!(!refusal.status.success());
    assert!(String::from_utf8_lossy(&refusal.stderr).contains("network must be disabled"));

    let disabled = Command::new(BINARY)
        .args(["network", "disable", "--state"])
        .arg(&state)
        .args(["--socket"])
        .arg(&socket)
        .output()
        .unwrap();
    assert!(
        disabled.status.success(),
        "{}",
        String::from_utf8_lossy(&disabled.stderr)
    );
    assert!(String::from_utf8_lossy(&disabled.stdout).contains("and enforced"));

    let operator_backup = temp.0.join("operator-backup.db");
    std::fs::write(&operator_backup, b"operator owned").unwrap();
    std::fs::set_permissions(&operator_backup, std::fs::Permissions::from_mode(0o600)).unwrap();
    let dry_run = Command::new(BINARY)
        .args([
            "state",
            "purge",
            "--confirm-installation-id",
            &identity.to_string(),
            "--dry-run",
            "--state",
        ])
        .arg(&state)
        .args(["--socket"])
        .arg(&socket)
        .output()
        .unwrap();
    assert!(
        dry_run.status.success(),
        "{}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let report = String::from_utf8_lossy(&dry_run.stdout);
    assert!(report.contains(state.to_str().unwrap()));
    assert!(report.contains("state.db.serve.lock"));
    assert!(report.contains("operator backups/configuration"));
    assert!(state.exists(), "dry-run must not remove the database");

    let purge = Command::new(BINARY)
        .args([
            "state",
            "purge",
            "--confirm-installation-id",
            &identity.to_string(),
            "--state",
        ])
        .arg(&state)
        .args(["--socket"])
        .arg(&socket)
        .output()
        .unwrap();
    assert!(
        purge.status.success(),
        "{}",
        String::from_utf8_lossy(&purge.stderr)
    );
    assert!(!state.exists());
    assert!(
        operator_backup.exists(),
        "operator backups are never purge targets"
    );
    assert!(temp.0.join("state.db.serve.lock").exists());
    let link = Command::new("ip")
        .args(["-n", &namespace.0, "link", "show", "wg0"])
        .output()
        .unwrap();
    assert!(!link.status.success());
}
