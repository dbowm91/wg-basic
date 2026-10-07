#![cfg(all(target_os = "linux", feature = "linux-integration"))]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wg_basic::{
    domain::{InterfaceName, NetworkPrefix, PrivateKey},
    protocol::{request, AuthorizationPolicy, RequestOperation, ResponseBody, SocketServer},
    reconcile::{
        ApplyStatus, DesiredAddress, DesiredManagedInterface, DesiredWireGuardConfiguration,
        LinkLifecycle, ManagedRoute, OwnershipDeclaration, ResourcePresence,
    },
    wireguard::generate_keypair,
};

fn command(program: &str, args: &[&str]) -> Output {
    Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("could not run {program}: {error}"))
}

fn run_ip(args: &[&str]) {
    let output = command("ip", args);
    assert!(
        output.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Namespace(String);

impl Namespace {
    fn new() -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("wgm4{suffix:x}");
        run_ip(&["netns", "add", &name]);
        Self(name)
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = command("ip", &["netns", "delete", &self.0]);
    }
}

struct Netd {
    child: Child,
    runtime: PathBuf,
    shutdown_file: PathBuf,
}

impl Netd {
    fn start(namespace: &str) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let runtime = std::env::temp_dir().join(format!("wgb-m004-{suffix:x}"));
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = runtime.join("netd.sock");
        let shutdown_file = runtime.join("shutdown");
        let executable = std::env::current_exe().unwrap();
        let child = Command::new("ip")
            .args(["netns", "exec", namespace])
            .arg(executable)
            .args(["--exact", "namespace_reconcile_netd_worker", "--nocapture"])
            .env("WG_BASIC_TEST_SOCKET", &socket)
            .env("WG_BASIC_TEST_SHUTDOWN", &shutdown_file)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("could not start netd in namespace");
        let started = Instant::now();
        while !socket.exists() {
            assert!(child.id() != 0);
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "netd socket did not appear"
            );
            thread::sleep(Duration::from_millis(10));
        }
        Self {
            child,
            runtime,
            shutdown_file,
        }
    }

    fn socket(&self) -> PathBuf {
        self.runtime.join("netd.sock")
    }
}

impl Drop for Netd {
    fn drop(&mut self) {
        let _ = fs::write(&self.shutdown_file, "shutdown");
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.runtime);
    }
}

#[test]
fn namespace_reconcile_netd_worker() {
    let (Some(socket), Some(shutdown_file)) = (
        std::env::var_os("WG_BASIC_TEST_SOCKET"),
        std::env::var_os("WG_BASIC_TEST_SHUTDOWN"),
    ) else {
        return;
    };
    let server =
        Arc::new(SocketServer::bind(socket, AuthorizationPolicy::current_user_and_root()).unwrap());
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = shutdown.clone();
    let worker = thread::spawn(move || server.run_until_shutdown(&thread_shutdown));
    let shutdown_path = PathBuf::from(shutdown_file);
    while !shutdown_path.exists() {
        thread::sleep(Duration::from_millis(10));
    }
    shutdown.store(true, Ordering::Release);
    worker.join().unwrap().unwrap();
}

fn apply(netd: &Netd, desired: DesiredManagedInterface) -> wg_basic::reconcile::ApplyReceipt {
    match request(
        &netd.socket(),
        RequestOperation::ApplyManagedInterface { desired },
        401,
    )
    .unwrap()
    {
        ResponseBody::ManagedInterfaceApplied(receipt) => receipt,
        _ => panic!("unexpected reconciliation response"),
    }
}

#[test]
fn kernel_reconciliation_manages_link_address_and_route_and_preserves_other_link() {
    if nix::unistd::geteuid().as_raw() != 0 {
        panic!("rootful integration test must run as root");
    }
    let probe = command("ip", &["netns", "list"]);
    assert!(probe.status.success(), "ip netns unavailable");

    let namespace = Namespace::new();
    run_ip(&[
        "-n",
        &namespace.0,
        "link",
        "add",
        "fixture0",
        "type",
        "dummy",
    ]);
    run_ip(&[
        "-n",
        &namespace.0,
        "addr",
        "add",
        "192.0.2.9/24",
        "dev",
        "fixture0",
    ]);
    run_ip(&["-n", &namespace.0, "link", "set", "fixture0", "up"]);
    run_ip(&[
        "-n",
        &namespace.0,
        "route",
        "add",
        "198.51.100.0/24",
        "dev",
        "fixture0",
    ]);
    run_ip(&[
        "-n",
        &namespace.0,
        "link",
        "add",
        "wg-wrong",
        "type",
        "dummy",
    ]);
    let netd = Netd::start(&namespace.0);
    let interface: InterfaceName = "wg-managed".parse().unwrap();
    let keypair = generate_keypair().unwrap();
    let private_key = keypair.private_key.expose_secret().to_owned();
    let managed_state = || DesiredManagedInterface {
        interface: interface.clone(),
        ownership: OwnershipDeclaration::Managed,
        lifecycle: LinkLifecycle::Present,
        admin_up: Some(true),
        wireguard: Some(DesiredWireGuardConfiguration {
            private_key: PrivateKey::new(private_key.clone()).unwrap(),
            listen_port: 51873,
            peers: Vec::new(),
            manage_all_peers: true,
        }),
        addresses: vec![DesiredAddress {
            address: "10.77.0.1/24".parse().unwrap(),
            presence: ResourcePresence::Present,
        }],
        routes: vec![ManagedRoute {
            destination: "203.0.113.0/24".parse::<NetworkPrefix>().unwrap(),
            gateway: None,
            presence: ResourcePresence::Present,
        }],
    };

    let first = apply(&netd, managed_state());
    assert_eq!(first.status, ApplyStatus::Applied, "receipt: {first:?}");
    assert!(first.completed_actions >= 4);
    let second = apply(&netd, managed_state());
    assert_eq!(second.status, ApplyStatus::NoChange);

    let wrong_kind_result = request(
        &netd.socket(),
        RequestOperation::PlanManagedInterface {
            desired: DesiredManagedInterface {
                interface: "wg-wrong".parse().unwrap(),
                ownership: OwnershipDeclaration::Managed,
                lifecycle: LinkLifecycle::Present,
                admin_up: Some(true),
                wireguard: None,
                addresses: Vec::new(),
                routes: Vec::new(),
            },
        },
        402,
    )
    .unwrap_err();
    assert_eq!(wrong_kind_result.kind(), std::io::ErrorKind::AlreadyExists);

    let preserved = command(
        "ip",
        &["-n", &namespace.0, "-o", "addr", "show", "dev", "fixture0"],
    );
    assert!(String::from_utf8_lossy(&preserved.stdout).contains("192.0.2.9/24"));

    let remove = DesiredManagedInterface {
        interface,
        ownership: OwnershipDeclaration::Managed,
        lifecycle: LinkLifecycle::Absent,
        admin_up: None,
        wireguard: None,
        addresses: vec![DesiredAddress {
            address: "10.77.0.1/24".parse().unwrap(),
            presence: ResourcePresence::Absent,
        }],
        routes: vec![ManagedRoute {
            destination: "203.0.113.0/24".parse::<NetworkPrefix>().unwrap(),
            gateway: None,
            presence: ResourcePresence::Absent,
        }],
    };
    assert_eq!(apply(&netd, remove).status, ApplyStatus::Applied);
    let fixture = command("ip", &["-n", &namespace.0, "link", "show", "fixture0"]);
    assert!(fixture.status.success(), "unrelated link did not survive");
    let preserved_route = command(
        "ip",
        &["-n", &namespace.0, "route", "show", "198.51.100.0/24"],
    );
    assert!(
        String::from_utf8_lossy(&preserved_route.stdout).contains("198.51.100.0/24"),
        "unrelated route did not survive"
    );
}
