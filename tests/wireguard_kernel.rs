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
    domain::{InterfaceName, NetworkPrefix, PublicKey},
    protocol::{request, AuthorizationPolicy, RequestOperation, ResponseBody, SocketServer},
    wireguard::{
        ApplyDisposition, DesiredWireGuardPeer, FieldUpdate, PeerMutation, WireGuardDevicePatch,
        WireGuardPeerPatch,
    },
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

fn unavailable(message: &str) -> bool {
    if std::env::var_os("CI").is_some() {
        panic!("required WireGuard kernel fixture unavailable: {message}");
    }
    eprintln!("SKIP: real WireGuard namespace test requires root and CAP_NET_ADMIN: {message}");
    true
}

struct Namespaces {
    a: String,
    b: String,
}
impl Namespaces {
    fn new() -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let fixture = Self {
            a: format!("wgb{suffix:x}a"),
            b: format!("wgb{suffix:x}b"),
        };
        for namespace in [&fixture.a, &fixture.b] {
            let output = command("ip", &["netns", "add", namespace]);
            if !output.status.success() {
                let _ = command("ip", &["netns", "delete", &fixture.a]);
                let _ = command("ip", &["netns", "delete", &fixture.b]);
                panic!(
                    "ip netns add failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        fixture
    }
}
impl Drop for Namespaces {
    fn drop(&mut self) {
        let _ = command("ip", &["netns", "delete", &self.a]);
        let _ = command("ip", &["netns", "delete", &self.b]);
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
        let runtime = std::env::temp_dir().join(format!("wgb-m003-{suffix:x}"));
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = runtime.join("netd.sock");
        let shutdown_file = runtime.join("shutdown");
        let executable = std::env::current_exe().unwrap();
        let mut child = Command::new("ip")
            .args(["netns", "exec", namespace])
            .arg(executable)
            .args(["--exact", "namespace_netd_worker", "--nocapture"])
            .env("WG_BASIC_TEST_SOCKET", &socket)
            .env("WG_BASIC_TEST_SHUTDOWN", &shutdown_file)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("could not start namespace-local netd worker");
        let started = Instant::now();
        while !socket.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("namespace-local netd exited before binding its socket: {status}");
            }
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
fn namespace_netd_worker() {
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

fn apply(
    netd: &Netd,
    interface: &InterfaceName,
    patch: WireGuardDevicePatch,
) -> wg_basic::wireguard::WireGuardApplyReceipt {
    match request(
        netd.socket(),
        RequestOperation::ApplyWireGuardDevice {
            interface: interface.clone(),
            patch,
        },
        300,
    )
    .unwrap()
    {
        ResponseBody::WireGuardApplied(receipt) => receipt,
        _ => panic!("unexpected netd response"),
    }
}

fn observe(netd: &Netd, interface: &InterfaceName) -> wg_basic::wireguard::ObservedWireGuardDevice {
    match request(
        netd.socket(),
        RequestOperation::ObserveWireGuardDevice {
            interface: interface.clone(),
        },
        301,
    )
    .unwrap()
    {
        ResponseBody::WireGuardDevice(device) => device,
        _ => panic!("unexpected netd response"),
    }
}

#[test]
fn kernel_wireguard_handshake_telemetry_and_peer_preservation() {
    if nix::unistd::geteuid().as_raw() != 0 {
        unavailable("test process is not root");
        return;
    }
    let probe = command("ip", &["netns", "list"]);
    if !probe.status.success() {
        unavailable("ip netns is unavailable");
        return;
    }

    let namespaces = Namespaces::new();
    let netd_a = Netd::start(&namespaces.a);
    let netd_b = Netd::start(&namespaces.b);
    let interface_a: InterfaceName = "wg-a".parse().unwrap();
    let interface_b: InterfaceName = "wg-b".parse().unwrap();

    run_ip(&["link", "add", "v3a", "type", "veth", "peer", "name", "v3b"]);
    run_ip(&["link", "set", "v3a", "netns", &namespaces.a]);
    run_ip(&["link", "set", "v3b", "netns", &namespaces.b]);
    run_ip(&[
        "-n",
        &namespaces.a,
        "addr",
        "add",
        "198.18.0.1/24",
        "dev",
        "v3a",
    ]);
    run_ip(&[
        "-n",
        &namespaces.b,
        "addr",
        "add",
        "198.18.0.2/24",
        "dev",
        "v3b",
    ]);
    run_ip(&["-n", &namespaces.a, "link", "set", "lo", "up"]);
    run_ip(&["-n", &namespaces.b, "link", "set", "lo", "up"]);
    run_ip(&["-n", &namespaces.a, "link", "set", "v3a", "up"]);
    run_ip(&["-n", &namespaces.b, "link", "set", "v3b", "up"]);

    run_ip(&[
        "-n",
        &namespaces.a,
        "link",
        "add",
        "wg-a",
        "type",
        "wireguard",
    ]);
    run_ip(&[
        "-n",
        &namespaces.b,
        "link",
        "add",
        "wg-b",
        "type",
        "wireguard",
    ]);
    run_ip(&[
        "-n",
        &namespaces.a,
        "addr",
        "add",
        "10.200.0.1/24",
        "dev",
        "wg-a",
    ]);
    run_ip(&[
        "-n",
        &namespaces.b,
        "addr",
        "add",
        "10.200.0.2/24",
        "dev",
        "wg-b",
    ]);
    run_ip(&["-n", &namespaces.a, "link", "set", "wg-a", "up"]);
    run_ip(&["-n", &namespaces.b, "link", "set", "wg-b", "up"]);

    let pair_a = wg_basic::wireguard::generate_keypair().unwrap();
    let pair_b = wg_basic::wireguard::generate_keypair().unwrap();
    let public_a = PublicKey::new(pair_a.public_key.expose().to_owned()).unwrap();
    let public_b = PublicKey::new(pair_b.public_key.expose().to_owned()).unwrap();
    let expected_public_a = public_a.clone();
    let private_a = pair_a.private_key;
    let private_b = pair_b.private_key;
    let peer_a = DesiredWireGuardPeer {
        public_key: public_b,
        preshared_key: None,
        allowed_ips: vec!["10.200.0.2/32".parse::<NetworkPrefix>().unwrap()],
        persistent_keepalive_seconds: None,
        endpoint: Some("198.18.0.2:51832".parse().unwrap()),
    };
    let peer_b = DesiredWireGuardPeer {
        public_key: public_a,
        preshared_key: None,
        allowed_ips: vec!["10.200.0.1/32".parse::<NetworkPrefix>().unwrap()],
        persistent_keepalive_seconds: None,
        endpoint: Some("198.18.0.1:51831".parse().unwrap()),
    };

    assert_eq!(
        apply(
            &netd_a,
            &interface_a,
            WireGuardDevicePatch {
                private_key: FieldUpdate::Set(private_a),
                listen_port: FieldUpdate::Set(51831),
                peer: Some(PeerMutation::Add(peer_a)),
            }
        )
        .disposition,
        ApplyDisposition::Applied
    );
    assert_eq!(
        apply(
            &netd_b,
            &interface_b,
            WireGuardDevicePatch {
                private_key: FieldUpdate::Set(private_b),
                listen_port: FieldUpdate::Set(51832),
                peer: Some(PeerMutation::Add(peer_b)),
            }
        )
        .disposition,
        ApplyDisposition::Applied
    );

    let preserved = wg_basic::wireguard::generate_keypair().unwrap().public_key;
    let preserve_patch = WireGuardDevicePatch {
        private_key: FieldUpdate::Keep,
        listen_port: FieldUpdate::Keep,
        peer: Some(PeerMutation::Add(DesiredWireGuardPeer {
            public_key: preserved,
            preshared_key: None,
            allowed_ips: vec!["10.200.0.99/32".parse().unwrap()],
            persistent_keepalive_seconds: None,
            endpoint: None,
        })),
    };
    apply(&netd_a, &interface_a, preserve_patch);

    // The B peer is already configured; use its public key from the A device observation.
    let observed_a = observe(&netd_a, &interface_a);
    let remote_b = observed_a
        .peers
        .iter()
        .find(|peer| {
            peer.allowed_ips
                .iter()
                .any(|prefix| prefix.to_string() == "10.200.0.2/32")
        })
        .unwrap()
        .public_key
        .clone();
    assert_eq!(observed_a.public_key, Some(expected_public_a));
    assert_eq!(observed_a.listen_port, Some(51831));
    assert_eq!(
        observe(&netd_a, &interface_a).peers.len(),
        2,
        "single-peer update must preserve the unrelated peer"
    );

    let baseline = observe(&netd_a, &interface_a)
        .peers
        .into_iter()
        .find(|peer| peer.public_key == remote_b)
        .unwrap();
    assert_eq!(baseline.latest_handshake, None);
    assert_eq!(baseline.rx_bytes, Some(0));
    assert_eq!(baseline.tx_bytes, Some(0));

    let ping = command(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.a,
            "ping",
            "-c",
            "3",
            "-W",
            "1",
            "10.200.0.2",
        ],
    );
    assert!(
        ping.status.success(),
        "WireGuard tunnel ping failed: {}",
        String::from_utf8_lossy(&ping.stderr)
    );

    let started = Instant::now();
    loop {
        let device = observe(&netd_a, &interface_a);
        let peer = device
            .peers
            .iter()
            .find(|peer| {
                peer.allowed_ips
                    .iter()
                    .any(|prefix| prefix.to_string() == "10.200.0.2/32")
            })
            .unwrap();
        if peer.latest_handshake.is_some()
            && peer.endpoint.is_some()
            && peer.rx_bytes.unwrap_or_default() > 0
            && peer.tx_bytes.unwrap_or_default() > 0
        {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "kernel handshake/telemetry did not converge"
        );
        thread::sleep(Duration::from_millis(100));
    }

    apply(
        &netd_a,
        &interface_a,
        WireGuardDevicePatch {
            private_key: FieldUpdate::Keep,
            listen_port: FieldUpdate::Keep,
            peer: Some(PeerMutation::Update(WireGuardPeerPatch {
                public_key: remote_b.clone(),
                preshared_key: FieldUpdate::Keep,
                allowed_ips: FieldUpdate::Set(vec!["10.200.0.2/32".parse().unwrap()]),
                persistent_keepalive_seconds: FieldUpdate::Set(25),
                endpoint: FieldUpdate::Keep,
            })),
        },
    );
    let updated_a = observe(&netd_a, &interface_a);
    assert_eq!(
        updated_a.peers.len(),
        2,
        "peer update must preserve unrelated peer"
    );
    assert_eq!(
        updated_a
            .peers
            .iter()
            .find(|peer| peer.public_key == remote_b)
            .unwrap()
            .persistent_keepalive_seconds,
        Some(25)
    );
    assert_eq!(
        updated_a
            .peers
            .iter()
            .find(|peer| peer.public_key == remote_b)
            .unwrap()
            .allowed_ips,
        vec!["10.200.0.2/32".parse::<NetworkPrefix>().unwrap()]
    );

    let preserved_key = observe(&netd_a, &interface_a)
        .peers
        .iter()
        .find(|peer| {
            peer.allowed_ips
                .iter()
                .any(|prefix| prefix.to_string() == "10.200.0.99/32")
        })
        .unwrap()
        .public_key
        .clone();
    let removed = apply(
        &netd_a,
        &interface_a,
        WireGuardDevicePatch {
            private_key: FieldUpdate::Keep,
            listen_port: FieldUpdate::Keep,
            peer: Some(PeerMutation::Remove {
                public_key: preserved_key,
            }),
        },
    );
    assert_eq!(removed.disposition, ApplyDisposition::Applied);
    assert_eq!(observe(&netd_a, &interface_a).peers.len(), 1);
}
