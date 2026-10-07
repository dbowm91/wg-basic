#![cfg(all(target_os = "linux", feature = "linux-integration"))]

use std::{
    fs,
    io::Write,
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
    firewall::{DesiredNetworkPolicy, FirewallApplyReceipt, Ipv4Forwarding, NatMode},
    protocol::{request, AuthorizationPolicy, RequestOperation, ResponseBody, SocketServer},
    reconcile::{
        ApplyStatus, DesiredAddress, DesiredManagedInterface, DesiredManagedPeer,
        DesiredWireGuardConfiguration, LinkLifecycle, ManagedRoute, OwnershipDeclaration,
        ResourcePresence,
    },
    wireguard::generate_keypair,
};

fn command(program: &str, args: &[&str]) -> Output {
    Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("could not run {program}: {error}"))
}

fn run(program: &str, args: &[&str]) -> Output {
    let output = command(program, args);
    assert!(
        output.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn run_ip(args: &[&str]) {
    run("ip", args);
}

fn nft_input(namespace: &Namespace, script: &str) {
    let mut child = Command::new("ip")
        .args(["netns", "exec", &namespace.0, "nft", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("could not start nft fixture command");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "nft fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn nft(namespace: &Namespace, args: &[&str]) -> Output {
    let mut full_args = vec!["netns", "exec", namespace.0.as_str(), "nft"];
    full_args.extend_from_slice(args);
    run("ip", &full_args)
}

struct Namespace(String);

impl Namespace {
    fn new(label: &str) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("wgm5{label}{suffix:x}");
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
        let runtime = std::env::temp_dir().join(format!("wgb-m005-{suffix:x}"));
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = runtime.join("netd.sock");
        let shutdown_file = runtime.join("shutdown");
        let executable = std::env::current_exe().unwrap();
        let child = Command::new("ip")
            .args(["netns", "exec", namespace])
            .arg(executable)
            .args([
                "--exact",
                "namespace_network_control_netd_worker",
                "--nocapture",
            ])
            .env("WG_BASIC_TEST_SOCKET", &socket)
            .env("WG_BASIC_TEST_SHUTDOWN", &shutdown_file)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("could not start network service in namespace");
        let started = Instant::now();
        while !socket.exists() {
            if child.id() == 0 {
                panic!("netd worker failed to start");
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
fn namespace_network_control_netd_worker() {
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

fn apply_interface(
    netd: &Netd,
    desired: DesiredManagedInterface,
    request_id: u64,
) -> wg_basic::reconcile::ApplyReceipt {
    match request(
        &netd.socket(),
        RequestOperation::ApplyManagedInterface { desired },
        request_id,
    )
    .unwrap()
    {
        ResponseBody::ManagedInterfaceApplied(receipt) => receipt,
        _ => panic!("unexpected interface response"),
    }
}

fn apply_policy(
    netd: &Netd,
    wireguard_interface: InterfaceName,
    policy: Option<DesiredNetworkPolicy>,
    request_id: u64,
) -> FirewallApplyReceipt {
    match request(
        &netd.socket(),
        RequestOperation::ApplyNetworkPolicy {
            wireguard_interface,
            policy,
        },
        request_id,
    )
    .unwrap()
    {
        ResponseBody::NetworkPolicyApplied(receipt) => receipt,
        _ => panic!("unexpected firewall response"),
    }
}

fn managed_interface(
    interface: InterfaceName,
    private_key: String,
    peer: DesiredManagedPeer,
    address: &str,
    listen_port: u16,
) -> DesiredManagedInterface {
    DesiredManagedInterface {
        interface,
        ownership: OwnershipDeclaration::Managed,
        lifecycle: LinkLifecycle::Present,
        admin_up: Some(true),
        wireguard: Some(DesiredWireGuardConfiguration {
            private_key: PrivateKey::new(private_key).unwrap(),
            listen_port,
            peers: vec![peer],
            manage_all_peers: true,
        }),
        addresses: vec![DesiredAddress {
            address: address.parse().unwrap(),
            presence: ResourcePresence::Present,
        }],
        routes: Vec::new(),
    }
}

fn policy(nat: NatMode) -> DesiredNetworkPolicy {
    DesiredNetworkPolicy {
        ipv4_forwarding: Ipv4Forwarding::Required,
        egress_interface: "veth-egress".parse().unwrap(),
        source_prefixes: vec!["10.8.0.0/24".parse::<NetworkPrefix>().unwrap()],
        nat,
    }
}

fn ping(client: &Namespace) -> Output {
    command(
        "ip",
        &[
            "netns",
            "exec",
            &client.0,
            "ping",
            "-n",
            "-c",
            "1",
            "-W",
            "2",
            "-I",
            "10.8.0.2",
            "198.51.100.2",
        ],
    )
}

#[test]
fn three_namespace_wireguard_forwarding_nat_restart_and_preservation() {
    if nix::unistd::geteuid().as_raw() != 0 {
        panic!("rootful integration test must run as root");
    }
    assert!(command("ip", &["netns", "list"]).status.success());
    assert!(command("nft", &["--version"]).status.success());

    let client = Namespace::new("c");
    let server = Namespace::new("s");
    let internet = Namespace::new("i");

    run_ip(&[
        "link",
        "add",
        "underlay-client",
        "type",
        "veth",
        "peer",
        "name",
        "underlay-server",
    ]);
    run_ip(&["link", "set", "underlay-client", "netns", &client.0]);
    run_ip(&["link", "set", "underlay-server", "netns", &server.0]);
    run_ip(&[
        "link",
        "add",
        "veth-egress",
        "type",
        "veth",
        "peer",
        "name",
        "veth-internet",
    ]);
    run_ip(&["link", "set", "veth-egress", "netns", &server.0]);
    run_ip(&["link", "set", "veth-internet", "netns", &internet.0]);

    run_ip(&[
        "-n",
        &client.0,
        "addr",
        "add",
        "192.0.2.2/24",
        "dev",
        "underlay-client",
    ]);
    run_ip(&[
        "-n",
        &server.0,
        "addr",
        "add",
        "192.0.2.1/24",
        "dev",
        "underlay-server",
    ]);
    run_ip(&[
        "-n",
        &server.0,
        "addr",
        "add",
        "198.51.100.1/24",
        "dev",
        "veth-egress",
    ]);
    run_ip(&[
        "-n",
        &internet.0,
        "addr",
        "add",
        "198.51.100.2/24",
        "dev",
        "veth-internet",
    ]);
    run_ip(&["-n", &client.0, "link", "set", "lo", "up"]);
    run_ip(&["-n", &server.0, "link", "set", "lo", "up"]);
    run_ip(&["-n", &internet.0, "link", "set", "lo", "up"]);
    run_ip(&["-n", &client.0, "link", "set", "underlay-client", "up"]);
    run_ip(&["-n", &server.0, "link", "set", "underlay-server", "up"]);
    run_ip(&["-n", &server.0, "link", "set", "veth-egress", "up"]);
    run_ip(&["-n", &internet.0, "link", "set", "veth-internet", "up"]);
    run_ip(&[
        "-n",
        &server.0,
        "route",
        "add",
        "203.0.113.0/24",
        "dev",
        "veth-egress",
    ]);

    run(
        "ip",
        &[
            "netns",
            "exec",
            &server.0,
            "sysctl",
            "-w",
            "net.ipv4.ip_forward=0",
        ],
    );

    nft_input(&server, "add table inet fixture_keep\nadd chain inet fixture_keep forward { type filter hook forward priority 20; policy accept; }\nadd rule inet fixture_keep forward counter accept comment \"fixture-preserve\"\n");
    let firewall_before = nft(&server, &["-j", "list", "table", "inet", "fixture_keep"]).stdout;

    let client_netd = Netd::start(&client.0);
    let mut server_netd = Netd::start(&server.0);
    let client_keys = generate_keypair().unwrap();
    let server_keys = generate_keypair().unwrap();
    let client_private = client_keys.private_key.expose_secret().to_owned();
    let server_private = server_keys.private_key.expose_secret().to_owned();
    let client_public = client_keys.public_key;
    let server_public = server_keys.public_key;
    let server_interface: InterfaceName = "wg-server".parse().unwrap();
    let client_interface: InterfaceName = "wg-client".parse().unwrap();

    let server_state = || {
        managed_interface(
            server_interface.clone(),
            server_private.clone(),
            DesiredManagedPeer {
                public_key: client_public.clone(),
                allowed_ips: vec!["10.8.0.2/32".parse().unwrap()],
                persistent_keepalive_seconds: None,
                endpoint: None,
            },
            "10.8.0.1/24",
            51820,
        )
    };
    let client_state = || {
        let mut desired = managed_interface(
            client_interface.clone(),
            client_private.clone(),
            DesiredManagedPeer {
                public_key: server_public.clone(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                persistent_keepalive_seconds: Some(25),
                endpoint: Some("192.0.2.1:51820".parse().unwrap()),
            },
            "10.8.0.2/24",
            51821,
        );
        desired.routes = vec![ManagedRoute {
            destination: "0.0.0.0/0".parse().unwrap(),
            gateway: None,
            presence: ResourcePresence::Present,
        }];
        desired
    };
    let first_server = apply_interface(&server_netd, server_state(), 501);
    assert_eq!(
        first_server.status,
        ApplyStatus::Applied,
        "server reconciliation receipt: {first_server:?}"
    );
    assert_eq!(
        apply_interface(&client_netd, client_state(), 502).status,
        ApplyStatus::Applied
    );

    let no_nat = apply_policy(
        &server_netd,
        server_interface.clone(),
        Some(policy(NatMode::Disabled)),
        503,
    );
    assert_eq!(no_nat.status, ApplyStatus::Applied);
    assert!(no_nat.forwarding_changed);
    assert!(
        !ping(&client).status.success(),
        "no-NAT fixture unexpectedly had a return path"
    );

    let with_nat = apply_policy(
        &server_netd,
        server_interface.clone(),
        Some(policy(NatMode::Masquerade)),
        504,
    );
    assert_eq!(
        with_nat.status,
        ApplyStatus::Applied,
        "NAT apply receipt: {with_nat:?}; owned table: {}",
        String::from_utf8_lossy(&nft(&server, &["-j", "list", "table", "inet", "wg_basic"]).stdout)
    );
    assert!(
        ping(&client).status.success(),
        "masqueraded client traffic did not reach internet namespace"
    );
    assert_eq!(
        apply_policy(
            &server_netd,
            server_interface.clone(),
            Some(policy(NatMode::Masquerade)),
            505
        )
        .status,
        ApplyStatus::NoChange
    );

    nft_input(&server, "add table inet external_drop\nadd chain inet external_drop forward { type filter hook forward priority 10; policy accept; }\nadd rule inet external_drop forward iifname \"wg-server\" drop comment \"external-firewall-drop\"\n");
    assert!(
        !ping(&client).status.success(),
        "wg-basic ACCEPT unexpectedly overrode a later independent firewall drop"
    );
    nft_input(&server, "delete table inet external_drop\n");
    assert!(
        ping(&client).status.success(),
        "traffic did not recover after external drop removal"
    );

    drop(server_netd);
    server_netd = Netd::start(&server.0);
    assert_eq!(
        apply_interface(&server_netd, server_state(), 506).status,
        ApplyStatus::NoChange
    );
    assert_eq!(
        apply_policy(
            &server_netd,
            server_interface.clone(),
            Some(policy(NatMode::Masquerade)),
            507
        )
        .status,
        ApplyStatus::NoChange
    );
    assert!(
        ping(&client).status.success(),
        "netd restart broke the WireGuard NAT path"
    );

    assert_eq!(
        apply_policy(&server_netd, server_interface.clone(), None, 508).status,
        ApplyStatus::Applied
    );
    let remove_server = DesiredManagedInterface {
        interface: server_interface.clone(),
        ownership: OwnershipDeclaration::Managed,
        lifecycle: LinkLifecycle::Absent,
        admin_up: None,
        wireguard: None,
        addresses: vec![DesiredAddress {
            address: "10.8.0.1/24".parse().unwrap(),
            presence: ResourcePresence::Absent,
        }],
        routes: Vec::<ManagedRoute>::new(),
    };
    assert_eq!(
        apply_interface(&server_netd, remove_server, 509).status,
        ApplyStatus::Applied
    );
    let forwarding = run(
        "ip",
        &[
            "netns",
            "exec",
            &server.0,
            "sysctl",
            "-n",
            "net.ipv4.ip_forward",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&forwarding.stdout).trim(),
        "1",
        "host forwarding was incorrectly reverted"
    );

    let firewall_after = nft(&server, &["-j", "list", "table", "inet", "fixture_keep"]).stdout;
    assert_eq!(
        firewall_after, firewall_before,
        "unrelated nftables table changed"
    );
    let preserved_route = run("ip", &["-n", &server.0, "route", "show", "203.0.113.0/24"]);
    assert!(String::from_utf8_lossy(&preserved_route.stdout).contains("203.0.113.0/24"));

    nft_input(&server, "add table inet wg_basic\n");
    let collision = request(
        &server_netd.socket(),
        RequestOperation::PlanNetworkPolicy {
            wireguard_interface: server_interface.clone(),
            policy: Some(policy(NatMode::Masquerade)),
        },
        510,
    )
    .unwrap_err();
    assert_eq!(collision.kind(), std::io::ErrorKind::AlreadyExists);
    nft(&server, &["delete", "table", "inet", "wg_basic"]);
}
