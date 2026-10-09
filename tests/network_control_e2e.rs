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
    domain::{InstallationId, InterfaceId, InterfaceName, NetworkPrefix, OwnerTag, PrivateKey},
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

fn nft_table_snapshot(namespace: &Namespace, table: &str) -> serde_json::Value {
    fn remove_dynamic_fields(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    remove_dynamic_fields(value);
                }
            }
            serde_json::Value::Object(object) => {
                object.remove("handle");
                if let Some(serde_json::Value::Object(counter)) = object.get_mut("counter") {
                    counter.remove("packets");
                    counter.remove("bytes");
                }
                for value in object.values_mut() {
                    remove_dynamic_fields(value);
                }
            }
            _ => {}
        }
    }

    let output = nft(namespace, &["-j", "list", "table", "inet", table]);
    let mut value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    remove_dynamic_fields(&mut value);
    value
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
        Self::start_with_path(namespace, None)
    }

    fn start_with_path(namespace: &str, path: Option<&std::ffi::OsStr>) -> Self {
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
            .envs(path.map(|path| [("PATH", path)]).into_iter().flatten())
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
        netd.socket(),
        RequestOperation::ApplyManagedInterface { desired },
        request_id,
    )
    .unwrap_or_else(|error| panic!("managed interface request {request_id} failed: {error}"))
    {
        ResponseBody::ManagedInterfaceApplied(receipt) => receipt,
        _ => panic!("unexpected interface response"),
    }
}

/// One installation identity for the whole fixture: the owned nftables table
/// binds to it, and every policy operation must present the same identity.
fn installation() -> InstallationId {
    "00000000-0000-4000-8000-0000000000a1"
        .parse::<InstallationId>()
        .unwrap()
}

fn apply_policy(
    netd: &Netd,
    wireguard_interface: InterfaceName,
    policy: Option<DesiredNetworkPolicy>,
    request_id: u64,
) -> FirewallApplyReceipt {
    match request(
        netd.socket(),
        RequestOperation::ApplyNetworkPolicy {
            installation_id: installation(),
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
    owner_tag: OwnerTag,
) -> DesiredManagedInterface {
    DesiredManagedInterface {
        interface,
        ownership: OwnershipDeclaration::Managed,
        lifecycle: LinkLifecycle::Present,
        admin_up: Some(true),
        owner_tag,
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
        ipv6_forwarding: wg_basic::firewall::Ipv6Forwarding::NotRequired,
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

fn ping6(client: &Namespace) -> Output {
    command(
        "ip",
        &[
            "netns",
            "exec",
            &client.0,
            "ping",
            "-6",
            "-n",
            "-c",
            "1",
            "-W",
            "2",
            "-I",
            "2001:db8:42::2",
            "2001:db8:100::2",
        ],
    )
}

fn ping_target(client: &Namespace, target: &str, ipv6: bool) -> Output {
    let mut args = vec!["netns", "exec", client.0.as_str(), "ping"];
    if ipv6 {
        args.push("-6");
    }
    args.extend_from_slice(&["-n", "-c", "1", "-W", "2"]);
    if ipv6 {
        args.extend_from_slice(&["-I", "2001:db8:42::2"]);
    } else {
        args.extend_from_slice(&["-I", "10.8.0.2"]);
    }
    args.push(target);
    command("ip", &args)
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
    run_ip(&[
        "-n",
        &server.0,
        "addr",
        "add",
        "2001:db8:100::1/64",
        "dev",
        "veth-egress",
    ]);
    run_ip(&[
        "-n",
        &internet.0,
        "addr",
        "add",
        "2001:db8:100::2/64",
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
    run_ip(&[
        "-n",
        &internet.0,
        "route",
        "add",
        "2001:db8:42::/64",
        "via",
        "2001:db8:100::1",
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
    let firewall_before = nft_table_snapshot(&server, "fixture_keep");

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
    // Each managed interface gets its own durable owner tag, derived from one
    // installation identity and the interface identity.
    let install = InstallationId::new();
    let server_owner = OwnerTag::new(install, InterfaceId::new());
    let client_owner = OwnerTag::new(install, InterfaceId::new());

    let server_state = || {
        let mut desired = managed_interface(
            server_interface.clone(),
            server_private.clone(),
            DesiredManagedPeer {
                public_key: client_public.clone(),
                allowed_ips: vec![
                    "10.8.0.2/32".parse().unwrap(),
                    "2001:db8:42::2/128".parse().unwrap(),
                ],
                persistent_keepalive_seconds: None,
                endpoint: None,
            },
            "10.8.0.1/24",
            51820,
            server_owner.clone(),
        );
        desired.addresses.push(DesiredAddress {
            address: "2001:db8:42::1/64".parse().unwrap(),
            presence: ResourcePresence::Present,
        });
        desired
    };
    let client_state = || {
        let mut desired = managed_interface(
            client_interface.clone(),
            client_private.clone(),
            DesiredManagedPeer {
                public_key: server_public.clone(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
                persistent_keepalive_seconds: Some(25),
                endpoint: Some("192.0.2.1:51820".parse().unwrap()),
            },
            "10.8.0.2/24",
            51821,
            client_owner.clone(),
        );
        desired.routes = vec![ManagedRoute {
            destination: "0.0.0.0/0".parse().unwrap(),
            gateway: None,
            presence: ResourcePresence::Present,
        }];
        desired.routes.push(ManagedRoute {
            destination: "::/0".parse().unwrap(),
            gateway: None,
            presence: ResourcePresence::Present,
        });
        desired.addresses.push(DesiredAddress {
            address: "2001:db8:42::2/64".parse().unwrap(),
            presence: ResourcePresence::Present,
        });
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

    let dual_stack = DesiredNetworkPolicy {
        ipv6_forwarding: wg_basic::firewall::Ipv6Forwarding::Required,
        source_prefixes: vec![
            "10.8.0.0/24".parse().unwrap(),
            "2001:db8:42::/64".parse().unwrap(),
        ],
        ..policy(NatMode::Masquerade)
    };
    let per_interface_before = run(
        "ip",
        &[
            "netns",
            "exec",
            &server.0,
            "sysctl",
            "-n",
            "net.ipv6.conf.veth-egress.forwarding",
        ],
    );
    let per_interface_before = String::from_utf8_lossy(&per_interface_before.stdout)
        .trim()
        .to_owned();
    let failure_root = std::env::temp_dir().join(format!(
        "wgb-m002-nft-failure-{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&failure_root).unwrap();
    let real_nft = command("which", &["nft"]);
    assert!(real_nft.status.success());
    let real_nft = String::from_utf8_lossy(&real_nft.stdout).trim().to_owned();
    let wrapper = failure_root.join("nft");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" -f - \"*) echo 'fixture nft failure' >&2; exit 1;; esac\nexec {real_nft} \"$@\"\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let inherited_path = std::env::var_os("PATH").unwrap_or_default();
    let fixture_path = std::env::join_paths(
        std::iter::once(failure_root.clone()).chain(std::env::split_paths(&inherited_path)),
    )
    .unwrap();
    drop(server_netd);
    server_netd = Netd::start_with_path(&server.0, Some(&fixture_path));
    let ipv6_apply = apply_policy(
        &server_netd,
        server_interface.clone(),
        Some(dual_stack.clone()),
        511,
    );
    assert_eq!(
        ipv6_apply.status,
        ApplyStatus::PartialFailure,
        "partial receipt must preserve the sysctl effect after nft failure: {ipv6_apply:?}"
    );
    assert!(ipv6_apply.forwarding_changed);
    let per_interface_after = run(
        "ip",
        &[
            "netns",
            "exec",
            &server.0,
            "sysctl",
            "-n",
            "net.ipv6.conf.veth-egress.forwarding",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&per_interface_after.stdout).trim(),
        "1",
        "ADR-007 global forwarding changed per-interface Host/Router forwarding from {per_interface_before}"
    );
    drop(server_netd);
    server_netd = Netd::start(&server.0);
    let retry = apply_policy(
        &server_netd,
        server_interface.clone(),
        Some(dual_stack.clone()),
        512,
    );
    assert_eq!(
        retry.status,
        ApplyStatus::Applied,
        "IPv6 policy retry: {retry:?}"
    );
    fs::remove_dir_all(&failure_root).unwrap();
    assert!(
        ping6(&client).status.success(),
        "routed IPv6 return path failed"
    );
    let ipv6_forwarding = run(
        "ip",
        &[
            "netns",
            "exec",
            &server.0,
            "sysctl",
            "-n",
            "net.ipv6.conf.all.forwarding",
        ],
    );
    assert_eq!(String::from_utf8_lossy(&ipv6_forwarding.stdout).trim(), "1");
    let owned_rules = nft(&server, &["-j", "list", "table", "inet", "wg_basic"]);
    let owned_rules: serde_json::Value = serde_json::from_slice(&owned_rules.stdout).unwrap();
    let serialized_rules = owned_rules.to_string();
    assert!(
        serialized_rules.contains("ip6"),
        "IPv6 source rule missing: {serialized_rules}"
    );
    let table_rules = owned_rules["nftables"].as_array().unwrap();
    assert!(
        table_rules
            .iter()
            .filter_map(|entry| entry.get("rule"))
            .filter(|rule| rule.to_string().contains("masquerade"))
            .all(|rule| !rule.to_string().contains("ip6")),
        "NAT66 emitted: {serialized_rules}"
    );

    nft_input(&server, "add table inet external_drop\nadd chain inet external_drop forward { type filter hook forward priority 10; policy accept; }\nadd rule inet external_drop forward iifname \"wg-server\" drop comment \"external-firewall-drop\"\n");
    assert!(
        !ping(&client).status.success() && !ping6(&client).status.success(),
        "wg-basic ACCEPT unexpectedly overrode a later independent firewall drop"
    );
    nft_input(&server, "delete table inet external_drop\n");
    assert!(
        ping(&client).status.success() && ping6(&client).status.success(),
        "traffic did not recover after external drop removal"
    );

    // Replace both default client routes with explicit split prefixes. The
    // selected egress networks continue through WireGuard, while destinations
    // outside each family prefix have no client tunnel route.
    let mut split_client = client_state();
    let split_peer = split_client
        .wireguard
        .as_mut()
        .unwrap()
        .peers
        .first_mut()
        .unwrap();
    split_peer.allowed_ips = vec![
        "198.51.100.0/24".parse().unwrap(),
        "2001:db8:100::/64".parse().unwrap(),
    ];
    split_client.routes = vec![
        ManagedRoute {
            destination: "198.51.100.0/24".parse().unwrap(),
            gateway: None,
            presence: ResourcePresence::Present,
        },
        ManagedRoute {
            destination: "2001:db8:100::/64".parse().unwrap(),
            gateway: None,
            presence: ResourcePresence::Present,
        },
    ];
    let split_receipt = apply_interface(&client_netd, split_client, 513);
    assert_eq!(
        split_receipt.status,
        ApplyStatus::Applied,
        "split-route apply: {split_receipt:?}"
    );
    assert!(
        ping(&client).status.success(),
        "IPv4 split route did not carry selected traffic"
    );
    assert!(
        ping6(&client).status.success(),
        "IPv6 split route did not carry selected traffic"
    );
    assert!(
        !ping_target(&client, "203.0.113.2", false).status.success(),
        "IPv4 traffic outside the split prefix unexpectedly used the tunnel"
    );
    assert!(
        !ping_target(&client, "2001:db8:200::2", true)
            .status
            .success(),
        "IPv6 traffic outside the split prefix unexpectedly used the tunnel"
    );

    drop(server_netd);
    server_netd = Netd::start(&server.0);
    let restarted_server = apply_interface(&server_netd, server_state(), 506);
    // Applying endpoint=None clears the server's dynamic peer endpoint learned
    // from client traffic; a fresh client packet establishes it again.
    assert!(
        matches!(
            restarted_server.status,
            ApplyStatus::NoChange | ApplyStatus::Applied
        ),
        "server restart reconciliation receipt: {restarted_server:?}"
    );
    assert_eq!(
        apply_policy(
            &server_netd,
            server_interface.clone(),
            Some(dual_stack.clone()),
            507
        )
        .status,
        ApplyStatus::NoChange
    );
    assert!(
        ping(&client).status.success() && ping6(&client).status.success(),
        "netd restart broke routed traffic"
    );

    assert_eq!(
        apply_policy(&server_netd, server_interface.clone(), None, 508).status,
        ApplyStatus::Applied
    );
    let ipv6_forwarding_after_disable = run(
        "ip",
        &[
            "netns",
            "exec",
            &server.0,
            "sysctl",
            "-n",
            "net.ipv6.conf.all.forwarding",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&ipv6_forwarding_after_disable.stdout).trim(),
        "1",
        "policy disable incorrectly reset IPv6 forwarding"
    );
    let remove_server = DesiredManagedInterface {
        interface: server_interface.clone(),
        ownership: OwnershipDeclaration::Managed,
        lifecycle: LinkLifecycle::Absent,
        admin_up: None,
        owner_tag: server_owner.clone(),
        wireguard: None,
        addresses: vec![
            DesiredAddress {
                address: "10.8.0.1/24".parse().unwrap(),
                presence: ResourcePresence::Absent,
            },
            DesiredAddress {
                address: "2001:db8:42::1/64".parse().unwrap(),
                presence: ResourcePresence::Absent,
            },
        ],
        routes: Vec::<ManagedRoute>::new(),
    };
    assert_eq!(
        apply_interface(&server_netd, remove_server, 509).status,
        ApplyStatus::Applied
    );
    let ipv6_forwarding = run(
        "ip",
        &[
            "netns",
            "exec",
            &server.0,
            "sysctl",
            "-n",
            "net.ipv6.conf.all.forwarding",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&ipv6_forwarding.stdout).trim(),
        "1",
        "IPv6 forwarding was incorrectly reverted"
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

    let firewall_after = nft_table_snapshot(&server, "fixture_keep");
    assert_eq!(
        firewall_after, firewall_before,
        "unrelated nftables table changed"
    );
    let preserved_route = run("ip", &["-n", &server.0, "route", "show", "203.0.113.0/24"]);
    assert!(String::from_utf8_lossy(&preserved_route.stdout).contains("203.0.113.0/24"));
    let preserved_egress_addresses = run(
        "ip",
        &["-n", &server.0, "addr", "show", "dev", "veth-egress"],
    );
    let preserved_egress_addresses = String::from_utf8_lossy(&preserved_egress_addresses.stdout);
    assert!(preserved_egress_addresses.contains("198.51.100.1/24"));
    assert!(preserved_egress_addresses.contains("2001:db8:100::1/64"));

    nft_input(&server, "add table inet wg_basic\n");
    let collision = request(
        server_netd.socket(),
        RequestOperation::PlanNetworkPolicy {
            installation_id: installation(),
            wireguard_interface: server_interface.clone(),
            policy: Some(policy(NatMode::Masquerade)),
        },
        510,
    )
    .unwrap_err();
    assert_eq!(collision.kind(), std::io::ErrorKind::AlreadyExists);
    nft(&server, &["delete", "table", "inet", "wg_basic"]);
}
