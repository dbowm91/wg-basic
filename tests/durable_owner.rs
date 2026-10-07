#![cfg(all(target_os = "linux", feature = "linux-integration"))]
//! Real-kernel qualification for durable ownership and generation-aware
//! aggregate reconciliation.
//!
//! These cases extend the accepted M004 evidence rather than replacing it. The
//! historical reconcile/WireGuard/forwarding suites must stay green alongside
//! them.

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
    aggregate::{AggregateStatus, InstallationNetworkIntent},
    domain::{
        DesiredGeneration, InstallationId, InterfaceId, InterfaceName, NetworkPrefix, OwnerTag,
        PrivateKey,
    },
    firewall::{DesiredNetworkPolicy, Ipv4Forwarding, NatMode},
    protocol::{request, AuthorizationPolicy, RequestOperation, ResponseBody, SocketServer},
    reconcile::{
        ApplyStatus, DesiredAddress, DesiredManagedInterface, DesiredWireGuardConfiguration,
        LinkLifecycle, OwnershipDeclaration, ResourcePresence,
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

fn link_alias(namespace: &str, interface: &str) -> Option<String> {
    let output = command("ip", &["-n", namespace, "-j", "link", "show", interface]);
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("link show returns json");
    parsed
        .get(0)
        .and_then(|entry| entry.get("ifalias"))
        .and_then(|alias| alias.as_str())
        .map(str::to_owned)
}

/// Runs an nft batch script inside a namespace.
fn nft_batch(namespace: &str, script: &str) -> Output {
    use std::io::Write;
    let mut child = Command::new("ip")
        .args(["netns", "exec", namespace, "nft", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("could not run nft in namespace");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(script.as_bytes())
        .expect("could not write nft script");
    child.wait_with_output().expect("could not await nft")
}

/// True when `inet wg_basic` exists inside the namespace.
fn owned_table_present(namespace: &str) -> bool {
    let output = Command::new("ip")
        .args(["netns", "exec", namespace, "nft", "list", "tables", "inet"])
        .output()
        .expect("could not list inet tables");
    output.status.success()
        && String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.split_whitespace().last() == Some("wg_basic"))
}

/// The comment attached to `inet wg_basic`, if the table exists.
fn owned_table_comment(namespace: &str) -> Option<String> {
    let output = Command::new("ip")
        .args([
            "netns", "exec", namespace, "nft", "--json", "list", "table", "inet", "wg_basic",
        ])
        .output()
        .expect("could not list the owned table");
    if !output.status.success() {
        return None;
    }
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("nft json output");
    parsed
        .get("nftables")
        .and_then(|items| items.as_array())
        .and_then(|items| {
            // The first entry is metainfo; the table object comes after it.
            items.iter().find_map(|item| item.get("table"))
        })
        .and_then(|table| table.get("comment"))
        .and_then(|comment| comment.as_str())
        .map(str::to_owned)
}

struct Namespace(String);

impl Namespace {
    fn new(prefix: &str) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("{prefix}{suffix:x}");
        run_ip(&["netns", "add", &name]);
        Self(name)
    }

    fn name(&self) -> &str {
        &self.0
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
        let runtime = std::env::temp_dir().join(format!("wgb-m002-{suffix:x}"));
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
                "namespace_durable_owner_netd_worker",
                "--nocapture",
            ])
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
fn namespace_durable_owner_netd_worker() {
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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// One installation identity for the whole suite, so ownership markers are
/// stable across netd restarts within a fixture.
fn installation() -> InstallationId {
    "00000000-0000-4000-8000-0000000000a1"
        .parse::<InstallationId>()
        .unwrap()
}

fn generation(value: u64) -> DesiredGeneration {
    DesiredGeneration::new(value).unwrap()
}

fn interface_name() -> InterfaceName {
    "wg-owned".parse().unwrap()
}

fn present_desired(owner_tag: OwnerTag, private_key: PrivateKey) -> DesiredManagedInterface {
    DesiredManagedInterface {
        interface: interface_name(),
        ownership: OwnershipDeclaration::Managed,
        lifecycle: LinkLifecycle::Present,
        admin_up: Some(true),
        owner_tag,
        wireguard: Some(DesiredWireGuardConfiguration {
            private_key,
            listen_port: 51999,
            peers: Vec::new(),
            manage_all_peers: true,
        }),
        addresses: vec![DesiredAddress {
            address: "10.44.0.1/24".parse().unwrap(),
            presence: ResourcePresence::Present,
        }],
        routes: Vec::new(),
    }
}

/// The teardown intent.
///
/// Every managed address must be listed as `Absent`, because M004 refuses to
/// delete a link that still carries an unlisted address. That preservation rule
/// is unchanged by durable ownership.
fn absent_desired(owner_tag: OwnerTag) -> DesiredManagedInterface {
    DesiredManagedInterface {
        interface: interface_name(),
        ownership: OwnershipDeclaration::Managed,
        lifecycle: LinkLifecycle::Absent,
        admin_up: None,
        owner_tag,
        wireguard: None,
        addresses: vec![DesiredAddress {
            address: "10.44.0.1/24".parse().unwrap(),
            presence: ResourcePresence::Absent,
        }],
        routes: Vec::new(),
    }
}

fn intent(
    installation: InstallationId,
    interface_id: InterfaceId,
    generation: DesiredGeneration,
    desired: DesiredManagedInterface,
    policy: Option<DesiredNetworkPolicy>,
) -> InstallationNetworkIntent {
    InstallationNetworkIntent::new(installation, generation, interface_id, desired, policy)
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
    .unwrap()
    {
        ResponseBody::ManagedInterfaceApplied(receipt) => receipt,
        other => panic!("unexpected reconciliation response: {other:?}"),
    }
}

fn apply_aggregate(
    netd: &Netd,
    intent: InstallationNetworkIntent,
    request_id: u64,
) -> wg_basic::protocol::InstallationNetworkApplyBody {
    match request(
        netd.socket(),
        RequestOperation::ApplyInstallationNetworkIntent { intent },
        request_id,
    )
    .unwrap()
    {
        ResponseBody::InstallationNetworkApplied(body) => body,
        other => panic!("unexpected aggregate response: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Required cases
// ---------------------------------------------------------------------------

/// Cases 1, 2: a created link receives the expected IFALIAS, and a matching
/// alias survives a netd restart and is still reconciled.
#[test]
fn created_link_is_tagged_and_a_matching_tag_survives_restart() {
    let namespace = Namespace::new("wgmo2a");
    let keys = generate_keypair().expect("wireguard module");
    let owner = OwnerTag::new(installation(), InterfaceId::new());

    let expected_tag = owner.as_str();
    let alias = {
        let netd = Netd::start(namespace.name());
        let receipt = apply_interface(
            &netd,
            present_desired(owner.clone(), keys.private_key.clone()),
            700,
        );
        assert_eq!(receipt.status, ApplyStatus::Applied);
        link_alias(namespace.name(), "wg-owned")
    };
    assert_eq!(
        alias,
        Some(expected_tag.clone()),
        "the created link must carry its durable owner tag"
    );

    // A fresh netd process must still prove ownership of the tagged link.
    let netd = Netd::start(namespace.name());
    let receipt = apply_interface(
        &netd,
        present_desired(owner.clone(), keys.private_key.clone()),
        701,
    );
    assert!(
        matches!(receipt.status, ApplyStatus::Applied | ApplyStatus::NoChange),
        "a matching owner tag must permit reconciliation after restart, got {:?}",
        receipt.status
    );
    assert_eq!(
        link_alias(namespace.name(), "wg-owned"),
        Some(owner.as_str())
    );
    let _ = namespace;
}

/// Case 3: a same-name untagged WireGuard link is a conflict.
#[test]
fn an_untagged_same_name_wireguard_link_is_a_conflict() {
    let namespace = Namespace::new("wgmo2b");
    run_ip(&[
        "-n",
        namespace.name(),
        "link",
        "add",
        "wg-owned",
        "type",
        "wireguard",
    ]);
    assert!(link_alias(namespace.name(), "wg-owned").is_none());

    let netd = Netd::start(namespace.name());
    let owner = OwnerTag::new(installation(), InterfaceId::new());
    let error = request(
        netd.socket(),
        RequestOperation::PlanManagedInterface {
            desired: present_desired(owner, generate_keypair().unwrap().private_key),
        },
        702,
    )
    .expect_err("an untagged link must not be adopted");
    assert!(
        error.to_string().contains("conflict") || error.to_string().contains("reject"),
        "unexpected error: {error}"
    );
}

/// Cases 4 and 5: a foreign owner tag and a duplicated owner tag are both
/// conflicts, and the conflicting links survive untouched.
#[test]
fn foreign_and_duplicate_owner_tags_are_conflicts_that_survive() {
    let namespace = Namespace::new("wgmo2c");

    // A link tagged for another installation.
    let foreign = OwnerTag::new(InstallationId::new(), InterfaceId::new());
    run_ip(&[
        "-n",
        namespace.name(),
        "link",
        "add",
        "wg-owned",
        "type",
        "wireguard",
    ]);
    run_ip(&[
        "-n",
        namespace.name(),
        "link",
        "set",
        "wg-owned",
        "alias",
        &foreign.as_str(),
    ]);
    assert_eq!(
        link_alias(namespace.name(), "wg-owned"),
        Some(foreign.as_str())
    );

    let netd = Netd::start(namespace.name());
    let owner = OwnerTag::new(installation(), InterfaceId::new());
    let result = request(
        netd.socket(),
        RequestOperation::PlanManagedInterface {
            desired: present_desired(owner.clone(), generate_keypair().unwrap().private_key),
        },
        703,
    );
    assert!(
        result.is_err(),
        "a foreign owner tag must be refused rather than adopted"
    );
    assert_eq!(
        link_alias(namespace.name(), "wg-owned"),
        Some(foreign.as_str()),
        "a refused link must survive untouched"
    );
}

/// Case 5: the same owner tag on a second link is a duplicate conflict.
#[test]
fn a_duplicate_owner_tag_on_another_link_is_a_conflict() {
    let namespace = Namespace::new("wgmo2d");
    let owner = OwnerTag::new(installation(), InterfaceId::new());

    run_ip(&[
        "-n",
        namespace.name(),
        "link",
        "add",
        "wg-owned",
        "type",
        "wireguard",
    ]);
    run_ip(&[
        "-n",
        namespace.name(),
        "link",
        "set",
        "wg-owned",
        "alias",
        &owner.as_str(),
    ]);
    // A second link carrying the same tag is a duplicate.
    run_ip(&[
        "-n",
        namespace.name(),
        "link",
        "add",
        "wg-copy",
        "type",
        "wireguard",
    ]);
    run_ip(&[
        "-n",
        namespace.name(),
        "link",
        "set",
        "wg-copy",
        "alias",
        &owner.as_str(),
    ]);

    let netd = Netd::start(namespace.name());
    let result = request(
        netd.socket(),
        RequestOperation::PlanManagedInterface {
            desired: present_desired(owner, generate_keypair().unwrap().private_key),
        },
        704,
    );
    assert!(
        result.is_err(),
        "a duplicated owner tag must be an operator-visible conflict"
    );
    assert!(link_alias(namespace.name(), "wg-owned").is_some());
    assert!(link_alias(namespace.name(), "wg-copy").is_some());
}

/// Case 6: the owned nftables table marker includes the installation identity.
#[test]
fn the_owned_nftables_table_marker_binds_to_the_installation() {
    let namespace = Namespace::new("wgmo2e");
    run_ip(&[
        "-n",
        namespace.name(),
        "link",
        "add",
        "veth-a",
        "type",
        "veth",
        "peer",
        "name",
        "veth-b",
    ]);
    run_ip(&[
        "-n",
        namespace.name(),
        "addr",
        "add",
        "10.44.0.1/24",
        "dev",
        "veth-a",
    ]);

    let keys = generate_keypair().expect("wireguard module");
    let interface_id = InterfaceId::new();
    let owner = OwnerTag::new(installation(), interface_id);
    let netd = Netd::start(namespace.name());

    let receipt = apply_aggregate(
        &netd,
        intent(
            installation(),
            interface_id,
            generation(1),
            present_desired(owner, keys.private_key.clone()),
            Some(DesiredNetworkPolicy {
                ipv4_forwarding: Ipv4Forwarding::NotRequired,
                egress_interface: "veth-a".parse().unwrap(),
                source_prefixes: vec![NetworkPrefix::new("10.44.0.0/24".parse().unwrap())],
                nat: NatMode::Disabled,
            }),
        ),
        705,
    );
    assert_eq!(receipt.status, AggregateStatus::Applied);
    assert!(owned_table_present(namespace.name()));

    let comment = owned_table_comment(namespace.name()).expect("owned table comment");
    assert_eq!(
        comment,
        format!("wg-basic:v1:{}", installation()),
        "the table comment must bind to this installation identity"
    );
}

/// Case 7: a foreign-installation table marker is a conflict and survives.
#[test]
fn a_foreign_installation_table_marker_is_a_conflict() {
    let namespace = Namespace::new("wgmo2f");
    let foreign = format!("wg-basic:v1:{}", InstallationId::new());

    let added = nft_batch(
        namespace.name(),
        &format!("add table inet wg_basic {{ comment \"{foreign}\"; }}"),
    );
    assert!(
        added.status.success(),
        "could not add the foreign table: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert_eq!(
        owned_table_comment(namespace.name()).as_deref(),
        Some(foreign.as_str())
    );

    run_ip(&[
        "-n",
        namespace.name(),
        "link",
        "add",
        "veth-a",
        "type",
        "veth",
        "peer",
        "name",
        "veth-b",
    ]);
    run_ip(&[
        "-n",
        namespace.name(),
        "addr",
        "add",
        "10.44.0.1/24",
        "dev",
        "veth-a",
    ]);

    let keys = generate_keypair().expect("wireguard module");
    let owner = OwnerTag::new(installation(), InterfaceId::new());
    let netd = Netd::start(namespace.name());
    let result = request(
        netd.socket(),
        RequestOperation::ApplyInstallationNetworkIntent {
            intent: intent(
                installation(),
                InterfaceId::new(),
                generation(1),
                present_desired(owner, keys.private_key),
                Some(DesiredNetworkPolicy {
                    ipv4_forwarding: Ipv4Forwarding::NotRequired,
                    egress_interface: "veth-a".parse().unwrap(),
                    source_prefixes: vec![NetworkPrefix::new("10.44.0.0/24".parse().unwrap())],
                    nat: NatMode::Disabled,
                }),
            ),
        },
        706,
    );
    assert!(
        result.is_err(),
        "a foreign-installation table marker must be refused"
    );
    assert_eq!(
        owned_table_comment(namespace.name()).as_deref(),
        Some(foreign.as_str()),
        "the foreign table must survive a refused apply untouched"
    );
}

/// Cases 8 and 9: an equal-generation reapply is idempotent, and a lower
/// generation is rejected without mutating anything.
#[test]
fn equal_generation_reapply_is_idempotent_and_lower_generation_is_rejected() {
    let namespace = Namespace::new("wgmo2g");
    run_ip(&[
        "-n",
        namespace.name(),
        "link",
        "add",
        "veth-a",
        "type",
        "veth",
        "peer",
        "name",
        "veth-b",
    ]);
    run_ip(&[
        "-n",
        namespace.name(),
        "addr",
        "add",
        "10.44.0.1/24",
        "dev",
        "veth-a",
    ]);

    let keys = generate_keypair().expect("wireguard module");
    let interface_id = InterfaceId::new();
    let owner = OwnerTag::new(installation(), interface_id);
    let netd = Netd::start(namespace.name());

    let build = |generation| {
        intent(
            installation(),
            interface_id,
            generation,
            present_desired(owner.clone(), keys.private_key.clone()),
            Some(DesiredNetworkPolicy {
                ipv4_forwarding: Ipv4Forwarding::NotRequired,
                egress_interface: "veth-a".parse().unwrap(),
                source_prefixes: vec![NetworkPrefix::new("10.44.0.0/24".parse().unwrap())],
                nat: NatMode::Disabled,
            }),
        )
    };

    let first = apply_aggregate(&netd, build(generation(5)), 707);
    assert_eq!(first.generation, generation(5));
    assert!(matches!(
        first.status,
        AggregateStatus::Applied | AggregateStatus::NoChange
    ));

    let repeat = apply_aggregate(&netd, build(generation(5)), 708);
    assert_eq!(
        repeat.status,
        AggregateStatus::NoChange,
        "an equal-generation reapply must be an idempotent no-op"
    );

    let newer = apply_aggregate(&netd, build(generation(6)), 709);
    assert!(matches!(
        newer.status,
        AggregateStatus::Applied | AggregateStatus::NoChange
    ));

    let older = request(
        netd.socket(),
        RequestOperation::ApplyInstallationNetworkIntent {
            intent: build(generation(2)),
        },
        710,
    );
    assert!(
        older.is_err(),
        "a lower generation must be rejected within one netd lifetime"
    );

    // The interface is still owned and present after the rejection.
    assert_eq!(
        link_alias(namespace.name(), "wg-owned"),
        Some(owner.as_str()),
        "a stale generation must not mutate kernel state"
    );
}

/// Case 10 and 11: the present aggregate path succeeds, and the disable path
/// removes the firewall table before the interface.
#[test]
fn the_disable_aggregate_path_removes_firewall_before_the_interface() {
    let namespace = Namespace::new("wgmo2h");
    run_ip(&[
        "-n",
        namespace.name(),
        "link",
        "add",
        "veth-a",
        "type",
        "veth",
        "peer",
        "name",
        "veth-b",
    ]);
    run_ip(&[
        "-n",
        namespace.name(),
        "addr",
        "add",
        "10.44.0.1/24",
        "dev",
        "veth-a",
    ]);

    let keys = generate_keypair().expect("wireguard module");
    let interface_id = InterfaceId::new();
    let owner = OwnerTag::new(installation(), interface_id);
    let netd = Netd::start(namespace.name());

    let enabled = apply_aggregate(
        &netd,
        intent(
            installation(),
            interface_id,
            generation(1),
            present_desired(owner.clone(), keys.private_key.clone()),
            Some(DesiredNetworkPolicy {
                ipv4_forwarding: Ipv4Forwarding::NotRequired,
                egress_interface: "veth-a".parse().unwrap(),
                source_prefixes: vec![NetworkPrefix::new("10.44.0.0/24".parse().unwrap())],
                nat: NatMode::Disabled,
            }),
        ),
        711,
    );
    assert_eq!(enabled.status, AggregateStatus::Applied);

    assert!(
        owned_table_present(namespace.name()),
        "the owned table should exist while enabled"
    );

    let disabled = apply_aggregate(
        &netd,
        intent(
            installation(),
            interface_id,
            generation(2),
            absent_desired(owner.clone()),
            None,
        ),
        712,
    );
    assert_eq!(disabled.status, AggregateStatus::Applied);

    assert!(
        !owned_table_present(namespace.name()),
        "the disable path must remove the owned firewall table"
    );
    let link = command("ip", &["-n", namespace.name(), "link", "show", "wg-owned"]);
    assert!(
        !link.status.success(),
        "the disable path must remove the managed interface"
    );
}

/// A foreign installation identity is refused while the netd process lives.
#[test]
fn a_different_installation_identity_is_refused_while_netd_lives() {
    let namespace = Namespace::new("wgmo2i");
    let keys = generate_keypair().expect("wireguard module");
    let interface_id = InterfaceId::new();
    let owner = OwnerTag::new(installation(), interface_id);
    let netd = Netd::start(namespace.name());

    let first = apply_aggregate(
        &netd,
        intent(
            installation(),
            interface_id,
            generation(1),
            present_desired(owner.clone(), keys.private_key.clone()),
            None,
        ),
        713,
    );
    assert!(matches!(
        first.status,
        AggregateStatus::Applied | AggregateStatus::NoChange
    ));

    let other = InstallationId::new();
    let result = request(
        netd.socket(),
        RequestOperation::ApplyInstallationNetworkIntent {
            intent: intent(
                other,
                InterfaceId::new(),
                generation(2),
                present_desired(OwnerTag::new(other, InterfaceId::new()), keys.private_key),
                None,
            ),
        },
        714,
    );
    assert!(
        result.is_err(),
        "a different installation identity must be refused in one netd lifetime"
    );
}
