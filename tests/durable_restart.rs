#![cfg(all(target_os = "linux", feature = "linux-integration"))]
//! Process-level restart and crash recovery qualification.
//!
//! These cases run real child processes against a real on-disk SQLite store,
//! disposable namespaces, kernel WireGuard, RTNETLINK, and nftables. They prove
//! process restart rather than in-process reconstruction.

use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wg_basic::{
    domain::{
        ClientId, DesiredAddress, DesiredClient, DesiredInterface, DesiredPeer, DesiredState,
        InstallationId, InterfaceId, LinkLifecycle, NetworkPrefix, OwnershipDeclaration, PeerId,
        PrivateKey, PublicKey, ResourcePresence,
    },
    state::{AttemptDisposition, StateStore, INITIAL_DESIRED_GENERATION},
};

const SECRET: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const PEER_PUBLIC: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

// ---------------------------------------------------------------------------
// Process plumbing
// ---------------------------------------------------------------------------

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

    /// Runs an nft batch script inside the namespace.
    fn nft(&self, script: &str) -> Output {
        let mut child = Command::new("ip")
            .args(["netns", "exec", self.name(), "nft", "-f", "-"])
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

    fn owned_table_present(&self) -> bool {
        let output = Command::new("ip")
            .args([
                "netns",
                "exec",
                self.name(),
                "nft",
                "list",
                "tables",
                "inet",
            ])
            .output()
            .expect("could not list inet tables");
        output.status.success()
            && String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.split_whitespace().last() == Some("wg_basic"))
    }

    /// The owner marker written on the owned nftables table, if the table exists.
    fn table_comment(&self) -> Option<String> {
        let output = Command::new("ip")
            .args([
                "netns",
                "exec",
                self.name(),
                "nft",
                "list",
                "table",
                "inet",
                "wg_basic",
            ])
            .output()
            .expect("could not list the owned table");
        if !output.status.success() {
            return None;
        }
        let listing = String::from_utf8_lossy(&output.stdout);
        listing
            .lines()
            .find_map(|line| line.trim().strip_prefix("comment "))
            .map(|comment| comment.trim().trim_matches('"').to_owned())
    }

    /// Replaces the owned table with one carrying a foreign installation marker.
    ///
    /// This is the realistic operator hazard the firewall layer must refuse: a
    /// table of the right name that this installation cannot prove it owns.
    fn plant_foreign_table(&self, foreign: &str) {
        let script = format!(
            "delete table inet wg_basic\nadd table inet wg_basic {{ comment \"{foreign}\"; }}\n"
        );
        let output = self.nft(&script);
        assert!(
            output.status.success(),
            "could not plant a foreign table: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn delete_table(&self) {
        let output = self.nft("delete table inet wg_basic\n");
        assert!(
            output.status.success(),
            "could not delete the table: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn link_exists(&self, name: &str) -> bool {
        command("ip", &["-n", self.name(), "link", "show", name])
            .status
            .success()
    }

    fn link_alias(&self, name: &str) -> Option<String> {
        let output = command("ip", &["-n", self.name(), "-j", "link", "show", name]);
        let parsed: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("link show returns json");
        parsed
            .get(0)
            .and_then(|entry| entry.get("ifalias"))
            .and_then(|alias| alias.as_str())
            .map(str::to_owned)
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = command("ip", &["netns", "delete", &self.0]);
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(prefix: &str) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}{suffix:x}"));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn db(&self) -> PathBuf {
        self.0.join("state.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn executable() -> PathBuf {
    let mut path = std::env::current_exe().expect("test executable path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("wg-basic")
}

struct Netd {
    child: Child,
    runtime: PathBuf,
}

impl Netd {
    fn start(namespace: &str) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let runtime = std::env::temp_dir().join(format!("wgb-m003-netd-{suffix:x}"));
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = runtime.join("netd.sock");
        let child = Command::new("ip")
            .args(["netns", "exec", namespace])
            .arg(executable())
            .args(["netd", "--socket", socket.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("could not start netd in namespace");
        let started = Instant::now();
        while !socket.exists() {
            assert!(child.id() != 0, "netd exited during startup");
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "netd socket did not appear"
            );
            thread::sleep(Duration::from_millis(10));
        }
        Self { child, runtime }
    }

    fn socket(&self) -> PathBuf {
        self.runtime.join("netd.sock")
    }
}

impl Drop for Netd {
    fn drop(&mut self) {
        // The real netd binary runs until signalled; it does not poll a
        // shutdown file. Terminate it explicitly so the child never outlives
        // the fixture.
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.runtime);
    }
}

/// Runs the management `reconcile` role as a real child process.
fn run_management(namespace: &str, state: &Path, socket: &Path) -> Output {
    let started = Instant::now();
    let output = Command::new("ip")
        .args(["netns", "exec", namespace])
        .arg(executable())
        .args([
            "reconcile",
            "--state",
            state.to_str().unwrap(),
            "--socket",
            socket.to_str().unwrap(),
        ])
        .output()
        .expect("could not run the management role");
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "management reconcile did not terminate"
    );
    output
}

/// Waits for a condition with a bounded timeout.
fn eventually(mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

// ---------------------------------------------------------------------------
// Durable state fixtures
// ---------------------------------------------------------------------------

fn desired_state(interface_id: InterfaceId) -> DesiredState {
    let peer_id = PeerId::new();
    let address: ipnet::IpNet = "10.55.0.2/32".parse().unwrap();
    DesiredState {
        interfaces: vec![DesiredInterface {
            id: interface_id,
            name: "wg-restart".parse().unwrap(),
            ownership: OwnershipDeclaration::Managed,
            lifecycle: LinkLifecycle::Present,
            admin_up: Some(true),
            private_key: PrivateKey::new(SECRET.into()).unwrap(),
            listen_port: Some(51990),
            manage_all_peers: true,
            tunnel_prefixes: vec![NetworkPrefix::new("10.55.0.0/24".parse().unwrap())],
            addresses: vec![DesiredAddress {
                address: "10.55.0.1/24".parse().unwrap(),
                presence: ResourcePresence::Present,
            }],
            routes: Vec::new(),
            peers: vec![DesiredPeer {
                id: peer_id,
                public_key: PublicKey::new(PEER_PUBLIC.into()).unwrap(),
                private_key: None,
                preshared_key: None,
                allowed_ips: vec![NetworkPrefix::new(address)],
                persistent_keepalive_seconds: None,
                endpoint: None,
            }],
            clients: vec![DesiredClient {
                id: ClientId::new(),
                peer_id,
                assigned_address: address,
                route_policy: Default::default(),
            }],
        }],
        client_routes: Default::default(),
        network_policy: None,
    }
}

/// [`desired_state`] plus a NAT policy, so the firewall layer programs the
/// owned `inet wg_basic` table.
///
/// The egress must differ from the managed interface; a fresh namespace only has
/// `lo` besides the link under construction.
fn desired_state_with_policy(interface_id: InterfaceId) -> DesiredState {
    let mut state = desired_state(interface_id);
    state.network_policy = Some(wg_basic::domain::DesiredNetworkPolicy {
        wireguard_interface: "wg-restart".parse().unwrap(),
        ipv4_forwarding_required: true,
        egress_interface: "lo".parse().unwrap(),
        source_prefixes: vec![NetworkPrefix::new("10.55.0.0/24".parse().unwrap())],
        masquerade: true,
    });
    state
}

/// Writes a fresh store whose desired state is committed at exactly
/// `generation`, returning the interface identity the final commit used.
fn seed_store(path: &Path, generation: u64) -> InterfaceId {
    seed_store_with(path, generation, desired_state)
}

/// [`seed_store`] using a snapshot that also carries a network policy.
///
/// Without a policy the firewall layer is a no-op and no `inet wg_basic` table
/// exists, so any test that asserts on the owned table must seed this way.
fn seed_store_with_policy(path: &Path, generation: u64) -> InterfaceId {
    seed_store_with(path, generation, desired_state_with_policy)
}

fn seed_store_with(
    path: &Path,
    generation: u64,
    snapshot_for: fn(InterfaceId) -> DesiredState,
) -> InterfaceId {
    let interface_id = InterfaceId::new();
    let store = StateStore::initialize(path).expect("initialize store");
    let target = wg_basic::domain::DesiredGeneration::new(generation).unwrap();
    let mut expected = INITIAL_DESIRED_GENERATION;
    while expected < target {
        let next = expected.next().expect("generation has room");
        // Only the final commit installs the interface identity the test uses.
        let snapshot = snapshot_for(if next == target {
            interface_id
        } else {
            InterfaceId::new()
        });
        let committed = store
            .mutate(expected, |_| Ok(snapshot))
            .expect("commit desired state");
        expected = committed.generation;
    }
    assert_eq!(
        expected, target,
        "seed must land exactly on the target generation"
    );
    drop(store);
    interface_id
}

/// The installation identity the store actually assigned.
///
/// It is generated at initialization, so tests read it back rather than
/// assuming a fixed value.
fn installation_of(path: &Path) -> InstallationId {
    StateStore::open(path)
        .expect("open store")
        .installation_metadata()
        .expect("installation metadata")
        .installation_id
}

fn owner_tag_for(path: &Path, interface_id: InterfaceId) -> String {
    wg_basic::domain::OwnerTag::new(installation_of(path), interface_id).to_string()
}

// ---------------------------------------------------------------------------
// Crash-point and drift qualification
// ---------------------------------------------------------------------------

/// Crash point A and C combined: a generation committed before any netd call,
/// and a generation that converged before its evidence was recorded.
///
/// Startup reconciles unconditionally, so a committed-but-unapplied generation
/// and an already-converged generation both end up converged, and the evidence
/// ends at the current generation.
#[test]
fn a_committed_generation_converges_after_a_management_process_restart() {
    let namespace = Namespace::new("wgm3a");
    let temp = TempDir::new("wgb-m003-a");
    let interface_id = seed_store(&temp.db(), 2);
    let expected_tag = owner_tag_for(&temp.db(), interface_id);

    let netd = Netd::start(namespace.name());
    let first = run_management(namespace.name(), &temp.db(), &netd.socket());
    assert!(
        first.status.success(),
        "management reconcile failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    assert!(eventually(|| namespace.link_exists("wg-restart")));
    assert_eq!(
        namespace.link_alias("wg-restart").as_deref(),
        Some(expected_tag.as_str())
    );

    let store = StateStore::open(temp.db()).unwrap();
    assert_eq!(
        store.convergence().unwrap().last_converged_generation,
        Some(wg_basic::domain::DesiredGeneration::new(2).unwrap()),
        "startup must record convergence for the generation it applied"
    );

    // Restart management: an already-converged generation replays idempotently.
    let second = run_management(namespace.name(), &temp.db(), &netd.socket());
    assert!(second.status.success());
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("converged"),
        "second startup: {}",
        String::from_utf8_lossy(&second.stdout)
    );
    drop(store);
}

/// Kernel drift while stopped: the owned tagged link is deleted and the owned
/// nftables table is removed. Startup must restore both.
#[test]
fn startup_restores_deleted_owned_link_and_owned_table() {
    let namespace = Namespace::new("wgm3b");
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
        "10.55.0.1/24",
        "dev",
        "veth-a",
    ]);

    let temp = TempDir::new("wgb-m003-b");
    let interface_id = seed_store_with_policy(&temp.db(), 2);
    let expected_tag = owner_tag_for(&temp.db(), interface_id);

    // Install the owned table directly so the scenario exercises drift on both
    // layers rather than only the interface layer.
    let marker = format!("wg-basic:v1:{}", installation_of(&temp.db()));
    let added = namespace.nft(&format!(
        "add table inet wg_basic {{ comment \"{marker}\"; }}\n\
         add chain inet wg_basic forward {{ type filter hook forward priority filter; policy accept; comment \"{marker}:chain:forward:x\"; }}\n"
    ));
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert!(namespace.owned_table_present());

    // First converge so there is an owned substrate to damage.
    {
        let netd = Netd::start(namespace.name());
        let first = run_management(namespace.name(), &temp.db(), &netd.socket());
        assert!(
            first.status.success(),
            "initial converge failed: {}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert!(eventually(|| namespace.link_exists("wg-restart")));
    }

    // Services stopped: the operator removes the managed link.
    run_ip(&["-n", namespace.name(), "link", "delete", "wg-restart"]);
    assert!(!namespace.link_exists("wg-restart"));

    let netd = Netd::start(namespace.name());
    let output = run_management(namespace.name(), &temp.db(), &netd.socket());
    assert!(
        output.status.success(),
        "startup must repair drift: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        eventually(|| namespace.link_exists("wg-restart")),
        "startup must recreate a deleted owned link"
    );
    assert_eq!(
        namespace.link_alias("wg-restart").as_deref(),
        Some(expected_tag.as_str()),
        "the recreated link must carry its durable owner tag again"
    );
}

/// Crash point B: a partially applied generation, and its recovery.
///
/// The enable path applies the interface before the firewall. Deleting the owned
/// link forces the interface layer to mutate, and replacing the owned table with
/// a foreign one makes the firewall layer refuse. That leaves the kernel in a
/// genuinely partial state: the link exists and is owned, the firewall is not.
///
/// The next management start must fail closed, preserve the desired generation,
/// and — once the operator clears the foreign table — converge on restart.
#[test]
fn a_partially_applied_generation_recovers_after_a_restart() {
    let namespace = Namespace::new("wgm3g");
    let temp = TempDir::new("wgb-m003-g");
    let interface_id = seed_store_with_policy(&temp.db(), 2);
    let expected_tag = owner_tag_for(&temp.db(), interface_id);
    let installation = installation_of(&temp.db());
    let expected_marker = format!("wg-basic:v1:{installation}");

    let netd = Netd::start(namespace.name());
    let first = run_management(namespace.name(), &temp.db(), &netd.socket());
    assert!(
        first.status.success(),
        "initial convergence failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(eventually(|| namespace.link_exists("wg-restart")));
    assert!(eventually(|| namespace.owned_table_present()));
    assert_eq!(
        namespace.table_comment().as_deref(),
        Some(expected_marker.as_str()),
        "the owned table must carry this installation's marker"
    );

    // Force the interface layer to mutate, and block the firewall layer.
    run_ip(&["-n", namespace.name(), "link", "delete", "wg-restart"]);
    let foreign = format!("wg-basic:v1:{}", InstallationId::new());
    namespace.plant_foreign_table(&foreign);

    let partial = run_management(namespace.name(), &temp.db(), &netd.socket());
    assert!(
        !partial.status.success(),
        "a foreign firewall table must not be adopted"
    );

    // The interface layer ran before the firewall layer refused: this really was
    // a partial apply, not a clean pre-mutation failure.
    assert!(
        eventually(|| namespace.link_exists("wg-restart")),
        "the interface layer mutates first, so the link was recreated"
    );
    assert_eq!(
        namespace.link_alias("wg-restart").as_deref(),
        Some(expected_tag.as_str()),
        "the recreated link stays owned by this installation"
    );
    assert_eq!(
        namespace.table_comment().as_deref(),
        Some(foreign.as_str()),
        "the foreign table must survive the refused apply untouched"
    );

    let store = StateStore::open(temp.db()).unwrap();
    assert_eq!(
        store.convergence().unwrap().last_outcome.as_deref(),
        Some("state_conflict"),
        "the retry finds the interface already converged, so only the foreign \
         table remains: a clean ownership conflict needing an operator: {}",
        String::from_utf8_lossy(&partial.stderr)
    );
    assert_eq!(
        store.current_generation().unwrap(),
        wg_basic::domain::DesiredGeneration::new(2).unwrap(),
        "the desired generation survives a partial apply for the next start"
    );
    drop(store);

    // The operator clears the conflicting table; the next start converges.
    namespace.delete_table();
    let recovered = run_management(namespace.name(), &temp.db(), &netd.socket());
    assert!(
        recovered.status.success(),
        "startup must recover a partially applied generation: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(eventually(|| namespace.owned_table_present()));
    assert_eq!(
        namespace.table_comment().as_deref(),
        Some(expected_marker.as_str()),
        "recovery re-establishes this installation's ownership"
    );

    let store = StateStore::open(temp.db()).unwrap();
    assert_eq!(
        store.convergence().unwrap().last_converged_generation,
        Some(wg_basic::domain::DesiredGeneration::new(2).unwrap()),
        "the recovered generation is recorded as converged"
    );
    drop(store);
}

/// Ownership loss fails closed: the owner tag is changed to something else and
/// startup must refuse rather than re-adopt the link.
#[test]
fn a_changed_owner_tag_fails_closed_instead_of_re_adopting() {
    let namespace = Namespace::new("wgm3c");
    let temp = TempDir::new("wgb-m003-c");
    let interface_id = seed_store(&temp.db(), 2);

    let netd = Netd::start(namespace.name());
    let first = run_management(namespace.name(), &temp.db(), &netd.socket());
    assert!(first.status.success());
    assert!(eventually(|| namespace.link_exists("wg-restart")));

    // The tag is replaced with a foreign wg-basic tag.
    let foreign = wg_basic::domain::OwnerTag::new(InstallationId::new(), interface_id);
    run_ip(&[
        "-n",
        namespace.name(),
        "link",
        "set",
        "wg-restart",
        "alias",
        &foreign.to_string(),
    ]);

    let second = run_management(namespace.name(), &temp.db(), &netd.socket());
    assert!(
        !second.status.success(),
        "a changed owner tag must fail closed rather than be re-adopted"
    );
    assert_eq!(
        namespace.link_alias("wg-restart").as_deref(),
        Some(foreign.to_string().as_str()),
        "the foreign tag must survive the refused startup"
    );

    // The desired state is preserved for operator resolution.
    let store = StateStore::open(temp.db()).unwrap();
    assert_eq!(
        store.convergence().unwrap().last_outcome.as_deref(),
        Some("state_conflict"),
        "an ownership conflict is recorded as a category, not a message"
    );
    assert_eq!(
        store.current_generation().unwrap(),
        wg_basic::domain::DesiredGeneration::new(2).unwrap(),
        "durable desired state is preserved through the conflict"
    );
    drop(store);
}

/// A newer generation cannot be marked converged by an older generation's late
/// completion.
#[test]
fn a_stale_completion_cannot_mark_a_newer_generation_converged() {
    let temp = TempDir::new("wgb-m003-d");
    let interface_id = InterfaceId::new();
    let store = StateStore::initialize(temp.db()).unwrap();
    let older = wg_basic::domain::DesiredGeneration::new(2).unwrap();

    store
        .mutate(INITIAL_DESIRED_GENERATION, |_| {
            Ok(desired_state(interface_id))
        })
        .unwrap();
    assert!(store.record_converged_if_current(older).unwrap());

    let newer = older.next().unwrap();
    store
        .mutate(older, |_| Ok(desired_state(InterfaceId::new())))
        .unwrap();

    // A delayed duplicate receipt for the older generation arrives.
    assert!(
        !store.record_converged_if_current(older).unwrap(),
        "a stale completion must not mark the newer generation converged"
    );
    assert_eq!(
        store.convergence().unwrap().last_converged_generation,
        Some(older),
        "the newer desired generation is not yet converged"
    );
    assert_eq!(store.current_generation().unwrap(), newer);

    assert!(store.record_converged_if_current(newer).unwrap());
    assert_eq!(
        store.convergence().unwrap().last_converged_generation,
        Some(newer)
    );
    drop(store);
}

/// Startup with no network service is a bounded retry that ends in a clear
/// unavailable state, never an unbounded loop and never a privilege escalation.
#[test]
fn an_absent_network_service_is_a_bounded_unavailable_state() {
    let namespace = Namespace::new("wgm3e");
    let temp = TempDir::new("wgb-m003-e");
    seed_store(&temp.db(), 2);

    // No netd at all: the socket path does not exist.
    let missing = std::env::temp_dir().join(format!("wgb-absent-{}", std::process::id()));
    let started = Instant::now();
    let output = run_management(namespace.name(), &temp.db(), &missing);
    assert!(!output.status.success(), "startup must report a failure");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the retry must be bounded, not an indefinite wait"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("network service"),
        "the failure must name the missing network service: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let store = StateStore::open(temp.db()).unwrap();
    assert_eq!(
        store.convergence().unwrap().last_outcome.as_deref(),
        Some("backend_unavailable"),
        "the category is recorded without any secret-bearing message"
    );
    drop(store);
}

/// Secret material never reaches diagnostics or process arguments.
#[test]
fn startup_never_exposes_secret_material() {
    let namespace = Namespace::new("wgm3f");
    let temp = TempDir::new("wgb-m003-f");
    seed_store(&temp.db(), 2);

    let netd = Netd::start(namespace.name());
    let output = run_management(namespace.name(), &temp.db(), &netd.socket());
    assert!(output.status.success());

    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !rendered.contains(SECRET),
        "secret leaked into CLI output: {rendered}"
    );

    let store = StateStore::open(temp.db()).unwrap();
    let debug = format!("{:?}", store.load().unwrap());
    assert!(!debug.contains(SECRET), "secret leaked in state Debug");
    assert!(
        debug.contains("[REDACTED]"),
        "the snapshot must still redact its key material: {debug}"
    );
    drop(store);

    // The database file must remain owner-only.
    let mode = std::os::unix::fs::MetadataExt::mode(&fs::symlink_metadata(temp.db()).unwrap());
    assert_eq!(mode & 0o777, 0o600, "state file must stay owner-only");
}

/// A stale disposition category is never confused with a converged one.
#[test]
fn attempt_categories_stay_distinct_from_convergence() {
    for disposition in [
        AttemptDisposition::Converged,
        AttemptDisposition::PartialFailure,
        AttemptDisposition::Superseded,
        AttemptDisposition::StateConflict,
    ] {
        assert_eq!(
            AttemptDisposition::parse_category(disposition.as_str()),
            Some(disposition)
        );
    }
    assert_ne!(
        AttemptDisposition::Superseded.as_str(),
        AttemptDisposition::Converged.as_str()
    );
}
