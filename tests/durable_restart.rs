#![cfg(all(target_os = "linux", feature = "linux-integration"))]
//! Process-level restart and crash recovery qualification.
//!
//! These cases run real child processes against a real on-disk SQLite store,
//! disposable namespaces, kernel WireGuard, RTNETLINK, and nftables. They prove
//! process restart rather than in-process reconstruction.

use std::{
    ffi::OsString,
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
        Self::start_with_path(namespace, None)
    }

    /// Starts netd with an optional fixture-private `PATH` prepended.
    ///
    /// The override exists so a case can put a fault-injecting `nft` in front of
    /// the real one for this process only. Nothing in production reads `PATH`
    /// for anything but `nft`, so this changes no wg-basic behaviour other than
    /// which binary that one call reaches.
    fn start_with_path(namespace: &str, path_override: Option<&OsString>) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let runtime = std::env::temp_dir().join(format!("wgb-m003-netd-{suffix:x}"));
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = runtime.join("netd.sock");
        let mut command = Command::new("ip");
        command
            .args(["netns", "exec", namespace])
            .arg(executable())
            .args(["netd", "--socket", socket.to_str().unwrap()]);
        if let Some(path) = path_override {
            command.env("PATH", path);
        }
        let child = command
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

/// A fixture-private `nft` that fails mutations while armed.
///
/// The shim exists so a case can inject a *firewall backend* failure — the class
/// of failure an operator hits when nftables refuses a rule — without teaching
/// production code a fault-injection hook or touching the host's nftables state.
/// It forwards every read-only probe to the real binary, so the firewall layer
/// still observes the owned table and genuinely reaches its mutation; only that
/// mutation fails, deterministically.
///
/// It installs transparent and is switched on with [`Self::arm`], so the same
/// live netd can converge, fail, and recover without a restart. That is what
/// makes the recovery run an **equal-generation retry** rather than a fresh
/// apply against a netd that has forgotten the generation.
struct NftFailureShim {
    directory: PathBuf,
    kill_switch: PathBuf,
}

impl NftFailureShim {
    fn install(prefix: &str) -> Self {
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let real = std::env::split_paths(&inherited)
            .map(|directory| directory.join("nft"))
            .find(|candidate| candidate.is_file())
            .expect("nft must be on PATH for this suite to mean anything");

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("{prefix}nft-{suffix:x}"));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let kill_switch = directory.join("recovered");

        let script = format!(
            "#!/bin/sh\n\
             # Fixture-private nft shim. Read-only probes are forwarded to the real\n\
             # binary so the firewall layer still observes state and reaches its\n\
             # mutation; the mutation itself is refused until the kill switch exists.\n\
             real_nft={}\n\
             kill_switch={}\n\
             if [ -e \"$kill_switch\" ]; then\n\
             \texec \"$real_nft\" \"$@\"\n\
             fi\n\
             case \"$1\" in\n\
             \tdelete|add|flush|insert|replace|rename|-f)\n\
             \techo \"wg-basic fixture: injected nft mutation failure\" >&2\n\
             \texit 1\n\
             \t\t;;\n\
             esac\n\
             exec \"$real_nft\" \"$@\"\n",
            shell_quote(&real),
            shell_quote(&kill_switch),
        );
        let shim = directory.join("nft");
        fs::write(&shim, script).unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();

        let this = Self {
            directory,
            kill_switch,
        };
        // Installs transparent: a case arms the failure only for the step it is
        // qualifying, so the setup around it exercises the real backend.
        fs::write(&this.kill_switch, "recovered").unwrap();
        this
    }

    /// Begins refusing mutations for every later invocation, including from
    /// processes that are already running.
    fn arm(&self) {
        let _ = fs::remove_file(&self.kill_switch);
    }

    /// Restores real behavior for every later invocation.
    fn disarm(&self) {
        fs::write(&self.kill_switch, "recovered").unwrap();
    }

    /// The `PATH` to hand to the process under test.
    fn path(&self) -> OsString {
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let mut entries = vec![self.directory.clone()];
        entries.extend(std::env::split_paths(&inherited));
        std::env::join_paths(entries).expect("fixture PATH is constructible")
    }
}

impl Drop for NftFailureShim {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// Single-quotes a path for `/bin/sh`.
fn shell_quote(value: &Path) -> String {
    let text = value.to_string_lossy();
    format!("'{}'", text.replace('\'', r"'\''"))
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
                assigned_ipv6_address: None,
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
        ipv6_forwarding_required: false,
        egress_interface: "lo".parse().unwrap(),
        source_prefixes: vec![NetworkPrefix::new("10.55.0.0/24".parse().unwrap())],
        masquerade: true,
    });
    state
}

/// [`desired_state`] with the managed interface declared absent.
///
/// Every managed address is listed as `Absent`, because teardown refuses to
/// delete a link that still carries an address the desired state does not
/// mention. Dropping the network policy is what makes this the disable path:
/// the aggregate coordinator removes the owned firewall table before tearing the
/// interface down.
fn disabled_state(interface_id: InterfaceId) -> DesiredState {
    let mut state = desired_state(interface_id);
    let interface = &mut state.interfaces[0];
    interface.lifecycle = LinkLifecycle::Absent;
    interface.admin_up = None;
    for address in &mut interface.addresses {
        address.presence = ResourcePresence::Absent;
    }
    state.network_policy = None;
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

/// Disable-path fault injection: the firewall layer refuses to remove the owned
/// policy, so the interface teardown that follows it must not happen.
///
/// The failure is injected into netd's `nft` through a fixture-private `PATH`,
/// so this qualifies the *shipped* disable ordering — firewall removal first,
/// interface second — rather than a test-only branch. The recovery run reuses
/// the same live netd, which is what makes it an equal-generation retry.
#[test]
fn a_failing_firewall_blocks_the_disable_and_recovers_on_equal_generation_retry() {
    let namespace = Namespace::new("wgm3h");
    let temp = TempDir::new("wgb-m003-h");
    let shim = NftFailureShim::install("wgb-m003-h");

    // Generation 2 converges first, so there really is owned firewall state and
    // an owned link for the failed disable to have to protect.
    let interface_id = seed_store_with_policy(&temp.db(), 2);
    let expected_tag = owner_tag_for(&temp.db(), interface_id);
    let installation = installation_of(&temp.db());
    let expected_marker = format!("wg-basic:v1:{installation}");

    let netd = Netd::start_with_path(namespace.name(), Some(&shim.path()));
    let converged = run_management(namespace.name(), &temp.db(), &netd.socket());
    assert!(
        converged.status.success(),
        "initial convergence failed: {}",
        String::from_utf8_lossy(&converged.stderr)
    );
    assert!(eventually(|| namespace.link_exists("wg-restart")));
    assert_eq!(
        namespace.table_comment().as_deref(),
        Some(expected_marker.as_str()),
        "the owned table must exist before the disable is attempted"
    );

    // Arm the fault: from here on the firewall layer's mutation fails.
    shim.arm();

    // Generation 3 disables the interface and drops the policy.
    let store = StateStore::open(temp.db()).unwrap();
    let committed = store
        .mutate(wg_basic::domain::DesiredGeneration::new(2).unwrap(), |_| {
            Ok(disabled_state(interface_id))
        })
        .expect("commit the disable generation");
    assert_eq!(
        committed.generation,
        wg_basic::domain::DesiredGeneration::new(3).unwrap(),
        "the disable must commit as exactly one new generation"
    );
    drop(store);

    let blocked = run_management(namespace.name(), &temp.db(), &netd.socket());
    assert!(
        !blocked.status.success(),
        "a disable whose firewall removal failed must not report success"
    );

    // The firewall layer runs first and failed, so nothing else may have run.
    assert!(
        namespace.owned_table_present(),
        "a failed removal leaves the owned table in place, not half-removed"
    );
    assert_eq!(
        namespace.table_comment().as_deref(),
        Some(expected_marker.as_str()),
        "the still-owned table keeps this installation's marker"
    );
    assert!(
        namespace.link_exists("wg-restart"),
        "the interface teardown must not run after the firewall layer failed"
    );
    assert_eq!(
        namespace.link_alias("wg-restart").as_deref(),
        Some(expected_tag.as_str()),
        "the blocked teardown leaves the link owned, not unowned"
    );

    let store = StateStore::open(temp.db()).unwrap();
    assert_eq!(
        store.convergence().unwrap().last_outcome.as_deref(),
        Some(AttemptDisposition::Rejected.as_str()),
        "a firewall backend failure is refused, not retried forever: {}",
        String::from_utf8_lossy(&blocked.stderr)
    );
    assert_eq!(
        store.convergence().unwrap().last_converged_generation,
        Some(wg_basic::domain::DesiredGeneration::new(2).unwrap()),
        "a blocked disable must not be recorded as converged"
    );
    assert_eq!(
        store.current_generation().unwrap(),
        wg_basic::domain::DesiredGeneration::new(3).unwrap(),
        "the committed disable generation survives the failure for the retry"
    );
    drop(store);

    // The firewall backend recovers. Generation 3 has not changed, so this is an
    // equal-generation retry against the same live netd, which must be accepted
    // and must now run to completion.
    shim.disarm();
    let recovered = run_management(namespace.name(), &temp.db(), &netd.socket());
    assert!(
        recovered.status.success(),
        "the equal-generation retry must converge once the firewall layer works: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );

    assert!(
        !namespace.owned_table_present(),
        "the retry removes the owned firewall table"
    );
    assert!(
        !namespace.link_exists("wg-restart"),
        "the retry then tears the managed interface down"
    );
    assert_eq!(
        namespace.table_comment(),
        None,
        "no table of the owned name may survive the completed disable"
    );
    // A stale or duplicated firewall object would show up as any other inet
    // table, set, or chain the firewall layer could have left behind.
    let listing = Command::new("ip")
        .args(["netns", "exec", namespace.name(), "nft", "list", "tables"])
        .output()
        .expect("could not list tables");
    assert!(
        listing.status.success(),
        "the final listing must succeed: {}",
        String::from_utf8_lossy(&listing.stderr)
    );
    let tables = String::from_utf8_lossy(&listing.stdout);
    assert!(
        !tables.contains("wg_basic"),
        "the completed disable leaves no wg-basic firewall object behind:\n{tables}"
    );

    let store = StateStore::open(temp.db()).unwrap();
    let convergence = store.convergence().unwrap();
    assert_eq!(
        convergence.last_converged_generation,
        Some(wg_basic::domain::DesiredGeneration::new(3).unwrap()),
        "the disable generation is recorded as converged"
    );
    assert_eq!(
        convergence.last_outcome.as_deref(),
        Some(AttemptDisposition::Converged.as_str())
    );
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
