#![cfg(all(target_os = "linux", feature = "linux-integration"))]
//! End-to-end qualification that a **restored** database drives the kernel.
//!
//! The server side of a real three-namespace WireGuard topology is managed
//! entirely through the durable state store: a real `wg-basic reconcile` child
//! process projects the committed generation, applies it through the real
//! `netd` binary, and real traffic flows. The database is then backed up, the
//! whole managed environment is torn down, the backup is restored, and ordinary
//! startup has to rebuild everything from the restored file.
//!
//! The second test is the important negative case: a restored database is not
//! authority over unrelated host state. With a foreign same-name link in place,
//! restore still succeeds as a database operation, but startup fails closed and
//! the foreign resource survives untouched.

use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wg_basic::{
    domain::{
        validate_desired_state, ClientId, DesiredAddress, DesiredClient, DesiredGeneration,
        DesiredInterface, DesiredNetworkPolicy, DesiredPeer, DesiredState, InstallationId,
        InterfaceId, LinkLifecycle, NetworkPrefix, OwnershipDeclaration, PeerId, PrivateKey,
        PublicKey, ResourcePresence,
    },
    protocol::{RequestOperation, ResponseBody},
    reconcile::DesiredManagedPeer,
    state::StateStore,
    wireguard::generate_keypair,
};

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
        let name = format!("wgdb{prefix}{suffix:x}");
        run_ip(&["netns", "add", &name]);
        Self(name)
    }

    fn name(&self) -> &str {
        &self.0
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

    fn delete_wireguard_link(&self, name: &str) {
        let output = command("ip", &["-n", self.name(), "link", "delete", name]);
        assert!(
            output.status.success(),
            "could not delete {name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn owned_table_present(&self) -> bool {
        let output = command(
            "ip",
            &[
                "netns",
                "exec",
                self.name(),
                "nft",
                "list",
                "tables",
                "inet",
            ],
        );
        output.status.success()
            && String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.split_whitespace().last() == Some("wg_basic"))
    }

    fn delete_owned_table(&self) {
        let mut child = Command::new("ip")
            .args(["netns", "exec", self.name(), "nft", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn nft");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(b"delete table inet wg_basic\n")
            .expect("write nft script");
        let output = child.wait_with_output().expect("await nft");
        assert!(
            output.status.success(),
            "could not delete the owned table: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = command("ip", &["netns", "delete", &self.0]);
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-durable-backup-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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

/// The real privileged service, running inside the namespace.
struct Netd {
    child: Child,
    socket: PathBuf,
    runtime: PathBuf,
}

impl Netd {
    fn start(namespace: &str) -> Self {
        let runtime = std::env::temp_dir().join(format!(
            "wgdb-netd-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = runtime.join("netd.sock");

        let child = Command::new("ip")
            .args([
                "netns",
                "exec",
                namespace,
                &executable().display().to_string(),
                "netd",
            ])
            .arg("--socket")
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn netd");
        let netd = Self {
            child,
            socket,
            runtime,
        };
        netd.await_socket();
        netd
    }

    fn await_socket(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.socket.exists() && self.pingable() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("netd never became ready");
    }

    fn pingable(&self) -> bool {
        UnixStream::connect(&self.socket).is_ok()
    }

    fn socket(&self) -> &Path {
        &self.socket
    }
}

impl Drop for Netd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.runtime);
    }
}

/// Runs one `wg-basic` management command as a real child process.
fn run_wg_basic(namespace: &str, args: &[&str]) -> Output {
    Command::new("ip")
        .args([
            "netns",
            "exec",
            namespace,
            &executable().display().to_string(),
        ])
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("could not run wg-basic {args:?}: {error}"))
}

fn run_reconcile(namespace: &str, state: &Path, socket: &Path) -> Output {
    run_wg_basic(
        namespace,
        &[
            "reconcile",
            "--state",
            state.to_str().expect("utf-8 path"),
            "--socket",
            socket.to_str().expect("utf-8 path"),
        ],
    )
}

fn eventually(mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

// ---------------------------------------------------------------------------
// Topology
// ---------------------------------------------------------------------------

/// The identity material a topology needs.
///
/// Held separately so a second, *fresh* set of namespaces can be built for the
/// post-restore phase while still presenting the same public keys the restored
/// database expects. Without that, the restored configuration would be talking
/// to peers that no longer exist.
struct Keys {
    client_public: PublicKey,
    client_private: PrivateKey,
    server_private: PrivateKey,
    server_public: PublicKey,
}

struct Topology {
    client: Namespace,
    server: Namespace,
    /// Held so the internet namespace lives for the whole fixture; traffic is
    /// addressed by address rather than by handle.
    #[allow(dead_code)]
    internet: Namespace,
    /// Kept alive for the whole fixture so the client device stays inspectable.
    client_netd: Netd,
}

impl Topology {
    fn build(keys: &Keys) -> Self {
        let client = Namespace::new("c");
        let server = Namespace::new("s");
        let internet = Namespace::new("i");

        run_ip(&["link", "add", "u-c", "type", "veth", "peer", "name", "u-s"]);
        run_ip(&["link", "set", "u-c", "netns", client.name()]);
        run_ip(&["link", "set", "u-s", "netns", server.name()]);
        run_ip(&["link", "add", "v-e", "type", "veth", "peer", "name", "v-i"]);
        run_ip(&["link", "set", "v-e", "netns", server.name()]);
        run_ip(&["link", "set", "v-i", "netns", internet.name()]);

        for (namespace, address, device) in [
            (&client, "192.0.2.2/24", "u-c"),
            (&server, "192.0.2.1/24", "u-s"),
            (&server, "198.51.100.1/24", "v-e"),
            (&internet, "198.51.100.2/24", "v-i"),
        ] {
            run_ip(&[
                "-n",
                namespace.name(),
                "addr",
                "add",
                address,
                "dev",
                device,
            ]);
            run_ip(&["-n", namespace.name(), "link", "set", device, "up"]);
        }
        for namespace in [&client, &server, &internet] {
            run_ip(&["-n", namespace.name(), "link", "set", "lo", "up"]);
        }
        run_ip(&[
            "-n",
            server.name(),
            "route",
            "add",
            "203.0.113.0/24",
            "dev",
            "v-e",
        ]);
        // Best effort: proving the firewall turns forwarding *on* only needs
        // this to succeed, and it is not worth a hard dependency on procps.
        let _ = command(
            "ip",
            &[
                "netns",
                "exec",
                server.name(),
                "sysctl",
                "-w",
                "net.ipv4.ip_forward=0",
            ],
        );

        let mut topology = Self {
            client,
            server,
            internet,
            client_netd: Netd {
                child: Command::new("true").spawn().expect("placeholder"),
                socket: PathBuf::new(),
                runtime: PathBuf::new(),
            },
        };
        topology.client_netd = Netd::start(topology.client.name());
        topology.configure_client(keys);
        topology
    }

    /// The client side is a plain WireGuard peer managed directly through netd.
    ///
    /// It is not part of the durable store: the store manages exactly one
    /// interface per installation, which is the server side under test.
    fn configure_client(&self, keys: &Keys) {
        let desired = wg_basic::reconcile::DesiredManagedInterface {
            interface: "wg-client".parse().unwrap(),
            ownership: OwnershipDeclaration::Managed,
            lifecycle: LinkLifecycle::Present,
            admin_up: Some(true),
            owner_tag: wg_basic::domain::OwnerTag::new(InstallationId::new(), InterfaceId::new()),
            wireguard: Some(wg_basic::reconcile::DesiredWireGuardConfiguration {
                private_key: keys.client_private.clone(),
                listen_port: 51821,
                peers: vec![DesiredManagedPeer {
                    public_key: keys.server_public.clone(),
                    allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                    persistent_keepalive_seconds: Some(25),
                    endpoint: Some("192.0.2.1:51820".parse().unwrap()),
                }],
                manage_all_peers: true,
            }),
            addresses: vec![DesiredAddress {
                address: "10.8.0.2/24".parse().unwrap(),
                presence: ResourcePresence::Present,
            }],
            routes: vec![wg_basic::domain::ManagedRoute {
                destination: "0.0.0.0/0".parse().unwrap(),
                gateway: None,
                presence: ResourcePresence::Present,
            }],
        };
        let response = wg_basic::protocol::request(
            self.client_netd.socket(),
            RequestOperation::ApplyManagedInterface { desired },
            9001,
        )
        .expect("client reconcile request");
        assert!(
            matches!(response, ResponseBody::ManagedInterfaceApplied(_)),
            "unexpected client response"
        );
    }

    /// A WireGuard device as netd itself reports it.
    ///
    /// The kernel's `ip` output does not print WireGuard peers, so the service
    /// is asked directly rather than inferred from link state.
    fn observe_device(netd: &Netd, interface: &str) -> String {
        match wg_basic::protocol::request(
            netd.socket(),
            RequestOperation::ObserveWireGuardDevice {
                interface: interface.parse().unwrap(),
            },
            9100,
        ) {
            Ok(body) => format!("{body:?}"),
            Err(error) => format!("observe failed: {error}"),
        }
    }

    /// Real traffic through the tunnel and out through masquerade.
    fn ping_internet(&self) -> Output {
        command(
            "ip",
            &[
                "netns",
                "exec",
                self.client.name(),
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
}

// ---------------------------------------------------------------------------
// Desired state
// ---------------------------------------------------------------------------

/// The server-side desired state, as the durable store holds it.
fn server_desired_state(keys: &Keys, interface_id: InterfaceId) -> DesiredState {
    let client_public = &keys.client_public;
    let peer_id = PeerId::new();
    let client_address: ipnet::IpNet = "10.8.0.2/32".parse().unwrap();
    DesiredState {
        interfaces: vec![DesiredInterface {
            id: interface_id,
            name: "wg-server".parse().unwrap(),
            ownership: OwnershipDeclaration::Managed,
            lifecycle: LinkLifecycle::Present,
            admin_up: Some(true),
            private_key: keys.server_private.clone(),
            listen_port: Some(51820),
            manage_all_peers: true,
            tunnel_prefixes: vec![NetworkPrefix::new("10.8.0.0/24".parse().unwrap())],
            addresses: vec![DesiredAddress {
                address: "10.8.0.1/24".parse().unwrap(),
                presence: ResourcePresence::Present,
            }],
            routes: Vec::new(),
            peers: vec![DesiredPeer {
                id: peer_id,
                public_key: client_public.clone(),
                private_key: None,
                preshared_key: None,
                allowed_ips: vec![NetworkPrefix::new(client_address)],
                persistent_keepalive_seconds: None,
                endpoint: None,
            }],
            clients: vec![DesiredClient {
                id: ClientId::new(),
                peer_id,
                assigned_address: client_address,
                route_policy: Default::default(),
            }],
        }],
        client_routes: Default::default(),
        // Masquerade out of v-e, so the client can reach the internet namespace.
        network_policy: Some(DesiredNetworkPolicy {
            wireguard_interface: "wg-server".parse().unwrap(),
            ipv4_forwarding_required: true,
            egress_interface: "v-e".parse().unwrap(),
            source_prefixes: vec![NetworkPrefix::new("10.8.0.0/24".parse().unwrap())],
            masquerade: true,
        }),
    }
}

/// Commits the server desired state so the store lands on generation 2.
fn seed_store(path: &Path, state: DesiredState) -> InstallationId {
    let store = StateStore::initialize(path).expect("initialize the store");
    let committed = store
        .mutate(wg_basic::state::INITIAL_DESIRED_GENERATION, |_| Ok(state))
        .expect("commit the server desired state");
    assert_eq!(committed.generation, DesiredGeneration::new(2).unwrap());
    let identity = store.installation_metadata().unwrap().installation_id;
    drop(store);
    identity
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn a_restored_database_drives_real_wireguard_forwarding_and_nat() {
    if nix::unistd::geteuid().as_raw() != 0 {
        panic!("rootful integration test must run as root");
    }
    // One keypair per side: the private half configures the device and the
    // public half is what the peer expects. Splitting them would leave the
    // handshake unable to complete.
    let client_keys = generate_keypair().unwrap();
    let server_keys = generate_keypair().unwrap();
    let keys = Keys {
        client_private: client_keys.private_key,
        client_public: client_keys.public_key,
        server_private: server_keys.private_key,
        server_public: server_keys.public_key,
    };
    let topology = Topology::build(&keys);
    let temp = TempDir::new();
    let interface_id = InterfaceId::new();
    let identity = seed_store(&temp.db(), server_desired_state(&keys, interface_id));
    let expected_tag = wg_basic::domain::OwnerTag::new(identity, interface_id).to_string();

    // 2. Startup reconciles and real traffic succeeds.
    {
        let netd = Netd::start(topology.server.name());
        let first = run_reconcile(topology.server.name(), &temp.db(), netd.socket());
        assert!(
            first.status.success(),
            "initial reconcile failed: {}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert!(eventually(|| topology.server.link_exists("wg-server")));
        assert_eq!(
            topology.server.link_alias("wg-server").as_deref(),
            Some(expected_tag.as_str())
        );
        assert!(eventually(|| topology.server.owned_table_present()));
        assert!(
            eventually(|| topology.ping_internet().status.success()),
            "masqueraded traffic must reach the internet namespace\nserver device: {}\nclient device: {}",
            Topology::observe_device(&netd, "wg-server"),
            Topology::observe_device(&topology.client_netd, "wg-client")
        );

        // 3. Back up at generation N, through the real operator command.
        let backup = temp.0.join("backup.db");
        let output = run_wg_basic(
            topology.server.name(),
            &[
                "state",
                "backup",
                backup.to_str().expect("utf-8"),
                "--state",
                temp.db().to_str().expect("utf-8"),
            ],
        );
        assert!(
            output.status.success(),
            "backup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let rendered = String::from_utf8_lossy(&output.stdout);
        assert!(
            rendered.contains("VPN private and preshared keys"),
            "backup output must warn about its contents: {rendered}"
        );
        let secret = keys.server_private.expose_secret();
        assert!(!rendered.contains(secret), "{rendered}");
        assert_eq!(
            std::os::unix::fs::MetadataExt::mode(&fs::symlink_metadata(&backup).unwrap()) & 0o777,
            0o600
        );
        // 4. Stop netd: the drop below ends the service before the teardown.
    }

    // 5. Remove the database, then build a *fresh* environment.
    //
    // A fresh set of namespaces is used rather than tearing the old ones down,
    // for two reasons. It is the stronger claim: the restored database has to
    // rebuild an environment that has never seen it. And it avoids carrying
    // namespace-scoped kernel state — conntrack entries above all — across the
    // two phases, which would test fixture hygiene rather than recovery.
    drop(topology);
    let _ = fs::remove_file(temp.db());
    let _ = fs::remove_file(temp.0.join("state.db-wal"));
    let _ = fs::remove_file(temp.0.join("state.db-shm"));
    let topology = Topology::build(&keys);

    // 6. Restore, through the real operator command.
    let backup = temp.0.join("backup.db");
    let output = run_wg_basic(
        topology.server.name(),
        &[
            "state",
            "restore",
            backup.to_str().expect("utf-8"),
            "--state",
            temp.db().to_str().expect("utf-8"),
        ],
    );
    assert!(
        output.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // 10. The restored desired state equals the backup source semantically.
    let restored = StateStore::open(temp.db()).expect("the restored database must open");
    let metadata = restored.installation_metadata().unwrap();
    let loaded = restored.load().unwrap();
    assert_eq!(
        metadata.installation_id, identity,
        "restore must not mint a new installation identity"
    );
    assert_eq!(loaded.generation, DesiredGeneration::new(2).unwrap());
    assert_eq!(
        loaded.state.interfaces[0].id, interface_id,
        "the restored interface identity must be the backed-up one"
    );
    assert_eq!(
        loaded.state.interfaces[0].peers[0].public_key, keys.client_public,
        "the restored peer must be the backed-up peer"
    );
    assert_eq!(
        loaded.state.interfaces[0].clients[0]
            .assigned_address
            .to_string(),
        "10.8.0.2/32",
        "the restored client assignment must be the backed-up one"
    );
    assert!(
        loaded.state.network_policy.as_ref().unwrap().masquerade,
        "the restored policy must still masquerade"
    );
    validate_desired_state(&loaded.state).expect("restored state must validate");
    drop(restored);

    // 7-9. Ordinary startup rebuilds the environment and traffic works again.
    {
        let netd = Netd::start(topology.server.name());
        let second = run_reconcile(topology.server.name(), &temp.db(), netd.socket());
        assert!(
            second.status.success(),
            "startup after restore failed: {}",
            String::from_utf8_lossy(&second.stderr)
        );
        assert!(eventually(|| topology.server.link_exists("wg-server")));
        assert_eq!(
            topology.server.link_alias("wg-server").as_deref(),
            Some(expected_tag.as_str()),
            "the rebuilt link must carry the restored installation's owner tag"
        );
        assert!(eventually(|| topology.server.owned_table_present()));
        assert!(
            eventually(|| topology.ping_internet().status.success()),
            "restored configuration must again carry real traffic\nserver device: {}\nclient device: {}",
            Topology::observe_device(&netd, "wg-server"),
            Topology::observe_device(&topology.client_netd, "wg-client")
        );
    }
}

#[test]
fn a_restore_does_not_authorize_taking_over_a_foreign_same_name_link() {
    if nix::unistd::geteuid().as_raw() != 0 {
        panic!("rootful integration test must run as root");
    }
    // One keypair per side: the private half configures the device and the
    // public half is what the peer expects. Splitting them would leave the
    // handshake unable to complete.
    let client_keys = generate_keypair().unwrap();
    let server_keys = generate_keypair().unwrap();
    let keys = Keys {
        client_private: client_keys.private_key,
        client_public: client_keys.public_key,
        server_private: server_keys.private_key,
        server_public: server_keys.public_key,
    };
    let topology = Topology::build(&keys);
    let temp = TempDir::new();
    let interface_id = InterfaceId::new();
    seed_store(&temp.db(), server_desired_state(&keys, interface_id));

    {
        let netd = Netd::start(topology.server.name());
        assert!(
            run_reconcile(topology.server.name(), &temp.db(), netd.socket())
                .status
                .success()
        );
        assert!(eventually(|| topology.server.link_exists("wg-server")));
        let output = run_wg_basic(
            topology.server.name(),
            &[
                "state",
                "backup",
                temp.0.join("backup.db").to_str().expect("utf-8"),
                "--state",
                temp.db().to_str().expect("utf-8"),
            ],
        );
        assert!(output.status.success());
    }

    // Tear the managed environment down and put an unrelated, same-name
    // WireGuard link in its place.
    let _ = fs::remove_file(temp.db());
    let _ = fs::remove_file(temp.0.join("state.db-wal"));
    let _ = fs::remove_file(temp.0.join("state.db-shm"));
    topology.server.delete_wireguard_link("wg-server");
    topology.server.delete_owned_table();

    let foreign = wg_basic::domain::OwnerTag::new(InstallationId::new(), InterfaceId::new());
    run_ip(&[
        "-n",
        topology.server.name(),
        "link",
        "add",
        "wg-server",
        "type",
        "wireguard",
    ]);
    run_ip(&[
        "-n",
        topology.server.name(),
        "link",
        "set",
        "wg-server",
        "alias",
        &foreign.to_string(),
    ]);

    // Restore succeeds: it is a database operation and the candidate is valid.
    let backup = temp.0.join("backup.db");
    let output = run_wg_basic(
        topology.server.name(),
        &[
            "state",
            "restore",
            backup.to_str().expect("utf-8"),
            "--state",
            temp.db().to_str().expect("utf-8"),
        ],
    );
    assert!(
        output.status.success(),
        "restore must succeed as a database operation: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Startup must then fail closed and leave the foreign link alone.
    let netd = Netd::start(topology.server.name());
    let reconcile = run_reconcile(topology.server.name(), &temp.db(), netd.socket());
    assert!(
        !reconcile.status.success(),
        "a restored database must not authorize taking over a foreign link"
    );
    assert_eq!(
        topology.server.link_alias("wg-server").as_deref(),
        Some(foreign.to_string().as_str()),
        "the foreign link must survive the refused startup untouched"
    );

    // The desired state is preserved for operator resolution.
    let store = StateStore::open(temp.db()).expect("the restored store must still open");
    assert_eq!(
        store.current_generation().unwrap(),
        DesiredGeneration::new(2).unwrap(),
        "the restored desired generation is preserved through the conflict"
    );
    assert_eq!(
        store.convergence().unwrap().last_outcome.as_deref(),
        Some("state_conflict")
    );
}
