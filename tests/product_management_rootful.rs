//! Phase 8 M001 rootful evidence.
//!
//! M001 has no HTTP surface, so the claims that need a real kernel are made
//! here, against a real `netd` inside a real network namespace:
//!
//! * a created client becomes a real WireGuard peer;
//! * disabling that client removes the real peer from the device;
//! * re-enabling restores the **same** peer, not a new one;
//! * deleting removes the real peer;
//! * a backend outage *after* the commit is reported as committed-but-degraded,
//!   and a later restart converges it.
//!
//! The last one is the reason this file exists at all. M001's central claim is
//! that a database commit and a kernel apply are two different facts, and that a
//! receipt can say so. A receipt can only be believed if a real outage produces
//! one, so the outage is induced here rather than simulated.
//!
//! # Where each process runs, and why
//!
//! `netd` runs **inside** the namespace, because it is the process that has to
//! create real links there. The management worker runs on the host over the
//! authorized unix socket, which is the real unprivileged deployment path.
//!
//! # Root is required, and says so
//!
//! The whole file is behind `linux-integration`, and every test checks the
//! effective uid first so a mistake is a clear message rather than a confusing
//! namespace failure.

#![cfg(all(target_os = "linux", feature = "linux-integration"))]

use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
};
use wg_basic::{
    domain::{ClientRoutePolicy, DesiredGeneration, InterfaceId, NetworkPrefix, PrincipalId},
    management::{set_password_at, spawn, WorkerClient, WorkerConfig, WorkerStartup},
    product::{
        ClientCreateCommand, ClientDeleteCommand, ClientLabel, ServerSetupCommand,
        SetClientEnabledCommand,
    },
    protocol::{RequestOperation, ResponseBody},
    state::StateStore,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");

fn require_root(suite: &str) {
    let status =
        std::fs::read_to_string("/proc/self/status").expect("/proc/self/status is readable");
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|value| value.split_whitespace().next())
        .unwrap_or("0");
    assert_eq!(
        uid, "0",
        "rootful integration test must run as root (effective uid was {uid}); \
         run it with: sudo -E env \"PATH=$PATH\" CARGO_HOME=/tmp/wg-basic-root-cargo \
         cargo test --locked --features linux-integration --test product_management_rootful"
    );
    let _ = suite;
}

fn run(args: &[&str]) -> std::process::Output {
    let output = Command::new("ip")
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("could not run ip {args:?}: {error}"));
    assert!(
        output.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// A disposable network namespace that removes itself.
struct Namespace(String);

impl Namespace {
    fn new(label: &str) -> Self {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("wgm1{label}{suffix:x}");
        run(&["netns", "add", &name]);
        run(&["-n", &name, "link", "set", "lo", "up"]);
        Self(name)
    }

    /// Public keys present on the named WireGuard device inside the namespace.
    ///
    /// Asked of `netd` over the authorized socket rather than of `ip wg`, for
    /// two reasons: `wireguard-tools` is not installed on every runner, and the
    /// privileged backend is the component whose behaviour this file is
    /// qualifying in the first place.
    fn device_public_keys(&self, socket: &std::path::Path, interface: &str) -> Vec<String> {
        let name: wg_basic::domain::InterfaceName = interface.parse().expect("interface name");
        match wg_basic::protocol::request(
            socket,
            RequestOperation::ObserveWireGuardDevice { interface: name },
            9001,
        ) {
            Ok(ResponseBody::WireGuardDevice(device)) => device
                .peers
                .into_iter()
                .map(|peer| peer.public_key.expose().to_owned())
                .collect(),
            _ => Vec::new(),
        }
    }

    fn interface_exists(&self, interface: &str) -> bool {
        Command::new("ip")
            .args(["-n", &self.0, "link", "show", interface])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).status();
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = PathBuf::from(format!(
            "/tmp/wg-basic-m001-rootful-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn state(&self) -> PathBuf {
        self.0.join("state.db")
    }

    fn netd_socket(&self) -> PathBuf {
        self.0.join("netd.sock")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Managed {
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
    reader: Option<thread::JoinHandle<()>>,
}

impl Managed {
    fn netd(namespace: &str, scratch: &Scratch) -> Self {
        let socket = scratch.netd_socket();
        let mut command = Command::new("ip");
        command.args(["netns", "exec", namespace, BINARY, "netd"]);
        command.arg("--socket").arg(&socket);
        Self::spawn(command)
    }

    fn spawn(mut command: Command) -> Self {
        command
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        let mut child = command.spawn().expect("child process starts");
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        let stderr = child.stderr.take().expect("stderr is piped");
        let reader = Some(thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                sink.lock().unwrap().push(line);
            }
        }));
        Self {
            child,
            lines,
            reader,
        }
    }

    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Whether the backend has logged an answerable readiness line.
    fn ready(&self, needle: &str) -> bool {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.contains(needle))
    }

    /// Everything the child has logged, for a failure message.
    #[allow(dead_code)]
    fn stderr(&self) -> String {
        self.lines.lock().unwrap().join("\n")
    }
}

impl Drop for Managed {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// Waits for `condition`, polling on a bounded deadline rather than sleeping a
/// fixed amount.
fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if condition() {
            return;
        }
        thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

/// One installed, running, converged installation.
///
/// Mutations go through the management worker rather than straight at the store,
/// because the worker is the only place that can reconcile. Writing desired state
/// without a reconcile would leave every claim about real kernel peers untested.
struct Installation {
    scratch: Scratch,
    namespace: Namespace,
    netd: Managed,
    store: Arc<StateStore>,
    worker: WorkerStartup,
    principal: PrincipalId,
}

impl Installation {
    async fn start(label: &str, prefix: &str) -> Self {
        let scratch = Scratch::new();
        let namespace = Namespace::new(label);
        let netd = Managed::netd(&namespace.0, &scratch);
        wait_until("netd to listen", || netd.ready("listening"));

        let store = Arc::new(StateStore::initialize(scratch.state()).expect("store"));
        set_password_at(scratch.state(), "admin", "an administrator password")
            .expect("provision the administrator");
        let principal = StateStore::open(scratch.state())
            .expect("reopen")
            .principals()
            .expect("principals")[0]
            .id;

        let worker = spawn(WorkerConfig::new(scratch.state(), scratch.netd_socket()))
            .expect("the worker starts");
        let client: WorkerClient = worker.client().clone();

        let installation = Self {
            scratch,
            namespace,
            netd,
            store,
            worker,
            principal,
        };
        installation.setup(&client, prefix).await;
        installation
    }

    async fn setup(&self, client: &WorkerClient, prefix: &str) {
        client
            .setup_server(ServerSetupCommand {
                principal_id: self.principal,
                expected_generation: DesiredGeneration::default(),
                interface_name: "wg0".parse().unwrap(),
                tunnel_prefix: NetworkPrefix::new(prefix.parse().unwrap()),
                server_address: None,
                listen_port: 51820,
                advertised_endpoint: wg_basic::product::AdvertisedEndpoint::new(
                    "vpn.example.com",
                    51820,
                )
                .unwrap(),
                egress_interface: "lo".parse().unwrap(),
                ipv4_forwarding_required: false,
                masquerade: false,
                default_client_route_policy: ClientRoutePolicy::default(),
            })
            .await
            .expect("server setup");
        wait_until("the WireGuard device to exist", || {
            self.namespace.interface_exists("wg0")
        });
    }

    fn client(&self) -> WorkerClient {
        self.worker.client().clone()
    }

    fn interface_id(&self) -> InterfaceId {
        self.store
            .load()
            .unwrap()
            .state
            .interfaces
            .first()
            .map(|interface| interface.id)
            .expect("a configured interface")
    }

    async fn create_client(
        &self,
        client: &WorkerClient,
        label: &str,
    ) -> wg_basic::product::ProductClient {
        self.create_client_receipted(client, label).await.client
    }

    /// Creates a client and hands back the reconciled receipt too.
    async fn create_client_receipted(
        &self,
        client: &WorkerClient,
        label: &str,
    ) -> wg_basic::management::ClientMutationReply {
        client
            .create_client(ClientCreateCommand {
                principal_id: self.principal,
                expected_generation: self.store.current_generation().unwrap(),
                interface_id: self.interface_id(),
                label: ClientLabel::new(label).unwrap(),
                requested_address: None,
                route_policy: None,
                dns_servers: Vec::new(),
                client_keepalive_seconds: None,
            })
            .await
            .unwrap_or_else(|error| panic!("client create failed: {error:?}"))
    }

    /// Restarts the backend against the same durable state.
    async fn restart_backend(&mut self) {
        let replacement = Managed::netd(&self.namespace.0, &self.scratch);
        wait_until("netd to listen again", || replacement.ready("listening"));
        let old = std::mem::replace(&mut self.netd, replacement);
        drop(old);
    }

    /// Restarts the management worker too, so its startup reconcile runs against
    /// the same durable state.
    ///
    /// This is the claim plan §7 asks for -- "restart later reconciles it" -- and
    /// it is stronger than issuing another command, because nothing is asking
    /// for work: the worker comes up, reads the generation that was committed
    /// while the backend was gone, and converges it on its own.
    fn restart_worker(&mut self) {
        let replacement = spawn(WorkerConfig::new(
            self.scratch.state(),
            self.scratch.netd_socket(),
        ))
        .expect("the worker starts again");
        let old = std::mem::replace(&mut self.worker, replacement);
        drop(old);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_created_client_becomes_a_real_kernel_peer() {
    require_root("created client");
    let installation = Installation::start("mkpeer", "10.61.0.0/24").await;
    let worker = installation.client();

    let before = installation
        .namespace
        .device_public_keys(&installation.scratch.netd_socket(), "wg0");
    let reply = worker
        .create_client(ClientCreateCommand {
            principal_id: installation.principal,
            expected_generation: installation.store.current_generation().unwrap(),
            interface_id: installation.interface_id(),
            label: ClientLabel::new("laptop").unwrap(),
            requested_address: None,
            route_policy: None,
            dns_servers: Vec::new(),
            client_keepalive_seconds: None,
        })
        .await
        .unwrap_or_else(|error| panic!("create failed: {error:?}"));
    eprintln!("DIAG receipt={:?}", reply.receipt);
    let client = reply.client;
    let key = client.public_key.expose().to_owned();

    wait_until("the new peer to reach the device", || {
        let keys = installation
            .namespace
            .device_public_keys(&installation.scratch.netd_socket(), "wg0");
        keys.len() == before.len() + 1 && keys.contains(&key)
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabling_removes_the_real_peer_and_re_enabling_restores_the_same_one() {
    require_root("enable/disable");
    let installation = Installation::start("mtoggle", "10.62.0.0/24").await;
    let worker = installation.client();
    let client = installation.create_client(&worker, "laptop").await;
    let key = client.public_key.expose().to_owned();
    wait_until("the peer to appear", || {
        installation
            .namespace
            .device_public_keys(&installation.scratch.netd_socket(), "wg0")
            .contains(&key)
    });

    let disabled = worker
        .set_client_enabled(SetClientEnabledCommand {
            principal_id: installation.principal,
            expected_generation: installation.store.current_generation().unwrap(),
            client_id: client.client_id,
            enabled: wg_basic::product::ClientEnabled::Disabled,
        })
        .await
        .expect("disable");
    assert!(
        disabled.receipt.is_enforced(),
        "with a live backend the disable is enforced, not merely committed"
    );

    wait_until("the peer to leave the device", || {
        !installation
            .namespace
            .device_public_keys(&installation.scratch.netd_socket(), "wg0")
            .contains(&key)
    });

    // The durable row, the peer, and the address all survive the disable.
    let desired = installation.store.load().unwrap().state;
    assert!(
        desired.interfaces[0]
            .clients
            .iter()
            .any(|row| row.id == client.client_id),
        "a disabled client keeps its row and its address reservation"
    );
    assert!(
        desired.interfaces[0]
            .peers
            .iter()
            .any(|peer| peer.id == client.peer_id),
        "a disabled client keeps its peer in durable state"
    );

    worker
        .set_client_enabled(SetClientEnabledCommand {
            principal_id: installation.principal,
            expected_generation: installation.store.current_generation().unwrap(),
            client_id: client.client_id,
            enabled: wg_basic::product::ClientEnabled::Enabled,
        })
        .await
        .expect("enable");

    wait_until("the same peer to return to the device", || {
        installation
            .namespace
            .device_public_keys(&installation.scratch.netd_socket(), "wg0")
            .contains(&key)
    });
    assert_eq!(
        desired.interfaces[0]
            .peers
            .iter()
            .find(|peer| peer.id == client.peer_id)
            .map(|peer| peer.public_key.expose().to_owned()),
        Some(key),
        "re-enabling restores the identical peer"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_a_client_removes_the_real_peer() {
    require_root("delete");
    let installation = Installation::start("mdelete", "10.63.0.0/24").await;
    let worker = installation.client();
    let client = installation.create_client(&worker, "laptop").await;
    let key = client.public_key.expose().to_owned();
    wait_until("the peer to appear", || {
        installation
            .namespace
            .device_public_keys(&installation.scratch.netd_socket(), "wg0")
            .contains(&key)
    });

    let receipt = worker
        .delete_client(ClientDeleteCommand {
            principal_id: installation.principal,
            expected_generation: installation.store.current_generation().unwrap(),
            client_id: client.client_id,
        })
        .await
        .expect("delete");

    assert!(receipt.is_enforced());
    wait_until("the peer to leave the device", || {
        !installation
            .namespace
            .device_public_keys(&installation.scratch.netd_socket(), "wg0")
            .contains(&key)
    });
    let desired = installation.store.load().unwrap().state;
    assert!(desired.interfaces[0].peers.is_empty());
    assert!(desired.interfaces[0].clients.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backend_outage_after_commit_is_committed_but_degraded_and_restart_converges_it() {
    require_root("degraded enforcement");
    let mut installation = Installation::start("mdegrade", "10.64.0.0/24").await;
    let worker = installation.client();
    installation.create_client(&worker, "laptop").await;

    // Kill the backend, so the next commit is durable but cannot be enforced.
    let _ = installation.netd.child.kill();
    let _ = installation.netd.child.wait();
    wait_until("netd to stop answering", || !installation.netd.alive());

    let degraded = worker
        .create_client(ClientCreateCommand {
            principal_id: installation.principal,
            expected_generation: installation.store.current_generation().unwrap(),
            interface_id: installation.interface_id(),
            label: ClientLabel::new("created while the backend is down").unwrap(),
            requested_address: None,
            route_policy: None,
            dns_servers: Vec::new(),
            client_keepalive_seconds: None,
        })
        .await
        .expect("the commit must succeed even with the backend down");

    // The commit is durable truth and it moved forward.
    assert!(
        degraded.receipt.generation > DesiredGeneration::default(),
        "the generation advanced even though enforcement could not happen"
    );
    assert!(
        installation.store.load().unwrap().state.interfaces[0]
            .clients
            .iter()
            .any(|row| row.id == degraded.client.client_id),
        "the committed client is present in durable state despite the outage"
    );

    // The enforcement half is reported honestly rather than claimed.
    assert!(
        !degraded.receipt.is_enforced(),
        "a commit that never reached the kernel must not report itself enforced"
    );
    assert!(
        degraded.receipt.enforcement.degraded_category().is_some(),
        "a degraded receipt must carry a bounded category, not just a flag"
    );

    // The audit trail records the enforcement outcome separately from the
    // commit, because the kernel's answer is not inside the commit.
    let service = wg_basic::product::ProductService::new(&installation.store);
    service
        .record_degraded_enforcement(
            Some(installation.principal),
            degraded.client.client_id,
            degraded.receipt.enforcement.degraded_category().unwrap(),
        )
        .expect("record the degraded outcome");
    let events = installation.store.audit_events(50).unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.action.as_str() == "enforcement_degraded"),
        "the degraded enforcement outcome is in the audit trail"
    );
    assert!(
        events.iter().all(|event| event
            .resource_id
            .as_deref()
            .map(|id| !id.contains("PRIVATE KEY"))
            .unwrap_or(true)),
        "an audit row never carries key material"
    );

    // A later restart converges what the outage deferred.
    installation.restart_backend().await;
    installation.restart_worker();
    let key = degraded.client.public_key.expose().to_owned();
    wait_until("the deferred peer to reach the device", || {
        installation
            .namespace
            .device_public_keys(&installation.scratch.netd_socket(), "wg0")
            .contains(&key)
    });
}
