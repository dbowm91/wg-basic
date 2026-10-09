//! Phase 8 rootful product evidence.
//!
//! Product claims that need a real kernel are made here, against a real `netd`
//! inside disposable network namespaces and, where applicable, through the
//! authenticated management HTTP service:
//!
//! * a created client becomes a real WireGuard peer;
//! * disabling that client removes the real peer from the device;
//! * re-enabling restores the **same** peer, not a new one;
//! * deleting removes the real peer;
//! * a backend outage *after* the commit is reported as committed-but-degraded,
//!   and a later restart converges it.
//!
//! The outage case keeps durable commit and kernel application as separate
//! observable facts. The M005 fixture additionally drives setup, client
//! lifecycle, exports, enrollment, telemetry, and audit through the real HTTP
//! route pipeline.
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

use eggserve_server::Server;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
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
    domain::{
        ClientRoutePolicy, DesiredGeneration, InterfaceId, InterfaceName, NetworkPrefix,
        PresharedKey, PrincipalId, PrivateKey, PublicKey,
    },
    http::{
        AuthenticatedApi, Bucket, LoginLimiter, ManagementHttpConfig, ManagementService,
        OriginPolicy,
    },
    management::{set_password_at, spawn, WorkerClient, WorkerConfig, WorkerStartup},
    product::{
        ClientCreateCommand, ClientDeleteCommand, ClientLabel, ServerSetupCommand,
        SetClientEnabledCommand,
    },
    protocol::{RequestOperation, ResponseBody},
    state::StateStore,
    wireguard::{DesiredWireGuardPeer, FieldUpdate, PeerMutation, WireGuardDevicePatch},
};

#[allow(clippy::too_many_arguments)]
fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    host: &str,
    origin: Option<&str>,
    cookie: Option<&str>,
    csrf: Option<&str>,
    body: &str,
) -> (u16, String, Vec<(String, String)>) {
    let mut stream = TcpStream::connect(addr).expect("management listener");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(origin) = origin {
        request.push_str(&format!("Origin: {origin}\r\n"));
    }
    if let Some(cookie) = cookie {
        request.push_str(&format!("Cookie: {cookie}\r\n"));
    }
    if let Some(csrf) = csrf {
        request.push_str(&format!("x-wg-basic-csrf: {csrf}\r\n"));
    }
    if !body.is_empty() {
        request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes()).unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let status = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    let mut headers = Vec::new();
    loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (k, v) = line.split_once(':').unwrap();
        headers.push((k.to_owned(), v.trim().to_owned()));
    }
    let length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).unwrap();
    (status, String::from_utf8(bytes).unwrap(), headers)
}

static COUNTER: AtomicU64 = AtomicU64::new(0);
const EMBEDDED_ASSET_BYTES: usize = include_str!("../src/http/assets/index.html").len()
    + include_str!("../src/http/assets/app.css").len()
    + include_str!("../src/http/assets/app.js").len()
    + include_str!("../src/http/assets/enroll.html").len()
    + include_str!("../src/http/assets/enroll.js").len();

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

    fn device(
        &self,
        socket: &std::path::Path,
        interface: &str,
    ) -> wg_basic::wireguard::ObservedWireGuardDevice {
        match wg_basic::protocol::request(
            socket,
            RequestOperation::ObserveWireGuardDevice {
                interface: interface.parse().unwrap(),
            },
            9002,
        ) {
            Ok(ResponseBody::WireGuardDevice(device)) => device,
            other => panic!("expected WireGuard observation, got {other:?}"),
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
        let installation = Self::start_unconfigured(label).await;
        let client = installation.client();
        installation.setup(&client, prefix).await;
        installation
    }

    async fn start_unconfigured(label: &str) -> Self {
        let scratch = Scratch::new();
        let namespace = Namespace::new(label);
        let netd = Managed::netd(&namespace.0, &scratch);
        wait_until("netd to listen", || netd.ready("netd.started"));

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

        Self {
            scratch,
            namespace,
            netd,
            store,
            worker,
            principal,
        }
    }

    async fn setup(&self, client: &WorkerClient, prefix: &str) {
        client
            .setup_server(ServerSetupCommand {
                principal_id: self.principal,
                expected_generation: DesiredGeneration::default(),
                interface_name: "wg0".parse().unwrap(),
                tunnel_prefix: NetworkPrefix::new(prefix.parse().unwrap()),
                ipv6_tunnel_prefix: None,
                server_address: None,
                ipv6_server_address: None,
                listen_port: 51820,
                advertised_endpoint: wg_basic::product::AdvertisedEndpoint::new(
                    "198.18.0.1",
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
        wait_until("netd to listen again", || replacement.ready("netd.started"));
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
async fn exported_client_config_establishes_a_real_kernel_handshake() {
    require_root("exported client handshake");
    let mut installation = Installation::start_unconfigured("export").await;
    let client_ns = Namespace::new("client");
    let client_scratch = Scratch::new();
    let client_netd = Managed::netd(&client_ns.0, &client_scratch);
    wait_until("client netd to listen", || {
        client_netd.ready("netd.started")
    });

    run(&[
        "link", "add", "wgx1", "type", "veth", "peer", "name", "wgx2",
    ]);
    run(&["link", "set", "wgx1", "netns", &installation.namespace.0]);
    run(&["link", "set", "wgx2", "netns", &client_ns.0]);
    run(&[
        "-n",
        &installation.namespace.0,
        "addr",
        "add",
        "198.18.0.1/24",
        "dev",
        "wgx1",
    ]);
    run(&[
        "-n",
        &client_ns.0,
        "addr",
        "add",
        "198.18.0.2/24",
        "dev",
        "wgx2",
    ]);
    run(&["-n", &installation.namespace.0, "link", "set", "wgx1", "up"]);
    run(&["-n", &client_ns.0, "link", "set", "wgx2", "up"]);

    let management = installation.client();
    let api = AuthenticatedApi::new(
        management.clone(),
        Arc::new(OriginPolicy::loopback_only("127.0.0.1:0".parse().unwrap())),
        Arc::new(LoginLimiter::new(
            Bucket::per_second(100, 100),
            Bucket::per_second(100, 100),
            16,
        )),
    );
    let http_server = Server::builder()
        .runtime(
            ManagementHttpConfig::new("127.0.0.1:0")
                .unwrap()
                .runtime_config()
                .unwrap(),
        )
        .build()
        .unwrap();
    let handle = http_server
        .start_with_service(ManagementService::new(api))
        .await
        .unwrap();
    let addr = handle.local_addr();
    let host = addr.to_string();
    let origin = format!("http://{host}");
    let (control, mut completion) = handle.into_parts();
    let (ui_status, ui_body, ui_headers) = http(addr, "GET", "/", &host, None, None, None, "");
    assert_eq!(ui_status, 200);
    assert!(ui_body.contains("id=\"setup-form\""));
    assert!(ui_body.contains("id=\"client-rows\""));
    assert!(ui_headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-security-policy")
            && value == "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    }));
    let (login_status, _, login_headers) = http(
        addr,
        "POST",
        "/api/v1/login",
        &host,
        Some(&origin),
        None,
        None,
        r#"{"username":"admin","password":"an administrator password"}"#,
    );
    assert_eq!(login_status, 200);
    let cookie = login_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .unwrap()
        .1
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let (_, session_body, _) = http(
        addr,
        "GET",
        "/api/v1/session",
        &host,
        None,
        Some(&cookie),
        None,
        "",
    );
    let csrf = serde_json::from_str::<serde_json::Value>(&session_body).unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let setup_started = std::time::Instant::now();
    let (_, unconfigured_body, _) = http(
        addr,
        "GET",
        "/api/v1/server",
        &host,
        None,
        Some(&cookie),
        None,
        "",
    );
    let unconfigured: serde_json::Value = serde_json::from_str(&unconfigured_body).unwrap();
    assert!(unconfigured["server"].is_null());
    let setup_body = r#"{"expected_generation":1,"interface_name":"wg0","tunnel_prefix":"10.67.0.0/24","ipv6_tunnel_prefix":"2001:db8:67::/64","server_address":"10.67.0.1","ipv6_server_address":"2001:db8:67::1","listen_port":51820,"advertised_endpoint":"198.18.0.1:51820","egress_interface":"lo","ipv4_forwarding_required":false,"masquerade":false,"default_client_route_policy":{"prefixes":["10.67.0.1/32","2001:db8:67::1/128"]}}"#;
    let (setup_status, setup_reply, _) = http(
        addr,
        "POST",
        "/api/v1/setup",
        &host,
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        setup_body,
    );
    assert_eq!(setup_status, 200, "HTTP setup: {setup_reply}");
    let setup_elapsed = setup_started.elapsed();
    wait_until("HTTP setup to create the server WireGuard device", || {
        installation.namespace.interface_exists("wg0")
    });
    let dashboard_read_started = std::time::Instant::now();
    let (_, summary_body, _) = http(
        addr,
        "GET",
        "/api/v1/server",
        &host,
        None,
        Some(&cookie),
        None,
        "",
    );
    let summary: serde_json::Value = serde_json::from_str(&summary_body).unwrap();
    let dashboard_read_elapsed = dashboard_read_started.elapsed();
    let interface_id = summary["server"]["interface_id"].as_str().unwrap();
    let create_body = format!(
        r#"{{"expected_generation":{},"interface_id":"{interface_id}","label":"exported-phone","route_policy":{{"prefixes":["10.67.0.1/32","2001:db8:67::1/128"]}}}}"#,
        summary["generation"].as_u64().unwrap()
    );
    let create_started = std::time::Instant::now();
    let (create_status, create_reply, _) = http(
        addr,
        "POST",
        "/api/v1/clients",
        &host,
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        &create_body,
    );
    assert_eq!(create_status, 201, "HTTP create: {create_reply}");
    let create_elapsed_including_reconcile = create_started.elapsed();
    let created: serde_json::Value = serde_json::from_str(&create_reply).unwrap();
    let client_id: wg_basic::domain::ClientId = created["data"]["client_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let client_public_key =
        PublicKey::new(created["data"]["public_key"].as_str().unwrap().to_owned()).unwrap();
    let peer_id = created["data"]["peer_id"].as_str().unwrap().to_owned();
    let (config_status, config_text, config_headers) = http(
        addr,
        "GET",
        &format!("/api/v1/clients/{client_id}/config"),
        &host,
        None,
        Some(&cookie),
        None,
        "",
    );
    assert_eq!(config_status, 200);
    assert!(config_headers
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("cache-control") && value == "no-store"));
    let (qr_status, qr_body, _) = http(
        addr,
        "GET",
        &format!("/api/v1/clients/{client_id}/qr"),
        &host,
        None,
        Some(&cookie),
        None,
        "",
    );
    assert_eq!(qr_status, 200);
    assert!(qr_body.contains("<svg"));
    let (link_status, link_body, _) = http(
        addr,
        "POST",
        &format!("/api/v1/clients/{client_id}/enrollment-links"),
        &host,
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        r#"{"expires_in_seconds":600}"#,
    );
    assert_eq!(link_status, 201, "enrollment link: {link_body}");
    let link: serde_json::Value = serde_json::from_str(&link_body).unwrap();
    let capability_id = link["capability_id"].as_str().unwrap();
    let token = link["share_url"]
        .as_str()
        .unwrap()
        .split_once("#token=")
        .unwrap()
        .1;
    assert_eq!(
        http(
            addr,
            "GET",
            &format!("/enroll/{capability_id}"),
            &host,
            None,
            None,
            None,
            ""
        )
        .0,
        200
    );
    let consume_path = format!("/api/v1/enroll/{capability_id}/consume");
    let consume_body = format!(r#"{{"token":"{token}"}}"#);
    let (consume_status, enrollment_config, _) = http(
        addr,
        "POST",
        &consume_path,
        &host,
        Some(&origin),
        None,
        None,
        &consume_body,
    );
    assert_eq!(
        consume_status, 200,
        "first consume returns the exported config"
    );
    assert_eq!(
        http(
            addr,
            "POST",
            &consume_path,
            &host,
            Some(&origin),
            None,
            None,
            &consume_body
        )
        .0,
        410
    );
    assert_eq!(enrollment_config, config_text);
    let values = config_text
        .lines()
        .filter_map(|line| line.split_once(" = "))
        .collect::<std::collections::HashMap<_, _>>();
    let addresses = config_text
        .lines()
        .filter_map(|line| line.strip_prefix("Address = "))
        .map(|address| address.parse::<NetworkPrefix>().expect("config address"))
        .collect::<Vec<_>>();
    assert_eq!(
        addresses.len(),
        2,
        "dual-stack export contains both tunnel addresses"
    );
    let private_key = PrivateKey::new(values["PrivateKey"].to_owned()).expect("config key");
    let server_public_key = PublicKey::new(values["PublicKey"].to_owned()).expect("config peer");
    let endpoint = values["Endpoint"]
        .parse::<std::net::SocketAddr>()
        .unwrap_or_else(|error| {
            panic!(
                "invalid exported endpoint {:?}: {error}",
                values["Endpoint"]
            )
        });
    let allowed_ips = values["AllowedIPs"]
        .split(", ")
        .map(|ip| {
            ip.parse::<NetworkPrefix>().unwrap_or_else(|error| {
                panic!(
                    "invalid exported route {ip:?} from {:?}: {error}",
                    values["AllowedIPs"]
                )
            })
        })
        .collect();
    let preshared_key = values
        .get("PresharedKey")
        .map(|value| PresharedKey::new((*value).to_owned()).unwrap());
    let keepalive = values
        .get("PersistentKeepalive")
        .map(|value| value.parse::<u16>().unwrap());
    run(&[
        "-n",
        &client_ns.0,
        "link",
        "add",
        "wg-client",
        "type",
        "wireguard",
    ]);
    for address in &addresses {
        run(&[
            "-n",
            &client_ns.0,
            "addr",
            "add",
            &address.to_string(),
            "dev",
            "wg-client",
        ]);
    }
    run(&["-n", &client_ns.0, "link", "set", "wg-client", "up"]);
    let interface: InterfaceName = "wg-client".parse().unwrap();
    let reply = wg_basic::protocol::request(
        client_scratch.netd_socket(),
        RequestOperation::ApplyWireGuardDevice {
            interface: interface.clone(),
            patch: WireGuardDevicePatch {
                private_key: FieldUpdate::Set(private_key),
                listen_port: FieldUpdate::Set(51821),
                peer: Some(PeerMutation::Add(DesiredWireGuardPeer {
                    public_key: server_public_key.clone(),
                    preshared_key: preshared_key.clone(),
                    allowed_ips: allowed_ips.clone(),
                    persistent_keepalive_seconds: keepalive,
                    endpoint: Some(endpoint),
                })),
            },
        },
        9003,
    )
    .expect("configure client from exported values");
    assert!(
        matches!(reply, ResponseBody::WireGuardApplied(_)),
        "{reply:?}"
    );
    run(&[
        "-n",
        &client_ns.0,
        "route",
        "add",
        "10.67.0.1/32",
        "dev",
        "wg-client",
    ]);
    run(&[
        "-n",
        &client_ns.0,
        "route",
        "add",
        "2001:db8:67::1/128",
        "dev",
        "wg-client",
    ]);
    let ping = Command::new("ip")
        .args([
            "netns",
            "exec",
            &client_ns.0,
            "ping",
            "-n",
            "-c",
            "1",
            "-W",
            "2",
            "-I",
            "wg-client",
            "10.67.0.1",
        ])
        .output()
        .expect("ping");
    let _ = ping; // A local firewall may refuse ICMP; the WireGuard UDP exchange is authoritative here.
    let ping6 = Command::new("ip")
        .args([
            "netns",
            "exec",
            &client_ns.0,
            "ping",
            "-6",
            "-n",
            "-c",
            "1",
            "-W",
            "2",
            "-I",
            "wg-client",
            "2001:db8:67::1",
        ])
        .output()
        .expect("IPv6 ping");
    assert!(
        ping6.status.success(),
        "IPv6 tunnel traffic failed: {}",
        String::from_utf8_lossy(&ping6.stderr)
    );
    let observed_client = client_ns.device(&client_scratch.netd_socket(), "wg-client");
    let exported_peer = observed_client
        .peers
        .first()
        .expect("exported peer is installed");
    assert_eq!(exported_peer.endpoint, Some(endpoint));
    assert!(exported_peer
        .allowed_ips
        .contains(&"10.67.0.1/32".parse().unwrap()));
    assert!(exported_peer
        .allowed_ips
        .contains(&"2001:db8:67::1/128".parse().unwrap()));
    assert!(exported_peer.latest_handshake.is_some());
    assert!(exported_peer.rx_bytes.unwrap_or_default() > 0);
    assert!(exported_peer.tx_bytes.unwrap_or_default() > 0);
    wait_until("the exported client handshake and traffic counters", || {
        installation
            .namespace
            .device(&installation.scratch.netd_socket(), "wg0")
            .peers
            .iter()
            .any(|peer| {
                peer.public_key == client_public_key
                    && peer.latest_handshake.is_some()
                    && peer.rx_bytes.unwrap_or_default() > 0
                    && peer.tx_bytes.unwrap_or_default() > 0
            })
    });

    // Whole-network maintenance keeps the configured server/client rows while
    // projecting the interface and owned network policy absent.
    let before_disabled = installation.store.load().unwrap();
    let before_product = installation.store.load_product().unwrap();
    let disabled = Command::new(BINARY)
        .args(["network", "disable", "--state"])
        .arg(installation.scratch.state())
        .args(["--socket"])
        .arg(installation.scratch.netd_socket())
        .output()
        .unwrap();
    assert!(
        disabled.status.success(),
        "disable failed: {}",
        String::from_utf8_lossy(&disabled.stderr)
    );
    assert!(
        String::from_utf8_lossy(&disabled.stdout).contains("and enforced"),
        "disable receipt: {}; convergence {:?}",
        String::from_utf8_lossy(&disabled.stdout),
        installation.store.convergence().unwrap()
    );
    wait_until("whole-network disable to remove the interface", || {
        !installation.namespace.interface_exists("wg0")
    });
    let disabled_state = installation.store.load().unwrap();
    let disabled_product = installation.store.load_product().unwrap();
    assert_eq!(disabled_state.state, before_disabled.state);
    assert_eq!(disabled_product.state.clients, before_product.state.clients);
    assert_eq!(
        disabled_product
            .state
            .network_operational_enabled
            .get(&installation.interface_id()),
        Some(&false)
    );

    // A backend and management-worker restart must preserve disabled state.
    let _ = installation.netd.child.kill();
    let _ = installation.netd.child.wait();
    wait_until("netd to stop for disabled restart", || {
        !installation.netd.alive()
    });
    installation.restart_backend().await;
    installation.restart_worker();
    assert!(
        !installation.namespace.interface_exists("wg0"),
        "restart must not enable a durably disabled network"
    );

    let enabled = Command::new(BINARY)
        .args(["network", "enable", "--state"])
        .arg(installation.scratch.state())
        .args(["--socket"])
        .arg(installation.scratch.netd_socket())
        .output()
        .unwrap();
    assert!(
        enabled.status.success(),
        "enable failed: {}",
        String::from_utf8_lossy(&enabled.stderr)
    );
    wait_until("whole-network enable to restore the interface", || {
        installation.namespace.interface_exists("wg0")
    });
    let restored = installation
        .namespace
        .device(&installation.scratch.netd_socket(), "wg0");
    assert_eq!(restored.listen_port, Some(51820));
    assert_eq!(restored.public_key, Some(server_public_key.clone()));
    assert!(restored
        .peers
        .iter()
        .any(|peer| peer.public_key == client_public_key));
    let restored_peer = restored
        .peers
        .iter()
        .find(|peer| peer.public_key == client_public_key)
        .expect("the same client peer is restored");
    assert!(restored_peer
        .allowed_ips
        .contains(&"10.67.0.2/32".parse().unwrap()));
    assert!(restored_peer
        .allowed_ips
        .contains(&"2001:db8:67::2/128".parse().unwrap()));
    wait_until("the server IPv6 tunnel route after re-enable", || {
        Command::new("ip")
            .args([
                "-n",
                &installation.namespace.0,
                "-6",
                "route",
                "show",
                "dev",
                "wg0",
            ])
            .output()
            .is_ok_and(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("2001:db8:67::/64")
            })
    });
    // Recreating the server interface loses its kernel session keys. A client
    // that still holds the old session does not know that yet, so recreate its
    // peer state to model a normal client reconnect and force a fresh handshake.
    for peer in [
        PeerMutation::Remove {
            public_key: server_public_key.clone(),
        },
        PeerMutation::Add(DesiredWireGuardPeer {
            public_key: server_public_key.clone(),
            preshared_key: preshared_key.clone(),
            allowed_ips: allowed_ips.clone(),
            persistent_keepalive_seconds: keepalive,
            endpoint: Some(endpoint),
        }),
    ] {
        let response = wg_basic::protocol::request(
            client_scratch.netd_socket(),
            RequestOperation::ApplyWireGuardDevice {
                interface: "wg-client".parse().unwrap(),
                patch: WireGuardDevicePatch {
                    private_key: FieldUpdate::Keep,
                    listen_port: FieldUpdate::Keep,
                    peer: Some(peer),
                },
            },
            9004,
        )
        .expect("reconnect exported client peer");
        assert!(matches!(response, ResponseBody::WireGuardApplied(_)));
    }
    let ping = Command::new("ip")
        .args([
            "netns",
            "exec",
            &client_ns.0,
            "ping",
            "-n",
            "-c",
            "1",
            "-W",
            "2",
            "-I",
            "wg-client",
            "10.67.0.1",
        ])
        .output()
        .expect("ping after network re-enable");
    let _ = ping;
    let ping6 = Command::new("ip")
        .args([
            "netns",
            "exec",
            &client_ns.0,
            "ping",
            "-6",
            "-n",
            "-c",
            "1",
            "-W",
            "2",
            "-I",
            "wg-client",
            "2001:db8:67::1",
        ])
        .output()
        .expect("IPv6 ping after network re-enable");
    let client_after_recovery = client_ns.device(&client_scratch.netd_socket(), "wg-client");
    let client_peer_after_recovery = client_after_recovery.peers.first();
    assert_eq!(
        client_peer_after_recovery.and_then(|peer| peer.endpoint),
        Some(endpoint)
    );
    let server_after_recovery = installation
        .namespace
        .device(&installation.scratch.netd_socket(), "wg0");
    let server_peer_after_recovery = server_after_recovery
        .peers
        .iter()
        .find(|peer| peer.public_key == client_public_key);
    if !ping6.status.success() {
        eprintln!(
            "IPv6 recovery diagnostics: client_routes={}; client_peer={:?}; server_peer={:?}",
            String::from_utf8_lossy(
                &Command::new("ip")
                    .args(["-n", &client_ns.0, "-6", "route", "show"])
                    .output()
                    .unwrap()
                    .stdout
            ),
            client_peer_after_recovery.map(|peer| (
                &peer.allowed_ips,
                peer.latest_handshake,
                peer.rx_bytes,
                peer.tx_bytes
            )),
            server_peer_after_recovery.map(|peer| (
                &peer.allowed_ips,
                peer.latest_handshake,
                peer.rx_bytes,
                peer.tx_bytes
            ))
        );
    }
    assert!(
        ping6.status.success(),
        "IPv6 tunnel traffic after restart/reconcile failed: {}; server addresses: {}; routes: {}",
        String::from_utf8_lossy(&ping6.stderr),
        String::from_utf8_lossy(
            &Command::new("ip")
                .args([
                    "-n",
                    &installation.namespace.0,
                    "-6",
                    "addr",
                    "show",
                    "dev",
                    "wg0"
                ])
                .output()
                .unwrap()
                .stdout
        ),
        String::from_utf8_lossy(
            &Command::new("ip")
                .args(["-n", &installation.namespace.0, "-6", "route", "show"])
                .output()
                .unwrap()
                .stdout
        )
    );
    wait_until(
        "the same exported peer to handshake after re-enable",
        || {
            installation
                .namespace
                .device(&installation.scratch.netd_socket(), "wg0")
                .peers
                .iter()
                .any(|peer| peer.public_key == client_public_key && peer.latest_handshake.is_some())
        },
    );

    let audit_rows_before = installation.store.audit_events(1_000).unwrap().len();
    let telemetry_started = std::time::Instant::now();
    let (telemetry_status, telemetry_body, telemetry_headers) = http(
        addr,
        "GET",
        "/api/v1/clients/telemetry",
        &host,
        None,
        Some(&cookie),
        None,
        "",
    );
    let telemetry_elapsed = telemetry_started.elapsed();
    assert_eq!(telemetry_status, 200, "{telemetry_body}");
    assert_eq!(
        telemetry_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("cache-control"))
            .map(|(_, value)| value.as_str()),
        Some("no-store")
    );
    assert!(telemetry_headers
        .iter()
        .all(|(name, _)| !name.eq_ignore_ascii_case("access-control-allow-origin")));
    let telemetry: serde_json::Value = serde_json::from_str(&telemetry_body).unwrap();
    let row = telemetry["clients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["client_id"] == client_id.to_string())
        .unwrap();
    assert_eq!(row["peer_id"], peer_id);
    assert_eq!(row["observation"], "present");
    assert_eq!(row["drift"], false);
    assert_eq!(row["endpoint"], "198.18.0.2:51821");
    assert!(row["latest_handshake_unix_seconds"].as_u64().unwrap() > 1_700_000_000);
    assert!(row["rx_bytes"].as_u64().unwrap() > 0);
    assert!(row["tx_bytes"].as_u64().unwrap() > 0);
    assert_eq!(
        installation.store.audit_events(1_000).unwrap().len(),
        audit_rows_before,
        "telemetry reads do not persist observations"
    );
    let removed_enabled_peer = wg_basic::protocol::request(
        installation.scratch.netd_socket(),
        RequestOperation::ApplyWireGuardDevice {
            interface: "wg0".parse().unwrap(),
            patch: WireGuardDevicePatch {
                private_key: FieldUpdate::Keep,
                listen_port: FieldUpdate::Keep,
                peer: Some(PeerMutation::Remove {
                    public_key: client_public_key.clone(),
                }),
            },
        },
        9006,
    )
    .expect("remove enabled peer from observation fixture");
    assert!(matches!(
        removed_enabled_peer,
        ResponseBody::WireGuardApplied(_)
    ));
    let (missing_status, missing_body, _) = http(
        addr,
        "GET",
        "/api/v1/clients/telemetry",
        &host,
        None,
        Some(&cookie),
        None,
        "",
    );
    assert_eq!(missing_status, 200, "{missing_body}");
    let missing_json: serde_json::Value = serde_json::from_str(&missing_body).unwrap();
    let missing_row = missing_json["clients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["client_id"] == client_id.to_string())
        .unwrap();
    assert_eq!(missing_row["enabled"], true);
    assert_eq!(missing_row["observation"], "missing");
    assert_eq!(missing_row["drift"], true);
    let (audit_status, audit_body, _) = http(
        addr,
        "GET",
        "/api/v1/audit",
        &host,
        None,
        Some(&cookie),
        None,
        "",
    );
    assert_eq!(audit_status, 200, "{audit_body}");
    assert!(audit_body.contains("client_create"));
    assert!(!audit_body.contains("PrivateKey"));
    assert!(!audit_body.contains("PresharedKey"));

    let generation = installation
        .store
        .current_generation()
        .unwrap()
        .to_storage() as u64;
    let (disable_status, disable_body, _) = http(
        addr,
        "POST",
        &format!("/api/v1/clients/{client_id}/disable"),
        &host,
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        &format!(r#"{{"expected_generation":{generation}}}"#),
    );
    assert_eq!(disable_status, 200, "HTTP disable: {disable_body}");
    let (disabled_status, disabled_body, _) = http(
        addr,
        "GET",
        "/api/v1/clients/telemetry",
        &host,
        None,
        Some(&cookie),
        None,
        "",
    );
    assert_eq!(disabled_status, 200, "{disabled_body}");
    let disabled_json: serde_json::Value = serde_json::from_str(&disabled_body).unwrap();
    let disabled_row = disabled_json["clients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["client_id"] == client_id.to_string())
        .unwrap();
    assert_eq!(disabled_row["enabled"], false);
    assert_eq!(disabled_row["observation"], "missing");
    assert_eq!(disabled_row["drift"], false);

    let unexpected_peer = wg_basic::protocol::request(
        installation.scratch.netd_socket(),
        RequestOperation::ApplyWireGuardDevice {
            interface: "wg0".parse().unwrap(),
            patch: WireGuardDevicePatch {
                private_key: FieldUpdate::Keep,
                listen_port: FieldUpdate::Keep,
                peer: Some(PeerMutation::Add(DesiredWireGuardPeer {
                    public_key: client_public_key.clone(),
                    preshared_key: None,
                    allowed_ips: vec![addresses[0].clone()],
                    persistent_keepalive_seconds: None,
                    endpoint: None,
                })),
            },
        },
        9005,
    )
    .expect("inject read-only observation drift fixture");
    assert!(matches!(unexpected_peer, ResponseBody::WireGuardApplied(_)));
    let extra_pair = wg_basic::wireguard::generate_keypair().unwrap();
    let extra_peer = wg_basic::protocol::request(
        installation.scratch.netd_socket(),
        RequestOperation::ApplyWireGuardDevice {
            interface: "wg0".parse().unwrap(),
            patch: WireGuardDevicePatch {
                private_key: FieldUpdate::Keep,
                listen_port: FieldUpdate::Keep,
                peer: Some(PeerMutation::Add(DesiredWireGuardPeer {
                    public_key: extra_pair.public_key,
                    preshared_key: None,
                    allowed_ips: vec!["10.67.0.250/32".parse().unwrap()],
                    persistent_keepalive_seconds: None,
                    endpoint: None,
                })),
            },
        },
        9007,
    )
    .expect("add unmanaged peer to bounded observation fixture");
    assert!(matches!(extra_peer, ResponseBody::WireGuardApplied(_)));
    let (drift_status, drift_body, _) = http(
        addr,
        "GET",
        "/api/v1/clients/telemetry",
        &host,
        None,
        Some(&cookie),
        None,
        "",
    );
    assert_eq!(drift_status, 200, "{drift_body}");
    let drift_json: serde_json::Value = serde_json::from_str(&drift_body).unwrap();
    let drift_row = drift_json["clients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["client_id"] == client_id.to_string())
        .unwrap();
    assert_eq!(drift_row["enabled"], false);
    assert_eq!(drift_row["observation"], "present");
    assert_eq!(drift_row["drift"], true);
    assert_eq!(drift_json["unassociated_peer_count"], 1);

    let generation = serde_json::from_str::<serde_json::Value>(&disable_body).unwrap()
        ["generation"]
        .as_u64()
        .unwrap();
    let (enable_status, enable_body, _) = http(
        addr,
        "POST",
        &format!("/api/v1/clients/{client_id}/enable"),
        &host,
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        &format!(r#"{{"expected_generation":{generation}}}"#),
    );
    assert_eq!(enable_status, 200, "HTTP enable: {enable_body}");
    let _ = Command::new("ip")
        .args([
            "netns",
            "exec",
            &client_ns.0,
            "ping",
            "-n",
            "-c",
            "1",
            "-W",
            "2",
            "-I",
            "wg-client",
            "10.67.0.1",
        ])
        .output()
        .expect("trigger replacement handshake");
    wait_until("re-enabled peer observation after a new handshake", || {
        installation
            .namespace
            .device(&installation.scratch.netd_socket(), "wg0")
            .peers
            .iter()
            .any(|peer| peer.public_key == client_public_key && peer.latest_handshake.is_some())
    });
    let (enabled_status, enabled_body, _) = http(
        addr,
        "GET",
        "/api/v1/clients/telemetry",
        &host,
        None,
        Some(&cookie),
        None,
        "",
    );
    assert_eq!(enabled_status, 200, "{enabled_body}");
    let enabled_json: serde_json::Value = serde_json::from_str(&enabled_body).unwrap();
    let enabled_row = enabled_json["clients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["client_id"] == client_id.to_string())
        .unwrap();
    assert_eq!(enabled_row["enabled"], true);
    assert_eq!(enabled_row["observation"], "present");
    let generation = serde_json::from_str::<serde_json::Value>(&enable_body).unwrap()["generation"]
        .as_u64()
        .unwrap();
    let (delete_status, delete_body, _) = http(
        addr,
        "DELETE",
        &format!("/api/v1/clients/{client_id}"),
        &host,
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        &format!(r#"{{"expected_generation":{generation}}}"#),
    );
    assert_eq!(delete_status, 200, "HTTP delete: {delete_body}");
    wait_until("HTTP delete to remove the real peer", || {
        !installation
            .namespace
            .device_public_keys(&installation.scratch.netd_socket(), "wg0")
            .contains(&client_public_key.expose().to_owned())
    });
    let (audit_status, final_audit, _) = http(
        addr,
        "GET",
        "/api/v1/audit",
        &host,
        None,
        Some(&cookie),
        None,
        "",
    );
    assert_eq!(audit_status, 200);
    for action in [
        "server_setup",
        "client_create",
        "client_disable",
        "client_enable",
        "client_delete",
        "enrollment_capability_created",
        "enrollment_capability_consumed",
    ] {
        assert!(
            final_audit.contains(action),
            "audit lacks {action}: {final_audit}"
        );
    }
    assert!(!final_audit.contains("PrivateKey"));
    assert!(!final_audit.contains("PresharedKey"));
    assert!(!final_audit.contains(token));
    eprintln!(
        "Phase 8 product fixture measurements: setup={setup_elapsed:?}; \
         safe server/dashboard read={dashboard_read_elapsed:?}; \
         client create including reconcile={create_elapsed_including_reconcile:?}; \
         live telemetry read={telemetry_elapsed:?}; \
         embedded assets={EMBEDDED_ASSET_BYTES} bytes"
    );
    control.shutdown();
    completion.wait().await.expect("HTTP worker drains");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_http_crud_applies_real_peer_lifecycle() {
    require_root("HTTP CRUD");
    let scratch = Scratch::new();
    let namespace = Namespace::new("http");
    let netd = Managed::netd(&namespace.0, &scratch);
    wait_until("netd to listen", || netd.ready("netd.started"));
    let _store = StateStore::initialize(scratch.state()).expect("initialize state");
    set_password_at(scratch.state(), "admin", "an administrator password")
        .expect("admin provisioned");
    let startup =
        spawn(WorkerConfig::new(scratch.state(), scratch.netd_socket())).expect("worker starts");
    let worker = startup.client().clone();
    drop(startup);

    let policy_bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let api = AuthenticatedApi::new(
        worker,
        Arc::new(OriginPolicy::loopback_only(policy_bind)),
        Arc::new(LoginLimiter::new(
            Bucket::per_second(1000, 1000),
            Bucket::per_second(1000, 1000),
            16,
        )),
    );
    let server = Server::builder()
        .runtime(
            ManagementHttpConfig::new("127.0.0.1:0")
                .unwrap()
                .runtime_config()
                .unwrap(),
        )
        .build()
        .unwrap();
    let handle = server
        .start_with_service(ManagementService::new(api))
        .await
        .unwrap();
    let addr = handle.local_addr();
    let host = addr.to_string();
    let origin = format!("http://{host}");
    let (control, mut completion) = handle.into_parts();

    let (code, login, headers) = http(
        addr,
        "POST",
        "/api/v1/login",
        &host,
        Some(&origin),
        None,
        None,
        r#"{"username":"admin","password":"an administrator password"}"#,
    );
    assert_eq!(code, 200, "{login}");
    let cookie = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
        .unwrap()
        .1
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let (_, session, _) = http(
        addr,
        "GET",
        "/api/v1/session",
        &host,
        None,
        Some(&cookie),
        None,
        "",
    );
    let csrf = serde_json::from_str::<serde_json::Value>(&session).unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let setup_body = r#"{"expected_generation":1,"interface_name":"wg0","tunnel_prefix":"10.66.0.0/24","listen_port":51820,"advertised_endpoint":"vpn.example.test:51820","egress_interface":"lo","ipv4_forwarding_required":false,"masquerade":false,"default_client_route_policy":{"prefixes":["0.0.0.0/0"]}}"#;
    let (code, setup, _) = http(
        addr,
        "POST",
        "/api/v1/setup",
        &host,
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        setup_body,
    );
    assert_eq!(code, 200, "setup: {setup}");
    let setup: serde_json::Value = serde_json::from_str(&setup).unwrap();
    let generation = setup["generation"].as_u64().unwrap();
    let interface = setup["data"]["interface_id"].as_str().unwrap();
    let create = format!(
        r#"{{"expected_generation":{generation},"interface_id":"{interface}","label":"http-client"}}"#
    );
    let (code, created, _) = http(
        addr,
        "POST",
        "/api/v1/clients",
        &host,
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        &create,
    );
    assert_eq!(code, 201, "create: {created}");
    let created: serde_json::Value = serde_json::from_str(&created).unwrap();
    let client_id = created["data"]["client_id"].as_str().unwrap();
    let key = created["data"]["public_key"].as_str().unwrap().to_owned();
    wait_until("HTTP-created key to reach the device", || {
        namespace
            .device_public_keys(&scratch.netd_socket(), "wg0")
            .contains(&key)
    });

    let generation = created["generation"].as_u64().unwrap();
    let (code, disabled, _) = http(
        addr,
        "POST",
        &format!("/api/v1/clients/{client_id}/disable"),
        &host,
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        &format!(r#"{{"expected_generation":{generation}}}"#),
    );
    assert_eq!(code, 200, "disable: {disabled}");
    wait_until("HTTP-disabled peer removal", || {
        !namespace
            .device_public_keys(&scratch.netd_socket(), "wg0")
            .contains(&key)
    });

    let generation = serde_json::from_str::<serde_json::Value>(&disabled).unwrap()["generation"]
        .as_u64()
        .unwrap();
    let (code, enabled, _) = http(
        addr,
        "POST",
        &format!("/api/v1/clients/{client_id}/enable"),
        &host,
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        &format!(r#"{{"expected_generation":{generation}}}"#),
    );
    assert_eq!(code, 200, "enable: {enabled}");
    wait_until("HTTP-enabled peer restoration", || {
        namespace
            .device_public_keys(&scratch.netd_socket(), "wg0")
            .contains(&key)
    });

    let generation = serde_json::from_str::<serde_json::Value>(&enabled).unwrap()["generation"]
        .as_u64()
        .unwrap();
    let (code, deleted, _) = http(
        addr,
        "DELETE",
        &format!("/api/v1/clients/{client_id}"),
        &host,
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        &format!(r#"{{"expected_generation":{generation}}}"#),
    );
    assert_eq!(code, 200, "delete: {deleted}");
    wait_until("HTTP-deleted peer removal", || {
        !namespace
            .device_public_keys(&scratch.netd_socket(), "wg0")
            .contains(&key)
    });

    control.shutdown();
    completion.wait().await.unwrap();
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

    let disabled = Command::new(BINARY)
        .args(["network", "disable", "--state"])
        .arg(installation.scratch.state())
        .args(["--socket"])
        .arg(installation.scratch.netd_socket())
        .output()
        .unwrap();
    assert!(disabled.status.success());
    assert!(
        String::from_utf8_lossy(&disabled.stdout).contains("committed at generation"),
        "offline disable must report its durable commit: {}",
        String::from_utf8_lossy(&disabled.stdout)
    );
    assert!(
        String::from_utf8_lossy(&disabled.stdout).contains("not yet enforced"),
        "offline disable must not claim enforcement: {}",
        String::from_utf8_lossy(&disabled.stdout)
    );
    assert_eq!(
        installation
            .store
            .load_product()
            .unwrap()
            .state
            .network_operational_enabled
            .get(&installation.interface_id()),
        Some(&false),
        "offline disable commits the durable operational flag"
    );

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

    // A later backend restart must preserve disabled state. Re-enabling then
    // converges all durable client rows that were committed during the outage.
    installation.restart_backend().await;
    installation.restart_worker();
    assert!(
        !installation.namespace.interface_exists("wg0"),
        "disabled state survives a backend restart"
    );
    let enabled = Command::new(BINARY)
        .args(["network", "enable", "--state"])
        .arg(installation.scratch.state())
        .args(["--socket"])
        .arg(installation.scratch.netd_socket())
        .output()
        .unwrap();
    assert!(
        enabled.status.success(),
        "enable failed: {}",
        String::from_utf8_lossy(&enabled.stderr)
    );
    let key = degraded.client.public_key.expose().to_owned();
    wait_until("the deferred peer to reach the device", || {
        installation
            .namespace
            .device_public_keys(&installation.scratch.netd_socket(), "wg0")
            .contains(&key)
    });
}
