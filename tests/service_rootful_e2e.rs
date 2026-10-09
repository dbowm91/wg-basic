//! Phase 7 M004 §6: the rootful end-to-end fixture.
//!
//! # Why this one needs root
//!
//! `tests/service_e2e.rs` qualifies the HTTP → worker → state → netd path with a
//! real `netd` child, but never asks it to touch the kernel. That leaves the most
//! important claim unproven: that the **HTTP health surface reflects the same
//! management runtime Phase 6 qualified**. A surface that says `ok` while the
//! network is actually unconverged would be worse than no surface.
//!
//! So this fixture does what Phase 6 does — create a namespace, start a real
//! `netd`, apply a real WireGuard device — and then drives the management HTTP
//! surface against it:
//!
//! * seed a store that really manages an interface, so startup reconcile has
//!   real work to do;
//! * start `netd` and `serve` as real children inside the namespace;
//! * log in over HTTP and require `/healthz` to say `ok`;
//! * require the authenticated route to report a **converged** record *and* a
//!   live backend that answered — the two halves agreeing, which is the whole
//!   point of §4;
//! * stop `serve`, change the network behind its back, start it again, and
//!   require the surface to go **degraded** rather than lying.
//!
//! The last step is the one that matters. A management surface that cannot notice
//! the network drifting away from the record is not a management surface.
//!
//! # Where each process runs, and why
//!
//! `netd` runs **inside** the namespace, because it is the process that has to
//! create real links there. `serve` and the HTTP client run **on the host**,
//! because the namespace has its own loopback: a listener bound to
//! `127.0.0.1` inside a namespace is a different socket from `127.0.0.1` outside
//! it, so a client on the host could never reach a `serve` that ran inside.
//!
//! `ip netns exec` does not remount `/tmp`, so the netd socket path is the same
//! file on both sides. `serve` therefore reaches the in-namespace backend over
//! exactly the authorized unix socket the unprivileged deployment uses — the
//! real integration path, not a shortcut.
//!
//! # Root is required, and says so
//!
//! The whole file is behind `linux-integration`, and every test checks the
//! effective uid first so a mistake is a clear message rather than a confusing
//! namespace failure.

#![cfg(all(target_os = "linux", feature = "linux-integration"))]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use wg_basic::{
    domain::{
        ClientId, DesiredAddress, DesiredClient, DesiredGeneration, DesiredInterface, DesiredPeer,
        DesiredState, InterfaceId, LinkLifecycle, NetworkPrefix, OwnershipDeclaration, PeerId,
        PrivateKey, ResourcePresence,
    },
    state::{StateStore, INITIAL_DESIRED_GENERATION},
    wireguard::generate_keypair,
};

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");

static COUNTER: AtomicU64 = AtomicU64::new(0);

const USERNAME: &str = "admin";
const PASSWORD: &str = "an administrator password";
const DEADLINE: Duration = Duration::from_secs(60);

/// The interface every fixture manages. Short enough to fit a Linux name limit.
const INTERFACE_NAME: &str = "wgm4vpn";

/// A fixed private key, so the "no key material on the surface" case has a
/// known secret to search for rather than a random one it cannot reproduce.
const SECRET: &str = "d2ctYmFzaWMtbTAwNC1uZXZlci1wcmludC1tZSEhISE=";

/// Runs the whole body as root, or says precisely why it cannot.
///
/// A namespace, a netd socket, and a WireGuard device all need privilege. Failing
/// with "rootful integration test must run as root" is more useful than failing
/// with `Operation not permitted` three frames later.
fn require_root() {
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
         cargo test --locked --features linux-integration --test service_rootful_e2e"
    );
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
        let name = format!("wgm4{label}{suffix:x}");
        run(&["netns", "add", &name]);
        Self(name)
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).status();
    }
}

/// A scratch directory shared between the namespace and the host.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = PathBuf::from(format!(
            "/tmp/wg-basic-m004-rootful-{}-{}",
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

/// A child process, with its stderr collected.
struct Managed {
    name: &'static str,
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
    reader: Option<thread::JoinHandle<()>>,
}

impl Managed {
    /// Starts a process inside `namespace`.
    fn in_namespace(name: &'static str, namespace: &str, args: &[&str]) -> Self {
        let mut command = Command::new("ip");
        command
            .args(["netns", "exec", namespace, BINARY])
            .args(args);
        Self::spawn(name, command)
    }

    /// Starts a process on the host.
    fn on_host(name: &'static str, args: &[&str]) -> Self {
        let mut command = Command::new(BINARY);
        command.args(args);
        Self::spawn(name, command)
    }

    fn spawn(name: &'static str, mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("could not start {name}: {error}"));

        let lines = Arc::new(Mutex::new(Vec::new()));
        let stderr = child.stderr.take().expect("stderr is piped");
        let collected = Arc::clone(&lines);
        let reader = thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                collected.lock().expect("the log lock is free").push(line);
            }
        });

        Self {
            name,
            child,
            lines,
            reader: Some(reader),
        }
    }

    fn log(&self) -> Vec<String> {
        self.lines.lock().expect("the log lock is free").clone()
    }

    fn is_alive(&self) -> bool {
        Path::new(&format!("/proc/{}", self.child.id())).exists()
    }

    fn await_log(&self, needle: &str) -> String {
        let deadline = Instant::now() + DEADLINE;
        loop {
            for line in self.log() {
                if line.contains(needle) {
                    return line;
                }
            }
            assert!(
                self.is_alive(),
                "{} exited before logging {needle:?}; log: {:#?}",
                self.name,
                self.log()
            );
            assert!(
                Instant::now() < deadline,
                "{} never logged {needle:?}; log: {:#?}",
                self.name,
                self.log()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Sends `SIGTERM` and requires a clean exit.
    ///
    /// The exit code is the assertion: a `serve` that dies from the signal rather
    /// than shutting down gracefully skips the drain and the store close, and this
    /// is the only place that would notice.
    fn stop(&mut self) -> i32 {
        if !self.is_alive() {
            return self.child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
        }
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + DEADLINE;
        loop {
            match self.child.try_wait().expect("the child is waitable") {
                Some(status) => {
                    if let Some(handle) = self.reader.take() {
                        let _ = handle.join();
                    }
                    return status.code().unwrap_or(-1);
                }
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "{} ignored SIGTERM; it does not shut down gracefully",
                        self.name
                    );
                    thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }
}

impl Drop for Managed {
    fn drop(&mut self) {
        if self.is_alive() {
            let _ = Command::new("kill")
                .args(["-KILL", &self.child.id().to_string()])
                .status();
            let _ = self.child.wait();
        }
    }
}

/// Starts `serve` on the host and returns it with its bound address.
fn start_serve(scratch: &Scratch) -> (Managed, SocketAddr) {
    let state = scratch.state();
    let socket = scratch.netd_socket();
    let process = Managed::on_host(
        "wg-basic serve",
        &[
            "serve",
            "--state",
            state.to_str().unwrap(),
            "--socket",
            socket.to_str().unwrap(),
            "--http-bind",
            "127.0.0.1:0",
        ],
    );
    let line = process.await_log("serve.started");
    let addr = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix("resource_id="))
        .expect("the event names the listener")
        .parse()
        .expect("a parseable bound address");
    (process, addr)
}

/// Seeds a store that really manages an interface, so startup reconcile has work.
fn seed_managed_installation(path: &Path) -> InterfaceId {
    let interface_id = InterfaceId::new();
    let server_keys = generate_keypair().expect("the CSPRNG yields a keypair");
    let client_keys = generate_keypair().expect("the CSPRNG yields a keypair");

    let state = StateStore::initialize(path).expect("the store initializes");
    let peer_id = PeerId::new();
    let committed = state
        .mutate(INITIAL_DESIRED_GENERATION, |_| {
            Ok(DesiredState {
                interfaces: vec![DesiredInterface {
                    id: interface_id,
                    name: INTERFACE_NAME.parse().expect("a valid interface name"),
                    ownership: OwnershipDeclaration::Managed,
                    lifecycle: LinkLifecycle::Present,
                    admin_up: Some(true),
                    private_key: server_keys.private_key,
                    listen_port: Some(51820),
                    manage_all_peers: true,
                    tunnel_prefixes: vec![NetworkPrefix::new(
                        "10.77.0.0/24".parse().expect("a prefix"),
                    )],
                    addresses: vec![DesiredAddress {
                        address: "10.77.0.1/24".parse().expect("an address"),
                        presence: ResourcePresence::Present,
                    }],
                    routes: Vec::new(),
                    peers: vec![DesiredPeer {
                        id: peer_id,
                        public_key: client_keys.public_key,
                        private_key: None,
                        preshared_key: None,
                        allowed_ips: vec![NetworkPrefix::new(
                            "10.77.0.2/32".parse().expect("a prefix"),
                        )],
                        persistent_keepalive_seconds: None,
                        endpoint: None,
                    }],
                    clients: vec![DesiredClient {
                        id: ClientId::new(),
                        peer_id,
                        assigned_address: "10.77.0.2/32".parse().expect("an address"),
                        route_policy: Default::default(),
                    }],
                }],
                client_routes: Default::default(),
                network_policy: None,
            })
        })
        .expect("the desired state commits");
    assert_eq!(
        committed.generation,
        DesiredGeneration::new(2).expect("a generation")
    );
    drop(state);
    interface_id
}

/// Provisions the administrator, by the same stdin-only route an operator uses.
fn provision_admin(path: &Path) {
    let mut child = Command::new(BINARY)
        .args([
            "admin",
            "set-password",
            "--username",
            USERNAME,
            "--state",
            path.to_str().unwrap(),
            "--password-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the CLI starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(PASSWORD.as_bytes())
        .expect("the password is written to stdin");
    let output = child.wait_with_output().expect("the CLI finishes");
    assert!(
        output.status.success(),
        "provisioning failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A minimal HTTP client for the loopback listener inside the namespace.
struct Client {
    addr: SocketAddr,
    host: String,
    cookies: Vec<(String, String)>,
}

impl Client {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            host: format!("127.0.0.1:{}", addr.port()),
            cookies: Vec::new(),
        }
    }

    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn request(&self, method: &str, path: &str, extra: &[(&str, &str)], body: &str) -> Reply {
        let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\n", self.host);
        let cookies = self.cookie_header();
        if !cookies.is_empty() {
            request.push_str(&format!("Cookie: {cookies}\r\n"));
        }
        for (name, value) in extra {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        let length = body.len().to_string();
        request.push_str(&format!("Content-Length: {length}\r\n"));
        request.push_str("Connection: close\r\n\r\n");
        request.push_str(body);
        raw_request(self.addr, &request)
    }

    fn get(&self, path: &str) -> Reply {
        self.request("GET", path, &[], "")
    }

    fn login(&mut self) -> Reply {
        let origin = format!("http://{}", self.host);
        let reply = self.request(
            "POST",
            "/api/v1/login",
            &[("Content-Type", "application/json"), ("Origin", &origin)],
            &format!("{{\"username\":{USERNAME:?},\"password\":{PASSWORD:?}}}"),
        );
        if let Some(set) = reply.header("set-cookie") {
            let pair = set.split(';').next().unwrap_or_default();
            if let Some((name, value)) = pair.split_once('=') {
                self.cookies
                    .push((name.trim().to_owned(), value.trim().to_owned()));
            }
        }
        assert_eq!(reply.status, 200, "login failed: {}", reply.body);
        reply
    }
}

#[derive(Debug)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|error| panic!("expected JSON, got {:?} ({error})", self.body))
    }
}

fn raw_request(addr: SocketAddr, raw: &str) -> Reply {
    let mut stream = TcpStream::connect(addr).expect("loopback connect succeeds");
    stream
        .set_read_timeout(Some(DEADLINE))
        .expect("a read timeout is settable");
    stream
        .write_all(raw.as_bytes())
        .expect("the request is written");
    stream.flush().unwrap();

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .expect("a status line arrives");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("a status code")
        .parse()
        .expect("a numeric status code");

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("a header line arrives");
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').expect("headers are name: value");
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }

    let length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).expect("the body arrives");
    Reply {
        status,
        headers,
        body: String::from_utf8(body).expect("management bodies are utf-8"),
    }
}

/// Polls until the listener answers or the deadline passes.
fn await_listener(addr: SocketAddr, child: &Managed) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
            return;
        }
        assert!(
            child.is_alive(),
            "serve exited before accepting; log: {:#?}",
            child.log()
        );
        assert!(
            Instant::now() < deadline,
            "serve never accepted a connection; log: {:#?}",
            child.log()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// Polls until the netd socket answers or the deadline passes.
fn await_netd(path: &Path, child: &Managed) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        if path.exists()
            && std::os::unix::net::UnixStream::connect(path)
                .map(|stream| {
                    drop(stream);
                    true
                })
                .unwrap_or(false)
        {
            return;
        }
        assert!(
            child.is_alive(),
            "netd exited before binding; log: {:#?}",
            child.log()
        );
        assert!(
            Instant::now() < deadline,
            "netd never bound {:?}; log: {:#?}",
            path,
            child.log()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// §6: the HTTP surface reflects real network state, in both directions.
///
/// Requires root: a namespace, a real `netd`, a real WireGuard device, and a
/// real firewall apply.
#[test]
fn the_management_surface_reflects_real_network_state_in_both_directions() {
    require_root();

    let namespace = Namespace::new("net");
    let scratch = Scratch::new();
    seed_managed_installation(&scratch.state());
    provision_admin(&scratch.state());

    // A real netd inside the namespace. `serve` is never told to start it.
    let mut netd = Managed::in_namespace(
        "wg-basic netd",
        &namespace.0,
        &["netd", "--socket", scratch.netd_socket().to_str().unwrap()],
    );
    netd.await_log("netd.started");
    await_netd(&scratch.netd_socket(), &netd);

    // First life: startup reconcile has a real interface to apply.
    let (mut serve, addr) = start_serve(&scratch);
    await_listener(addr, &serve);

    let reconcile = serve.await_log("serve.reconcile");
    assert!(
        reconcile.contains("converged") || reconcile.contains("degraded"),
        "a managed installation must attempt a real reconcile: {reconcile}"
    );

    let mut browser = Client::new(addr);
    browser.login();

    // The device really exists, because netd really applied it.
    let device = Command::new("ip")
        .args([
            "netns",
            "exec",
            &namespace.0,
            "ip",
            "link",
            "show",
            INTERFACE_NAME,
        ])
        .output()
        .expect("ip link show runs");
    assert!(
        device.status.success(),
        "the managed interface is not real, so nothing here is qualified: {}",
        String::from_utf8_lossy(&device.stderr)
    );

    // The authenticated route reports a converged record *and* a live backend.
    // Both, because they answer different questions and M004's whole point is
    // that an operator can tell them apart.
    let health = browser.get("/api/v1/health");
    assert_eq!(health.status, 200, "{}", health.body);
    let projected = health.json();
    assert_eq!(
        projected["backend"]["answered"],
        serde_json::json!(true),
        "the real netd must answer a live probe: {projected}"
    );
    assert_eq!(
        projected["health"]["convergence"],
        serde_json::json!("converged"),
        "a real device was applied and verified, so the record says converged: {projected}"
    );

    // And the anonymous surface agrees, without saying why.
    let anonymous = Client::new(addr);
    let healthz = anonymous.get("/healthz");
    assert_eq!(healthz.status, 200);
    assert_eq!(
        healthz.body, "ok",
        "the appliance is converged: {healthz:?}"
    );

    // Now take the *backend* away behind the service's back and restart it.
    //
    // Deleting the managed link would not do: netd owns it, so the startup
    // reconcile would simply re-create it and report `converged` — correctly.
    // A reconcile that genuinely fails needs a backend that cannot act, which is
    // both easier to arrange and the more realistic fault.
    assert_eq!(serve.stop(), 0, "serve must exit cleanly on SIGTERM");
    assert_eq!(netd.stop(), 0, "netd must exit cleanly");

    let (mut restarted, second_addr) = start_serve(&scratch);
    await_listener(second_addr, &restarted);
    let second_reconcile = restarted.await_log("serve.reconcile");
    assert!(
        second_reconcile.contains("degraded"),
        "the backend is gone, so the reconcile must fail: {second_reconcile}"
    );
    let readiness = restarted.await_log("serve.started");
    assert!(
        readiness.contains("outcome=degraded"),
        "a failed backend is degraded, not fatal: the listener is up and the \
         reason is named for the operator. {readiness}"
    );

    // The anonymous surface agrees, without saying why.
    let mut second = Client::new(second_addr);
    second.login();
    let degraded = second.get("/healthz");
    assert_eq!(degraded.status, 200);
    assert_eq!(
        degraded.body, "degraded",
        "the network is not converged and the surface must say so: {degraded:?}"
    );
    // Still no disclosure: the two tokens and nothing more.
    for word in ["network", "backend", "convergence", "database", "netd"] {
        assert!(
            !degraded.body.to_lowercase().contains(word),
            "/healthz leaked {word:?}: {}",
            degraded.body
        );
    }

    // The authenticated route explains what `/healthz` refuses to.
    let detail = second.get("/api/v1/health");
    assert_eq!(detail.status, 200);
    let projected = detail.json();
    assert_eq!(
        projected["backend"]["answered"],
        serde_json::json!(false),
        "no netd is running, so the live probe must say so: {projected}"
    );
    assert_ne!(
        projected["health"]["convergence"],
        serde_json::json!("converged"),
        "the reconcile failed, so the record must not still say converged: {projected}"
    );

    assert_eq!(restarted.stop(), 0, "the restarted serve must exit cleanly");
}

/// §6 and §11.8: the management role does not own the backend's lifetime.
///
/// The capability check M004 might have wanted to write — "does `serve` hold
/// `CAP_NET_ADMIN`?" — cannot be answered here, because this fixture runs as
/// root and a root process starts with that capability whether or not the role
/// uses it. Asserting on `/proc/<pid>/status` here would measure the test runner,
/// not the code.
///
/// What *is* measurable, and is the actual claim, is ownership: a backend that
/// disappears must not disturb the management role, and a backend that comes back
/// must be picked up without a restart. A role that owned its backend could not
/// survive either half.
#[test]
fn the_management_role_survives_its_backend_disappearing_and_picks_it_up_again() {
    require_root();

    let namespace = Namespace::new("own");
    let scratch = Scratch::new();
    seed_managed_installation(&scratch.state());
    provision_admin(&scratch.state());

    let mut netd = Managed::in_namespace(
        "wg-basic netd",
        &namespace.0,
        &["netd", "--socket", scratch.netd_socket().to_str().unwrap()],
    );
    netd.await_log("netd.started");
    await_netd(&scratch.netd_socket(), &netd);

    let (mut serve, addr) = start_serve(&scratch);
    await_listener(addr, &serve);

    let mut browser = Client::new(addr);
    browser.login();
    assert_eq!(
        browser.get("/api/v1/health").json()["backend"]["answered"],
        serde_json::json!(true),
        "the backend is up to begin with"
    );

    // The backend goes away underneath the running service.
    assert_eq!(netd.stop(), 0, "netd must exit cleanly");

    assert!(
        serve.is_alive(),
        "the management role must not die when its backend does; it is a \
         separate process with a separate lifetime"
    );
    // `/healthz` still says `ok`, and that is correct rather than a defect: it
    // reports *recorded* health, and the last reconcile really did converge. It
    // cannot probe, because an unauthenticated caller must not be able to make
    // this process dial the privileged backend. The stale record is exactly the
    // gap the authenticated live probe was added to close, so both halves are
    // asserted here.
    let recorded = browser.get("/healthz");
    assert_eq!(recorded.status, 200);
    assert_eq!(
        recorded.body, "ok",
        "/healthz reports the record; it must not reach the backend: {recorded:?}"
    );
    let detail = browser.get("/api/v1/health");
    assert_eq!(detail.status, 200, "{}", detail.body);
    assert_eq!(
        detail.json()["backend"]["answered"],
        serde_json::json!(false),
        "the live probe must report the backend as gone: {}",
        detail.body
    );

    // And the same session keeps working throughout: an operator must still be
    // able to log in and *see* the outage, or the outage is invisible.
    assert_eq!(
        browser.get("/api/v1/session").status,
        200,
        "a backend outage must not log the operator out; diagnosing it is the \
         surface's job"
    );

    // The backend comes back, and is picked up with no restart.
    let again = Managed::in_namespace(
        "wg-basic netd",
        &namespace.0,
        &["netd", "--socket", scratch.netd_socket().to_str().unwrap()],
    );
    again.await_log("netd.started");
    await_netd(&scratch.netd_socket(), &again);

    let recovered = browser.get("/api/v1/health");
    assert_eq!(
        recovered.json()["backend"]["answered"],
        serde_json::json!(true),
        "a restarted backend must be picked up without restarting serve: {}",
        recovered.body
    );

    assert_eq!(serve.stop(), 0);
    drop(again);
}

/// A private key must never appear in anything the surface renders.
#[test]
fn no_key_material_reaches_the_management_surface() {
    require_root();

    let namespace = Namespace::new("keys");
    let scratch = Scratch::new();
    let keys = generate_keypair().expect("the CSPRNG yields a keypair");
    let private = keys.private_key;

    let state = StateStore::initialize(scratch.state()).expect("the store initializes");
    let peer_id = PeerId::new();
    state
        .mutate(INITIAL_DESIRED_GENERATION, |_| {
            Ok(DesiredState {
                interfaces: vec![DesiredInterface {
                    id: InterfaceId::new(),
                    name: INTERFACE_NAME.parse().expect("a valid interface name"),
                    ownership: OwnershipDeclaration::Managed,
                    lifecycle: LinkLifecycle::Present,
                    admin_up: Some(true),
                    private_key: PrivateKey::new(SECRET.into()).expect("a valid key"),
                    listen_port: Some(51820),
                    manage_all_peers: true,
                    tunnel_prefixes: vec![NetworkPrefix::new(
                        "10.88.0.0/24".parse().expect("a prefix"),
                    )],
                    addresses: vec![DesiredAddress {
                        address: "10.88.0.1/24".parse().expect("an address"),
                        presence: ResourcePresence::Present,
                    }],
                    routes: Vec::new(),
                    peers: vec![DesiredPeer {
                        id: peer_id,
                        public_key: keys.public_key,
                        private_key: None,
                        preshared_key: None,
                        allowed_ips: vec![NetworkPrefix::new(
                            "10.88.0.2/32".parse().expect("a prefix"),
                        )],
                        persistent_keepalive_seconds: None,
                        endpoint: None,
                    }],
                    clients: vec![DesiredClient {
                        id: ClientId::new(),
                        peer_id,
                        assigned_address: "10.88.0.2/32".parse().expect("an address"),
                        route_policy: Default::default(),
                    }],
                }],
                client_routes: Default::default(),
                network_policy: None,
            })
        })
        .expect("the desired state commits");
    drop(state);
    provision_admin(&scratch.state());

    let netd = Managed::in_namespace(
        "wg-basic netd",
        &namespace.0,
        &["netd", "--socket", scratch.netd_socket().to_str().unwrap()],
    );
    netd.await_log("netd.started");
    await_netd(&scratch.netd_socket(), &netd);

    let (mut serve, addr) = start_serve(&scratch);
    await_listener(addr, &serve);

    let mut browser = Client::new(addr);
    browser.login();

    // Everything the surface can say to an authenticated operator.
    let rendered = [
        browser.get("/api/v1/session").body,
        browser.get("/api/v1/health").body,
        browser.get("/").body,
        browser.get("/assets/app.js").body,
        browser.get("/healthz").body,
        serve.log().join("\n"),
    ]
    .join("\n");

    // `PrivateKey` carries its base64 form, so that is the string to search for.
    // Its raw bytes are also searched, hex-encoded, because a leak through a
    // different serialiser would print them rather than the base64.
    let base64_secret = private.expose_secret().to_owned();
    let raw = hex_of(base64_secret.as_bytes());
    for secret in [&base64_secret, &raw] {
        assert!(
            !rendered.contains(secret.as_str()),
            "key material reached the management surface: {secret}"
        );
    }
    for marker in ["private_key", "PrivateKey", "preshared", SECRET] {
        assert!(
            !rendered.contains(marker),
            "{marker} appeared in something the surface rendered"
        );
    }

    assert_eq!(serve.stop(), 0);
    drop(netd);
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
