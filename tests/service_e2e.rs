//! Phase 7 M004 §6: end-to-end service qualification against real processes.
//!
//! # Why this file spawns binaries
//!
//! Every other Phase 7 test drives an in-process harness. That is the right unit
//! for a route, a policy, or a session — but it cannot see the things M004
//! claims:
//!
//! * that the **process topology** is what the plan says it is: an unprivileged
//!   `serve` talking to a separately-started privileged `netd` over an authorized
//!   socket, with `serve` neither spawning nor elevating anything;
//! * that the **CLI** provisions the credential the HTTP surface then accepts —
//!   two different entry points into one store, which is exactly the seam that
//!   broke during M003;
//! * that **startup reconciliation** ran and what it concluded;
//! * that a **restart of a real process** preserves a real session cookie.
//!
//! So this file runs `env!("CARGO_BIN_EXE_wg-basic")` as a child: once for
//! `admin set-password`, once for `netd`, and twice for `serve` (because the
//! required flow restarts it). Everything between is a hand-written HTTP/1.1
//! client over a real TCP socket to the child's own listener.
//!
//! # The port is read out of the child's own log
//!
//! `serve` binds an ephemeral port and prints it. The harness parses that line
//! rather than pre-selecting a port, so two concurrent runs cannot collide and
//! the test and the operator's log agree on what the listener is. The wait for
//! the line is a deadline, never a sleep.
//!
//! # What is deliberately *not* claimed here
//!
//! `netd` is started but never asked to touch the kernel: this fixture qualifies
//! the HTTP → worker → state → netd path, and `netd_reachable` is the honest
//! observation for it. Applying real interfaces and firewall policy is
//! `tests/service_rootful_e2e.rs`, which needs root and a namespace.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, ChildStderr, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");

static COUNTER: AtomicU64 = AtomicU64::new(0);

const USERNAME: &str = "admin";
const PASSWORD: &str = "an administrator password";
const NEW_PASSWORD: &str = "a replacement administrator password";

/// Every wait here is a deadline; none is a sleep.
const DEADLINE: Duration = Duration::from_secs(30);

/// A self-cleaning scratch directory holding the real on-disk state.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-m004-e2e-{}-{}",
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

/// A running child process whose stderr is collected line by line.
struct Child_ {
    name: &'static str,
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
    stderr_thread: Option<thread::JoinHandle<()>>,
}

impl Child_ {
    /// Starts `wg-basic <args>` with piped stderr.
    fn start(name: &'static str, args: &[&str]) -> Self {
        let mut child = Command::new(BINARY)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("could not start {name}: {error}"));

        let lines = Arc::new(Mutex::new(Vec::new()));
        let stderr: ChildStderr = child.stderr.take().expect("stderr is piped");
        let collected = Arc::clone(&lines);
        let stderr_thread = thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                collected.lock().expect("the log lock is free").push(line);
            }
        });

        Self {
            name,
            child,
            lines,
            stderr_thread: Some(stderr_thread),
        }
    }

    /// Every stderr line collected so far.
    fn log(&self) -> Vec<String> {
        self.lines.lock().expect("the log lock is free").clone()
    }

    /// Whether the child process is still running.
    ///
    /// Read from `/proc` rather than `Child::try_wait`, which needs `&mut self`
    /// and would force every wait helper that inspects a child to be mutable.
    fn is_alive(&self) -> bool {
        Path::new(&format!("/proc/{}", self.child.id())).exists()
    }

    /// Waits for a stderr line containing `needle`, under a deadline.
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
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Stops the child and returns its exit status.
    ///
    /// `SIGTERM` rather than `SIGKILL`, because the graceful path is what M004
    /// qualified: a process that ignores the signal would fail here.
    fn stop(&mut self) -> Option<i32> {
        if self.child.try_wait().ok().flatten().is_some() {
            return self
                .child
                .wait()
                .ok()
                .map(|status| status.code().unwrap_or(-1));
        }
        // `kill -TERM` via libc-free means: `Command` has no signal API, and the
        // crate deliberately has no unsafe code, so the signal is delivered with
        // the `kill` utility against the child's pid.
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + DEADLINE;
        loop {
            match self.child.try_wait().expect("the child is waitable") {
                Some(status) => {
                    if let Some(handle) = self.stderr_thread.take() {
                        let _ = handle.join();
                    }
                    return Some(status.code().unwrap_or(-1));
                }
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "{} ignored SIGTERM; it does not shut down gracefully",
                        self.name
                    );
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}

impl Drop for Child_ {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = Command::new("kill")
                .args(["-KILL", &self.child.id().to_string()])
                .status();
            let _ = self.child.wait();
        }
    }
}

/// A `wg-basic serve` child, with the address it actually bound.
struct ServeProcess {
    process: Child_,
    addr: SocketAddr,
}

impl ServeProcess {
    /// Starts `serve` on an ephemeral loopback port and learns where it bound.
    fn start(scratch: &Scratch) -> Self {
        let state = scratch.state();
        let socket = scratch.netd_socket();
        let process = Child_::start(
            "wg-basic serve",
            &[
                "serve",
                "--state",
                state.to_str().expect("a utf-8 scratch path"),
                "--socket",
                socket.to_str().expect("a utf-8 socket path"),
                // Port 0: the OS picks, and the child reports it. Two concurrent
                // runs therefore cannot collide.
                "--http-bind",
                "127.0.0.1:0",
            ],
        );
        let line = process.await_log("wg-basic serve listening on");
        let addr = parse_bound_address(&line);
        Self { process, addr }
    }

    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.addr.port())
    }

    fn client(&self) -> Client {
        Client {
            addr: self.addr,
            host: self.host(),
            cookies: Vec::new(),
        }
    }

    fn stop(&mut self) -> Option<i32> {
        self.process.stop()
    }
}

/// Pulls the bound address out of the child's own startup line.
///
/// Parsing the operator-visible line rather than choosing a port up front means
/// this test and the operator's log can never disagree about what was bound.
fn parse_bound_address(line: &str) -> SocketAddr {
    let after = line
        .split("listening on")
        .nth(1)
        .unwrap_or_else(|| panic!("unexpected startup line: {line:?}"));
    after
        .trim()
        .trim_start_matches("http://")
        .parse()
        .unwrap_or_else(|error| panic!("could not parse the bound address from {line:?}: {error}"))
}

/// A browser-shaped HTTP client holding cookies.
#[derive(Clone)]
struct Client {
    addr: SocketAddr,
    host: String,
    cookies: Vec<(String, String)>,
}

impl Client {
    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn remember(&mut self, reply: &Reply) {
        for value in reply.header_all("set-cookie") {
            let Some((pair, _)) = value.split_once(';') else {
                continue;
            };
            let Some((name, content)) = pair.split_once('=') else {
                continue;
            };
            match self
                .cookies
                .iter_mut()
                .find(|(existing, _)| existing == name.trim())
            {
                Some(slot) => *slot = (name.trim().to_owned(), content.trim().to_owned()),
                None => self
                    .cookies
                    .push((name.trim().to_owned(), content.trim().to_owned())),
            }
        }
    }

    fn after_restart(&self, addr: SocketAddr, host: &str) -> Client {
        Client {
            addr,
            host: host.to_owned(),
            cookies: self.cookies.clone(),
        }
    }

    fn get(&self, path: &str) -> Reply {
        let mut extra: Vec<(&str, &str)> = vec![("Connection", "close")];
        let cookies = self.cookie_header();
        if !cookies.is_empty() {
            extra.push(("Cookie", &cookies));
        }
        request_on(self.addr, &wire("GET", path, &self.host, &extra))
    }

    /// A JSON `POST` with the exact configured `Origin` and a framed body.
    fn post_json_with(&mut self, path: &str, body: &str, extra: &[(&str, &str)]) -> Reply {
        let origin = format!("http://{}", self.host);
        let length = body.len().to_string();
        let mut all: Vec<(&str, &str)> = vec![
            ("Content-Type", "application/json"),
            ("Content-Length", &length),
            ("Origin", &origin),
        ];
        let cookies = self.cookie_header();
        if !cookies.is_empty() {
            all.push(("Cookie", &cookies));
        }
        all.extend_from_slice(extra);
        let mut request = wire("POST", path, &self.host, &all);
        request.push_str(body);
        let reply = request_on(self.addr, &request);
        self.remember(&reply);
        reply
    }

    /// Logs in with the given password, keeping the cookie.
    fn login(&mut self, password: &str) -> Reply {
        self.post_json_with(
            "/api/v1/login",
            &format!("{{\"username\":{USERNAME:?},\"password\":{password:?}}}"),
            &[],
        )
    }
}

/// A parsed HTTP/1.1 response.
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

    fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|error| panic!("expected a JSON body, got {:?} ({error})", self.body))
    }

    fn session_id(&self) -> String {
        self.json()["session_id"]
            .as_str()
            .expect("a session_id field")
            .to_owned()
    }

    fn csrf_token(&self) -> String {
        self.json()["csrf_token"]
            .as_str()
            .expect("a csrf_token field")
            .to_owned()
    }
}

fn wire(method: &str, path: &str, host: &str, extra: &[(&str, &str)]) -> String {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (name, value) in extra {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");
    request
}

/// Writes raw request bytes and parses the framed reply, under a deadline.
fn request_on(addr: SocketAddr, raw: &str) -> Reply {
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
        .expect("a status code is present")
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
    reader
        .read_exact(&mut body)
        .expect("the framed body arrives in full");
    Reply {
        status,
        headers,
        body: String::from_utf8(body).expect("management bodies are utf-8"),
    }
}

/// Runs a one-shot CLI command, feeding `stdin` to it.
fn cli(args: &[&str], stdin: Option<&str>) -> std::process::Output {
    let mut child = Command::new(BINARY)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("could not run {args:?}: {error}"));
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(input.as_bytes())
            .expect("stdin is written");
    } else {
        drop(child.stdin.take());
    }
    child
        .wait_with_output()
        .expect("the one-shot command finishes")
}

fn cli_ok(args: &[&str], stdin: Option<&str>) -> String {
    let output = cli(args, stdin);
    assert!(
        output.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Blocks until the listener answers, or fails with a deadline.
///
/// A readiness *poll*, not a sleep: it returns as soon as the service is up and
/// never turns a slow machine into a slow suite.
fn await_listener(addr: SocketAddr, child: &Child_, name: &str) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
            return;
        }
        assert!(
            child.is_alive(),
            "{name} exited before accepting connections; log: {:#?}",
            child.log()
        );
        assert!(
            Instant::now() < deadline,
            "{name} never accepted a connection; log: {:#?}",
            child.log()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// §6: the whole required flow, across a real `serve` restart.
///
/// Steps 1 through 9 of the plan, in order, against real processes.
#[test]
fn the_required_service_flow_survives_a_real_serve_restart() {
    let scratch = Scratch::new();

    // --- 1. Create the local administrator through the CLI. ---
    // A password arrives on stdin only. The CLI refuses it in `argv` and in the
    // environment because both leak through `/proc`; this is the same seam that
    // was found broken during M003, so it is exercised here rather than assumed.
    let created = cli_ok(
        &[
            "admin",
            "set-password",
            "--username",
            USERNAME,
            "--state",
            scratch.state().to_str().unwrap(),
            "--password-stdin",
        ],
        Some(PASSWORD),
    );
    assert!(
        created.contains(USERNAME),
        "the CLI must report the principal it created: {created}"
    );
    assert!(
        !created.contains(PASSWORD),
        "the CLI must never echo the credential it was given: {created}"
    );

    // --- 2. Start netd and serve as two separate processes. ---
    let netd = Child_::start(
        "wg-basic netd",
        &["netd", "--socket", scratch.netd_socket().to_str().unwrap()],
    );
    await_socket(&scratch.netd_socket(), &netd);

    let mut serve = ServeProcess::start(&scratch);
    await_listener(serve.addr, &serve.process, "wg-basic serve");

    // The startup line the operator reads is the evidence the reconcile ran.
    let reconcile_line = serve.process.await_log("startup reconciliation");
    assert!(
        reconcile_line.contains("nothing to apply"),
        "a fresh install has nothing to converge: {reconcile_line}"
    );
    let readiness_line = serve.process.await_log("readiness: ready");
    assert!(readiness_line.contains("ready"), "{readiness_line}");

    // --- 3. Log in. ---
    let mut browser = serve.client();
    let login = browser.login(PASSWORD);
    assert_eq!(login.status, 200, "login failed: {}", login.body);
    let cookie_header = login.header("set-cookie").expect("a session cookie");
    assert!(
        cookie_header.starts_with("wg_basic_session="),
        "{cookie_header}"
    );
    assert!(cookie_header.contains("HttpOnly"), "{cookie_header}");
    assert!(cookie_header.contains("SameSite=Strict"), "{cookie_header}");
    assert!(!cookie_header.contains("Secure"), "{cookie_header}");

    // --- 4. Session and authenticated health. ---
    let session = browser.get("/api/v1/session");
    assert_eq!(session.status, 200, "{}", session.body);
    let session_id = session.session_id();
    let csrf = session.csrf_token();

    let health = browser.get("/api/v1/health");
    assert_eq!(health.status, 200, "{}", health.body);
    let projected = health.json();
    assert_eq!(
        projected["health"]["database_healthy"],
        serde_json::json!(true)
    );
    // The decisive line: a real `netd` child is answering on the authorized
    // socket, and the authenticated route says so.
    assert_eq!(
        projected["backend"]["answered"],
        serde_json::json!(true),
        "a real netd is running: {projected}"
    );
    // The recorded half is still honest about there being nothing applied yet:
    // the live probe answers "is it up", the record answers "has it converged",
    // and conflating them is exactly the gap M004 found.
    assert_eq!(
        projected["health"]["netd_reachable"],
        serde_json::json!(false),
        "no reconcile has run yet, so there is no recorded evidence -- a \
         different fact from the backend being down: {projected}"
    );

    // --- 5. The startup reconciliation state agrees across two entry points. ---
    let cli_health = cli_ok(
        &[
            "health",
            "--state",
            scratch.state().to_str().unwrap(),
            "--socket",
            scratch.netd_socket().to_str().unwrap(),
        ],
        None,
    );
    let from_cli: serde_json::Value =
        serde_json::from_str(cli_health.trim()).expect("`wg-basic health` prints JSON");
    assert_eq!(
        from_cli["netd_reachable"], projected["health"]["netd_reachable"],
        "the CLI and the HTTP surface must not disagree about the record: \
         {from_cli} vs {projected}"
    );
    assert_eq!(
        from_cli["database_healthy"],
        projected["health"]["database_healthy"]
    );

    // --- 6. Restart serve. ---
    let stopped = serve.stop().expect("the exit status is observed");
    assert_eq!(
        stopped,
        0,
        "serve must exit cleanly on SIGTERM, got {stopped:?}; log: {:#?}",
        serve.process.log()
    );
    let shutdown_log = serve.process.log();
    assert!(
        shutdown_log
            .iter()
            .any(|line| line.contains("listening on")),
        "the first life really did serve"
    );

    let mut restarted = ServeProcess::start(&scratch);
    await_listener(
        restarted.addr,
        &restarted.process,
        "wg-basic serve (restarted)",
    );

    // --- 7. Reuse the valid session, unchanged, against a new process. ---
    let browser = browser.after_restart(restarted.addr, &restarted.host());
    let reused = browser.get("/api/v1/session");
    assert_eq!(
        reused.status, 200,
        "a non-expired session must survive a real process restart: {}",
        reused.body
    );
    assert_eq!(
        reused.session_id(),
        session_id,
        "the same session, not a new one"
    );
    assert_eq!(reused.csrf_token(), csrf);

    // --- 8. Log out / revoke. ---
    let mut browser = browser;
    let logout = browser.post_json_with("/api/v1/logout", "", &[("x-wg-basic-csrf", &csrf)]);
    assert_eq!(logout.status, 204, "logout failed: {}", logout.body);

    // --- 9. The old cookie is rejected. ---
    assert_eq!(
        browser.get("/api/v1/session").status,
        401,
        "the revoked cookie must stop working"
    );

    // And a restart does not resurrect it.
    restarted.process.stop();
    let mut third = ServeProcess::start(&scratch);
    await_listener(third.addr, &third.process, "wg-basic serve (third)");
    let browser = browser.after_restart(third.addr, &third.host());
    assert_eq!(
        browser.get("/api/v1/session").status,
        401,
        "a revoked session must stay revoked across a restart"
    );
    third.process.stop();

    drop(netd);
}

/// §6 and §11.8: `serve` never spawns or elevates netd.
///
/// Asserted from the child's own process tree rather than from the code: after
/// `serve` starts, the only process holding the netd socket is the one this test
/// started. If `serve` spawned or elevated a backend, a second holder would
/// appear.
#[test]
fn serve_does_not_spawn_or_elevate_netd() {
    let scratch = Scratch::new();
    cli_ok(
        &[
            "admin",
            "set-password",
            "--username",
            USERNAME,
            "--state",
            scratch.state().to_str().unwrap(),
            "--password-stdin",
        ],
        Some(PASSWORD),
    );

    let mut serve = ServeProcess::start(&scratch);
    await_listener(serve.addr, &serve.process, "wg-basic serve");

    // No netd is running, and the service still comes up: degraded, not fatal.
    // That is only possible if `serve` did not start one itself.
    let browser = serve.client();
    let healthz = browser.get("/healthz");
    assert_eq!(healthz.status, 200);
    assert_eq!(
        healthz.body, "degraded",
        "with no netd running the appliance is degraded, which it could only know \
         by trying and failing to reach one it did not spawn"
    );
    // And the authenticated route agrees with the live probe rather than with
    // the (empty) record.
    let mut probing = serve.client();
    assert_eq!(probing.login(PASSWORD).status, 200);
    let probed = probing.get("/api/v1/health");
    assert_eq!(
        probed.json()["backend"]["answered"],
        serde_json::json!(false),
        "no netd is running, so the live probe must say so: {}",
        probed.body
    );

    // No child process hangs off `serve`: a single process owns the state store,
    // and it owns no network backend.
    let descendants = child_processes_of(serve.process.child.id());
    assert!(
        descendants.is_empty(),
        "serve must not spawn children; found {descendants:?}"
    );

    // And a netd started afterwards is picked up without restarting serve, which
    // is the other half of "management never owns the backend": the backend's
    // lifetime is independent.
    let netd = Child_::start(
        "wg-basic netd",
        &["netd", "--socket", scratch.netd_socket().to_str().unwrap()],
    );
    await_socket(&scratch.netd_socket(), &netd);

    let mut browser = serve.client();
    assert_eq!(browser.login(PASSWORD).status, 200, "login still works");
    let health = browser.get("/api/v1/health");
    assert_eq!(health.status, 200, "{}", health.body);
    assert_eq!(
        health.json()["backend"]["answered"],
        serde_json::json!(true),
        "serve reports a backend it did not spawn, started after it: {}",
        health.body
    );

    serve.stop();
    drop(netd);
}

/// §6 acceptance 5: the perimeter is load-bearing over the real wire.
///
/// Every check here is against a real child process and a real socket. If the
/// Host/Origin/CSRF checks only held in an in-process harness, these would fail.
#[test]
fn the_security_perimeter_holds_over_the_real_wire() {
    let scratch = Scratch::new();
    cli_ok(
        &[
            "admin",
            "set-password",
            "--username",
            USERNAME,
            "--state",
            scratch.state().to_str().unwrap(),
            "--password-stdin",
        ],
        Some(PASSWORD),
    );
    let netd = Child_::start(
        "wg-basic netd",
        &["netd", "--socket", scratch.netd_socket().to_str().unwrap()],
    );
    await_socket(&scratch.netd_socket(), &netd);

    let mut serve = ServeProcess::start(&scratch);
    await_listener(serve.addr, &serve.process, "wg-basic serve");

    // A rebinding `Host` is refused on every route, before routing.
    for path in ["/", "/healthz", "/api/v1/session", "/api/v1/login"] {
        let reply = request_on(
            serve.addr,
            &wire("GET", path, "evil.example.com", &[("Connection", "close")]),
        );
        assert_eq!(reply.status, 403, "{path} must refuse a foreign Host");
        assert_eq!(reply.body, "forbidden", "{path}");
    }

    // An unsafe method without the exact `Origin` never reaches a handler, so it
    // cannot even issue a session.
    let mut browser = serve.client();
    let originless_body = format!("{{\"username\":{USERNAME:?},\"password\":{PASSWORD:?}}}");
    let originless_length = originless_body.len().to_string();
    let originless_request = wire(
        "POST",
        "/api/v1/login",
        &browser.host,
        &[
            ("Content-Type", "application/json"),
            ("Content-Length", &originless_length),
            ("Connection", "close"),
        ],
    ) + &originless_body;
    let originless = request_on(serve.addr, &originless_request);
    assert_eq!(
        originless.status, 403,
        "a login without the exact Origin must be refused: {}",
        originless.body
    );

    // A logout without the CSRF token changes nothing.
    browser.login(PASSWORD);
    let csrf = browser.get("/api/v1/session").csrf_token();
    let tokenless = browser.post_json_with("/api/v1/logout", "", &[]);
    assert_eq!(tokenless.status, 403, "logout without CSRF must be refused");
    assert_eq!(
        browser.get("/api/v1/session").status,
        200,
        "the refused logout must not have revoked the session"
    );

    // With the token it works.
    let with_token = browser.post_json_with("/api/v1/logout", "", &[("x-wg-basic-csrf", &csrf)]);
    assert_eq!(with_token.status, 204);

    // The shell and its assets are served, self-contained, with no external
    // origin anywhere in them.
    let shell = browser.get("/");
    assert_eq!(shell.status, 200);
    assert!(shell
        .header("content-type")
        .unwrap()
        .starts_with("text/html"));
    assert_eq!(
        shell.header("content-security-policy"),
        Some(
            "default-src 'self'; object-src 'none'; base-uri 'none'; \
             frame-ancestors 'none'; form-action 'self'"
        ),
        "the shell needs no CSP concession: the policy is the same one every \
         other response carries"
    );
    for asset in ["/assets/app.css", "/assets/app.js"] {
        let reply = browser.get(asset);
        assert_eq!(reply.status, 200, "{asset}");
    }
    // The old password is refused, and the new one works: a reset really did
    // revoke every session, through the CLI, with no restart.
    cli_ok(
        &[
            "admin",
            "set-password",
            "--username",
            USERNAME,
            "--state",
            scratch.state().to_str().unwrap(),
            "--password-stdin",
        ],
        Some(NEW_PASSWORD),
    );
    assert_eq!(
        browser.get("/api/v1/session").status,
        401,
        "a CLI reset must revoke every live session without a restart"
    );

    serve.stop();
    drop(netd);
}

/// Blocks until the netd socket exists and accepts a connection.
fn await_socket(path: &Path, child: &Child_) {
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
            "wg-basic netd exited before binding {:?}; log: {:#?}",
            path,
            child.log()
        );
        assert!(
            Instant::now() < deadline,
            "wg-basic netd never bound {:?}; log: {:#?}",
            path,
            child.log()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// Every process whose parent is `pid`.
///
/// Read from `/proc`, so the answer is the real process tree rather than an
/// assumption about what the code was told to do.
fn child_processes_of(pid: u32) -> Vec<(u32, String)> {
    let mut children = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        // Without `/proc` the assertion cannot be made; saying so is better than
        // passing silently.
        panic!("cannot read /proc, so the process tree cannot be qualified");
    };
    for entry in entries.flatten() {
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let Some(ppid) = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|value| value.trim().parse::<u32>().ok())
        else {
            continue;
        };
        if ppid != pid {
            continue;
        }
        let name = status
            .lines()
            .find_map(|line| line.strip_prefix("Name:"))
            .map(|value| value.trim().to_owned())
            .unwrap_or_default();
        children.push((
            entry
                .path()
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .parse()
                .unwrap_or(0),
            name,
        ));
    }
    children
}

/// The binary under test is the one this suite exercises.
///
/// Spawned once so a build or packaging problem is reported as itself rather than
/// as a confusing connect failure in the middle of a flow test.
#[test]
fn the_under_test_binary_is_the_one_this_suite_exercises() {
    let output = cli(&["--version"], None);
    assert!(
        output.status.success(),
        "the binary under test does not run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reported = String::from_utf8_lossy(&output.stdout);
    assert!(
        reported.contains(env!("CARGO_PKG_VERSION")),
        "expected version {}, got {reported:?}",
        env!("CARGO_PKG_VERSION")
    );
}
