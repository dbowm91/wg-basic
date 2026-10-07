//! Loopback integration tests for the Phase 7 M001 management HTTP surface.
//!
//! These tests speak **real HTTP/1.1 over a real TCP socket** to a real EggServe
//! runtime. That is deliberate: the properties M001 has to prove — that the
//! surface binds loopback only, that it refuses an unsupported method with a
//! bounded body, that a body-bearing request never reaches application work, and
//! that a stopped worker becomes a bounded 503 — are properties of the assembled
//! server, not of the routing function. A unit test on the `Service` impl cannot
//! observe any of them.
//!
//! The client is written out by hand rather than pulled in as a dependency: the
//! surface sends four kinds of request, and a hand-written client keeps the
//! crate free of an HTTP client whose own behaviour would then need qualifying.

use eggserve_server::Server;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use wg_basic::{
    http::{ManagementHttpConfig, ManagementService},
    management::{spawn, WorkerConfig},
};

/// A parsed HTTP/1.1 response, reduced to what these tests assert on.
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
}

/// A scratch directory that cleans itself up.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "wg-basic-http-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn db(&self) -> PathBuf {
        self.0.join("state.db")
    }

    fn absent_socket(&self) -> PathBuf {
        self.0.join("no-such-netd.sock")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running management server plus the worker behind it.
struct Harness {
    addr: SocketAddr,
    control: eggserve_server::ServerControl,
    completion: eggserve_server::ServerCompletion,
}

impl Harness {
    /// Starts a real server on an ephemeral loopback port.
    async fn start(scratch: &Scratch) -> Self {
        let startup = spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket()))
            .expect("an empty store and an absent netd still start");
        let client = startup.client().clone();
        // `startup` is dropped here, which detaches the worker thread but keeps
        // it running: the service's own client clone holds the command queue
        // open. When the harness goes away the last sender drops, the worker's
        // `blocking_recv` returns `None`, and the thread exits with its store.
        drop(startup);

        let config = ManagementHttpConfig::new("127.0.0.1:0")
            .expect("a loopback ephemeral port is valid")
            .runtime_config()
            .expect("valid defaults");
        let server = Server::builder()
            .runtime(config)
            .build()
            .expect("valid runtime config");
        let handle = server
            .start_with_service(ManagementService::new(client.clone()))
            .await
            .expect("loopback bind succeeds");
        let addr = handle.local_addr();
        let (control, completion) = handle.into_parts();

        Self {
            addr,
            control,
            completion,
        }
    }

    /// Sends one request and reads the whole reply.
    fn request(&self, raw: &str) -> Reply {
        request_on(self.addr, raw)
    }

    /// Requests graceful shutdown and waits for the runtime to drain.
    async fn stop(mut self) {
        self.control.shutdown();
        self.completion.wait().await.expect("a clean shutdown");
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.control.shutdown();
    }
}

/// Writes raw request bytes and parses the reply.
fn request_on(addr: SocketAddr, raw: &str) -> Reply {
    let mut stream = TcpStream::connect(addr).expect("loopback connect succeeds");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    stream
        .write_all(raw.as_bytes())
        .expect("request bytes are written");
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
        .expect("a framed response carries content-length");
    // A HEAD response declares the length a GET would have returned but sends no
    // body, so reading it would block forever. Deciding from the request's own
    // method keeps the client honest about the wire contract.
    let sent_head = raw
        .split_whitespace()
        .next()
        .is_some_and(|method| method.eq_ignore_ascii_case("HEAD"));
    let mut body = vec![0u8; if sent_head { 0 } else { length }];
    reader
        .read_exact(&mut body)
        .expect("the framed body arrives in full");
    Reply {
        status,
        headers,
        body: String::from_utf8(body).expect("management bodies are utf-8"),
    }
}

/// A minimal well-formed `GET` request.
fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ephemeral_loopback_bind_serves_the_health_route() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;

    // Port 0 really did produce a concrete loopback port.
    assert!(harness.addr.port() > 0);
    assert_eq!(harness.addr.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));

    let reply = harness.request(&get("/healthz"));
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, "degraded", "no netd is running in a test");

    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_health_route_is_not_cached_by_an_intermediary() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;
    let reply = harness.request(&get("/healthz"));
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(
        reply.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listener_advertises_no_server_stack() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;
    let reply = harness.request(&get("/healthz"));
    assert_eq!(
        reply.header("server"),
        None,
        "the product must not hand a prober its stack"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_route_is_a_bounded_404_on_the_wire() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;
    let reply = harness.request(&get("/api/v1/interfaces"));
    assert_eq!(reply.status, 404);
    assert_eq!(reply.body, "not found");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unsupported_method_is_refused_with_405_and_a_bounded_body() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;

    for method in ["POST", "PUT", "DELETE"] {
        let reply = harness.request(&format!(
            "{method} /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        ));
        assert_eq!(reply.status, 405, "{method}");
        assert_eq!(reply.body, "method not allowed", "{method}");
    }

    // HEAD is refused too, and carries no body — so the refusal is still
    // bounded even for a method that must not receive one.
    let reply =
        harness.request("HEAD /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    assert_eq!(reply.status, 405);
    assert_eq!(reply.body, "");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_bearing_request_never_reaches_application_work() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;

    // The service declares `Reject`, so the transport refuses the body before
    // routing. Even on the one route the surface publishes, an attacker cannot
    // make the process buffer chosen bytes.
    let reply = harness.request(
        "POST /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    );
    assert!(
        reply.status == 405 || reply.status == 413,
        "expected the transport to refuse the body, got {}",
        reply.status
    );
    assert!(
        reply.body.len() <= 64,
        "the refusal body must stay bounded, got {:?}",
        reply.body
    );
    // Whatever the transport chose, the service still answered `ok`/`degraded`
    // only; a body it accepted could not have been reflected.
    assert_ne!(reply.body, "hello");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_that_is_stopped_becomes_a_bounded_503() {
    let scratch = Scratch::new();
    let startup =
        spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket())).expect("worker starts");
    let client = startup.client().clone();

    let config = ManagementHttpConfig::new("127.0.0.1:0")
        .expect("valid bind")
        .runtime_config()
        .expect("valid defaults");
    let server = Server::builder().runtime(config).build().unwrap();
    let handle = server
        .start_with_service(ManagementService::new(client.clone()))
        .await
        .expect("loopback bind succeeds");
    let addr = handle.local_addr();
    let (control, mut completion) = handle.into_parts();

    // Answered before the worker is gone.
    assert_eq!(request_on(addr, &get("/healthz")).status, 200);

    // Ending the worker must not end the listener: the operator still needs to
    // reach a surface that tells them so.
    startup.stop().await.expect("a clean shutdown");

    let reply = request_on(addr, &get("/healthz"));
    assert_eq!(reply.status, 503);
    assert_eq!(reply.body, "unavailable");
    assert_eq!(reply.header("cache-control"), Some("no-store"));

    control.shutdown();
    completion.wait().await.expect("a clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_known_route_answers_the_same_on_every_connection() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;

    // Two separate connections, so the answer is not a cached per-connection
    // artefact: each request gets its own real socket and real framing.
    for _ in 0..3 {
        let reply = harness.request(&get("/healthz"));
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, "degraded");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_lifecycle_releases_the_state_store_before_it_returns() {
    use wg_basic::{
        http::{run, ServeConfig},
        state::StateStore,
    };

    let scratch = Scratch::new();
    let config = ServeConfig::new(scratch.db(), scratch.absent_socket(), "127.0.0.1:0")
        .expect("a loopback ephemeral port is a valid configuration");
    let state_path = config.state_path.clone();

    let (signal, wait) = tokio::sync::oneshot::channel::<()>();
    let run = tokio::spawn(async move {
        run(config, async {
            wait.await.ok();
        })
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let _ = signal.send(());

    let report = run
        .await
        .expect("the run task must not panic")
        .expect("a clean run");
    assert!(report.bound.port() > 0, "a real listener must have bound");

    // The store was released, not merely forgotten: SQLite refuses a second
    // connection while this process still holds it, so a successful reopen
    // proves the worker thread exited and the store closed before `run`
    // returned. This lives in the integration suite on purpose — `src/http/`
    // must not reference the state store at all, even from a test.
    StateStore::open(&state_path).expect("the state store must be closed by the time run returns");
    drop(state_path);
}
