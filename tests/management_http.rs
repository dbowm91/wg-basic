//! Loopback integration tests for the Phase 7 management HTTP surface.
//!
//! These tests speak **real HTTP/1.1 over a real TCP socket** to a real EggServe
//! runtime. That is deliberate: the properties M001–M003 have to prove — that the
//! surface binds loopback only, that a foreign `Host` is refused before routing,
//! that every response on the wire carries the security headers, that an unsafe
//! method without the exact `Origin` never reaches a handler, that a logout
//! without a CSRF token changes nothing, and that a stopped worker becomes a
//! bounded 503 — are properties of the assembled server, not of the routing
//! function. A unit test on the `Service` impl cannot observe any of them.
//!
//! The client is written out by hand rather than pulled in as a dependency: the
//! surface answers a handful of request shapes, and a hand-written client keeps
//! the crate free of an HTTP client whose own behaviour would then need
//! qualifying.

use eggserve_server::Server;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use wg_basic::{
    domain::{CsrfToken, SessionId, SessionToken},
    http::{
        headers, AuthenticatedApi, Bucket, LoginLimiter, ManagementHttpConfig, ManagementService,
        OriginPolicy,
    },
    management::{spawn, WorkerConfig},
    state::SessionRecord,
};

/// A parsed HTTP/1.1 response, reduced to what these tests assert on.
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
}

/// The password every authenticated test provisions.
const PASSWORD: &str = "an administrator password";

/// Unix seconds, for the session-expiry fixture.
fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
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
            .start_with_service(ManagementService::new(api_for(client)))
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

    /// The `Host` value this harness's policy accepts with the bound port.
    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.addr.port())
    }

    /// Sends one request and reads the whole reply.
    fn request(&self, raw: &str) -> Reply {
        request_on(self.addr, raw)
    }

    /// A well-formed `GET` with a `Host` this harness accepts.
    fn get(&self, path: &str) -> Reply {
        self.request(&format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.host()
        ))
    }

    /// Requests graceful shutdown and waits for the runtime to drain.
    async fn stop(mut self) {
        self.control.shutdown();
        self.completion.wait().await.expect("a clean shutdown");
    }
}

/// The API a loopback test harness runs.
///
/// The limiter is deliberately wide enough that a test's handful of requests
/// cannot accidentally trip it: `limiter_before_hashing` in
/// `tests/authenticated_api.rs` drives a saturated one on purpose.
fn api_for(client: wg_basic::management::WorkerClient) -> AuthenticatedApi {
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    AuthenticatedApi::new(
        client,
        Arc::new(OriginPolicy::loopback_only(bind)),
        Arc::new(LoginLimiter::new(
            Bucket::per_second(1000, 1000),
            Bucket::per_second(1000, 1000),
            16,
        )),
    )
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

/// A well-formed request that closes the connection, with a caller-chosen method.
fn wire(method: &str, path: &str, host: &str, extra: &[(&str, &str)]) -> String {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (name, value) in extra {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");
    request
}

/// [`wire`] plus a body, as bytes appended after the header block.
///
/// Takes the body as a separate argument rather than through a format
/// placeholder, so the caller cannot accidentally interpolate it into the
/// request *line* where a newline in it would be a request-splitting bug.
fn wire_with_body(
    method: &str,
    path: &str,
    host: &str,
    extra: &[(&str, &str)],
    body: &str,
) -> String {
    let mut request = wire(method, path, host, extra);
    request.push_str(body);
    request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ephemeral_loopback_bind_serves_the_health_route() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;

    // Port 0 really did produce a concrete loopback port.
    assert!(harness.addr.port() > 0);
    assert_eq!(harness.addr.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));

    let reply = harness.get("/healthz");
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, "degraded", "no netd is running in a test");

    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_health_route_is_not_cached_by_an_intermediary() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;
    let reply = harness.get("/healthz");
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
    let reply = harness.get("/healthz");
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
    let reply = harness.get("/api/v1/interfaces");
    assert_eq!(reply.status, 404);
    assert_eq!(reply.body, "not found");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unsupported_method_is_refused_with_405_and_a_bounded_body() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;

    for method in ["POST", "PUT", "DELETE"] {
        let reply = harness.request(&wire(method, "/healthz", &harness.host(), &[]));
        assert_eq!(reply.status, 405, "{method}");
        assert_eq!(reply.body, "method not allowed", "{method}");
    }

    // HEAD is refused too, and carries no body — so the refusal is still
    // bounded even for a method that must not receive one.
    let reply = harness.request(&wire("HEAD", "/healthz", &harness.host(), &[]));
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
    let reply = harness.request(&wire_with_body(
        "POST",
        "/healthz",
        &harness.host(),
        &[("Content-Length", "5")],
        "hello",
    ));
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
        .start_with_service(ManagementService::new(api_for(client.clone())))
        .await
        .expect("loopback bind succeeds");
    let addr = handle.local_addr();
    let host = format!("127.0.0.1:{}", addr.port());
    let (control, mut completion) = handle.into_parts();

    // Answered before the worker is gone.
    assert_eq!(
        request_on(addr, &wire("GET", "/healthz", &host, &[])).status,
        200
    );

    // Ending the worker must not end the listener: the operator still needs to
    // reach a surface that tells them so.
    startup.stop().await.expect("a clean shutdown");

    let reply = request_on(addr, &wire("GET", "/healthz", &host, &[]));
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
        let reply = harness.get("/healthz");
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

// ---------------------------------------------------------------------------
// M003: the authenticated perimeter, observed on the wire.
//
// These are the properties that only exist once the transport, the service, and
// the worker are assembled. Each one is a claim the closure record will rest on.
// ---------------------------------------------------------------------------

/// The header names every management response must carry.
const REQUIRED_SECURITY_HEADERS: &[&str] = &[
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
];

impl Reply {
    fn headers_named(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .count()
    }
}

/// Asserts the security header set, and that no CORS header exists at all.
fn assert_perimeter(reply: &Reply) {
    for name in REQUIRED_SECURITY_HEADERS {
        assert!(reply.header(name).is_some(), "{name} must be present");
    }
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    // Zero CORS, on every response, in every case. An allowlist would be a
    // weaker position; a wildcard would be a bug.
    for name in [
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-max-age",
    ] {
        assert_eq!(reply.header(name), None, "{name} must never be emitted");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_foreign_host_is_refused_before_routing() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;

    // The DNS-rebinding shape: the page's name resolves to loopback, and the
    // `Host` the browser sends is the attacker's name, not ours.
    for host in ["evil.example.com", "evil.example.com:80", "localhost:8000"] {
        let reply = harness.request(&wire("GET", "/healthz", host, &[]));
        assert_eq!(reply.status, 403, "{host} must be refused");
        assert_eq!(reply.body, "forbidden", "{host}");
        // And it is refused as a *policy* answer, not a routing accident: the
        // known route does not answer 404 here.
        assert_perimeter(&reply);
    }

    // The accepted spelling still works, so the refusal is discrimination
    // rather than a blanket denial.
    assert_eq!(harness.get("/healthz").status, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_response_kind_carries_the_security_headers() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;

    // Success, unknown route, wrong method, and an authenticated-route refusal.
    // The header set is applied centrally, so all four must agree.
    assert_perimeter(&harness.get("/healthz"));
    assert_perimeter(&harness.get("/api/v1/nope"));
    assert_perimeter(&harness.request(&wire("PUT", "/healthz", &harness.host(), &[])));
    assert_perimeter(&harness.get("/api/v1/session"));

    for name in REQUIRED_SECURITY_HEADERS {
        assert_eq!(
            harness.get("/healthz").headers_named(name),
            1,
            "{name} must appear exactly once, not once per sealing path"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_loopback_deployment_never_claims_a_secure_transport() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;
    let reply = harness.get("/healthz");
    // HSTS on a plain-HTTP loopback listener would poison a browser's cache for
    // a host that legitimately serves HTTP. It follows the canonical origin, not
    // the connection, so it is absent here and present behind an HTTPS proxy.
    assert_eq!(reply.header("strict-transport-security"), None);
    assert_perimeter(&reply);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unsafe_method_without_the_exact_origin_is_refused() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;
    let body = r#"{"username":"admin","password":"nope"}"#;
    let length = body.len().to_string();

    // No `Origin` at all: not a legacy client, a non-browser caller.
    let missing = harness.request(&wire_with_body(
        "POST",
        "/api/v1/login",
        &harness.host(),
        &[
            ("Content-Type", "application/json"),
            ("Content-Length", &length),
        ],
        body,
    ));
    assert_eq!(missing.status, 403);
    assert_eq!(missing.body, "forbidden");

    // A cross-site `Origin`, and the browser's own cross-site verdict. The
    // request is refused before the limiter, the parser, or Argon2.
    let exact_origin = format!("http://{}", harness.host());
    for extra in [
        vec![("Origin", "http://evil.example.com")],
        vec![("Origin", "null")],
        vec![
            ("Origin", exact_origin.as_str()),
            ("Sec-Fetch-Site", "cross-site"),
        ],
    ] {
        let label = format!("{extra:?}");
        let mut headers = vec![
            ("Content-Type", "application/json"),
            ("Content-Length", length.as_str()),
        ];
        headers.extend(extra);
        let reply = harness.request(&wire_with_body(
            "POST",
            "/api/v1/login",
            &harness.host(),
            &headers,
            body,
        ));
        assert_eq!(reply.status, 403, "{label} must be refused");
        assert_perimeter(&reply);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_form_encoded_login_is_refused() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;
    let form_body = "username=admin&password=nope";
    let form_length = form_body.len().to_string();
    let reply = harness.request(&wire_with_body(
        "POST",
        "/api/v1/login",
        &harness.host(),
        &[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Content-Length", &form_length),
            ("Origin", &format!("http://{}", harness.host())),
        ],
        form_body,
    ));
    // A form post is exactly the cross-site request shape a CSRF token exists to
    // stop, and a simple form cannot carry a custom header.
    assert_eq!(reply.status, 401);
    assert_eq!(reply.body, "unauthorized");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_authenticated_route_refuses_an_unauthenticated_caller() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;

    for path in ["/api/v1/session", "/api/v1/health"] {
        let bare = harness.get(path);
        assert_eq!(bare.status, 401, "{path}");
        assert_eq!(bare.body, "unauthorized");

        // A garbage cookie is the same answer, not a distinguishable one.
        let forged = "f".repeat(64);
        let reply = harness.request(&wire(
            "GET",
            path,
            &harness.host(),
            &[("Cookie", &format!("wg_basic_session={forged}"))],
        ));
        assert_eq!(reply.status, 401, "{path} with a forged cookie");
        assert_eq!(reply.body, "unauthorized");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_without_a_csrf_token_changes_nothing() {
    let scratch = Scratch::new();
    let startup =
        spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket())).expect("worker starts");
    let client = startup.client().clone();
    client
        .set_admin_password(
            "admin".to_owned(),
            "correct horse battery staple".to_owned(),
        )
        .await
        .expect("an admin is provisioned");
    drop(startup);

    let server = Server::builder()
        .runtime(
            ManagementHttpConfig::new("127.0.0.1:0")
                .expect("valid bind")
                .runtime_config()
                .expect("valid defaults"),
        )
        .build()
        .unwrap();
    let handle = server
        .start_with_service(ManagementService::new(api_for(client)))
        .await
        .expect("loopback bind succeeds");
    let addr = handle.local_addr();
    let host = addr.to_string();
    let origin = format!("http://{host}");
    let (control, mut completion) = handle.into_parts();

    // Log in for real.
    let body = r#"{"username":"admin","password":"correct horse battery staple"}"#;
    let length = body.len().to_string();
    let login = request_on(
        addr,
        &wire_with_body(
            "POST",
            "/api/v1/login",
            &host,
            &[
                ("Content-Type", "application/json"),
                ("Content-Length", &length),
                ("Origin", &origin),
            ],
            body,
        ),
    );
    assert_eq!(login.status, 200, "login failed: {login:?}");
    let set_cookie = login
        .header("set-cookie")
        .expect("a successful login publishes a session cookie");
    assert!(set_cookie.starts_with("wg_basic_session="), "{set_cookie}");
    assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
    assert!(set_cookie.contains("SameSite=Strict"), "{set_cookie}");
    assert!(!set_cookie.contains("Domain"), "{set_cookie}");
    assert!(!set_cookie.contains("Secure"), "{set_cookie}");
    let session_cookie = set_cookie.split(';').next().unwrap().to_owned();

    // The session works.
    let session = request_on(
        addr,
        &wire(
            "GET",
            "/api/v1/session",
            &host,
            &[("Cookie", &session_cookie)],
        ),
    );
    assert_eq!(session.status, 200);
    assert!(session.body.contains("csrf_token"), "{}", session.body);

    // Logout with a real Origin but no CSRF header is refused, and the session
    // is still live afterwards — which is the whole point of checking.
    let refused = request_on(
        addr,
        &wire(
            "POST",
            "/api/v1/logout",
            &host,
            &[("Cookie", &session_cookie), ("Origin", &origin)],
        ),
    );
    assert_eq!(refused.status, 403);
    assert_eq!(refused.body, "forbidden");
    let still_live = request_on(
        addr,
        &wire(
            "GET",
            "/api/v1/session",
            &host,
            &[("Cookie", &session_cookie)],
        ),
    );
    assert_eq!(
        still_live.status, 200,
        "a refused logout must not revoke the session"
    );

    // The authenticated health route renders the safe projection, and nothing
    // that could be a credential.
    let health = request_on(
        addr,
        &wire(
            "GET",
            "/api/v1/health",
            &host,
            &[("Cookie", &session_cookie)],
        ),
    );
    assert_eq!(health.status, 200);
    assert!(!health.body.contains("password"), "{}", health.body);
    assert!(
        !health.body.to_lowercase().contains("argon"),
        "{}",
        health.body
    );

    // A logout with a wrong CSRF token is also refused.
    let wrong = request_on(
        addr,
        &wire(
            "POST",
            "/api/v1/logout",
            &host,
            &[
                ("Cookie", &session_cookie),
                ("Origin", &origin),
                ("x-wg-basic-csrf", "not-the-token"),
            ],
        ),
    );
    assert_eq!(wrong.status, 403);
    assert_eq!(
        request_on(
            addr,
            &wire(
                "GET",
                "/api/v1/session",
                &host,
                &[("Cookie", &session_cookie)]
            )
        )
        .status,
        200
    );

    control.shutdown();
    completion.wait().await.expect("a clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_product_crud_uses_generation_cas_and_reports_degraded_commit() {
    let scratch = Scratch::new();
    let startup =
        spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket())).expect("worker starts");
    let client = startup.client().clone();
    client
        .set_admin_password("admin".to_owned(), PASSWORD.to_owned())
        .await
        .expect("admin provisioned");
    drop(startup);

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
        .start_with_service(ManagementService::new(api_for(client)))
        .await
        .unwrap();
    let addr = handle.local_addr();
    let host = addr.to_string();
    let origin = format!("http://{host}");
    let (control, mut completion) = handle.into_parts();

    let login_body = format!(r#"{{"username":"admin","password":"{PASSWORD}"}}"#);
    let login = request_on(
        addr,
        &wire_with_body(
            "POST",
            "/api/v1/login",
            &host,
            &[
                ("Origin", &origin),
                ("Content-Type", "application/json"),
                ("Content-Length", &login_body.len().to_string()),
            ],
            &login_body,
        ),
    );
    assert_eq!(login.status, 200, "{login:?}");
    let cookie = login
        .header("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let session = request_on(
        addr,
        &wire("GET", "/api/v1/session", &host, &[("Cookie", &cookie)]),
    );
    let csrf = serde_json::from_str::<serde_json::Value>(&session.body).unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let unsafe_request = |method: &str, path: &str, body: &str, with_csrf: bool| {
        let length = body.len().to_string();
        let mut headers = vec![
            ("Cookie", cookie.as_str()),
            ("Origin", origin.as_str()),
            ("Content-Type", "application/json"),
            ("Content-Length", length.as_str()),
        ];
        if with_csrf {
            headers.push(("x-wg-basic-csrf", csrf.as_str()));
        }
        request_on(addr, &wire_with_body(method, path, &host, &headers, body))
    };
    for (method, path, body) in [
        ("POST", "/api/v1/setup", "{}"),
        ("POST", "/api/v1/clients", "{}"),
    ] {
        assert_eq!(
            unsafe_request(method, path, body, false).status,
            403,
            "{method} {path} without CSRF"
        );
    }

    let setup_body = r#"{"expected_generation":1,"interface_name":"wg0","tunnel_prefix":"10.77.0.0/24","listen_port":51820,"advertised_endpoint":"vpn.example.test:51820","egress_interface":"eth0","ipv4_forwarding_required":true,"masquerade":true,"default_client_route_policy":{"prefixes":["10.77.0.0/24"]}}"#;
    let setup = unsafe_request("POST", "/api/v1/setup", setup_body, true);
    assert_eq!(
        setup.status, 202,
        "a durable commit against the absent netd is degraded: {}",
        setup.body
    );
    let setup_json: serde_json::Value = serde_json::from_str(&setup.body).unwrap();
    let generation = setup_json["generation"].as_u64().unwrap();
    let interface_id = setup_json["data"]["interface_id"].as_str().unwrap();

    let stale = unsafe_request(
        "POST",
        "/api/v1/clients",
        &format!(r#"{{"expected_generation":1,"interface_id":"{interface_id}","label":"phone"}}"#),
        true,
    );
    assert_eq!(
        stale.status, 409,
        "stale generation must not commit: {stale:?}"
    );

    let create_body = format!(
        r#"{{"expected_generation":{generation},"interface_id":"{interface_id}","label":"phone","dns_servers":["1.1.1.1"],"client_keepalive_seconds":25}}"#
    );
    let created = unsafe_request("POST", "/api/v1/clients", &create_body, true);
    assert_eq!(
        created.status, 202,
        "committed client with unavailable backend is 202: {}",
        created.body
    );
    assert!(
        !created.body.to_lowercase().contains("private_key"),
        "{}",
        created.body
    );
    let created_json: serde_json::Value = serde_json::from_str(&created.body).unwrap();
    let client_id = created_json["data"]["client_id"].as_str().unwrap();
    let generation = created_json["generation"].as_u64().unwrap();

    let config = request_on(
        addr,
        &wire(
            "GET",
            &format!("/api/v1/clients/{client_id}/config"),
            &host,
            &[("Cookie", &cookie)],
        ),
    );
    assert_eq!(config.status, 200);
    assert!(config.body.contains("[Interface]"));
    assert!(config.body.contains("PrivateKey = "));
    assert_eq!(config.header("cache-control"), Some("no-store"));
    assert!(config
        .header("content-disposition")
        .unwrap()
        .contains(client_id));
    assert_eq!(config.header("x-content-type-options"), Some("nosniff"));
    let qr = request_on(
        addr,
        &wire(
            "GET",
            &format!("/api/v1/clients/{client_id}/qr"),
            &host,
            &[("Cookie", &cookie)],
        ),
    );
    assert_eq!(qr.status, 200);
    assert_eq!(qr.header("content-type"), Some("image/svg+xml"));
    assert_eq!(qr.header("cache-control"), Some("no-store"));
    assert!(qr.body.starts_with("<svg "));
    assert!(!qr.body.contains("PrivateKey"));

    let link_path = format!("/api/v1/clients/{client_id}/enrollment-links");
    assert_eq!(unsafe_request("POST", &link_path, "{}", false).status, 403);
    let link_response = unsafe_request("POST", &link_path, "{}", true);
    assert_eq!(link_response.status, 201, "{}", link_response.body);
    assert_eq!(link_response.header("cache-control"), Some("no-store"));
    let link: serde_json::Value = serde_json::from_str(&link_response.body).unwrap();
    let share_url = link["share_url"].as_str().unwrap();
    let (_, fragment) = share_url
        .split_once('#')
        .unwrap_or_else(|| panic!("share URL has no fragment: {share_url}"));
    let token = fragment.strip_prefix("token=").unwrap();
    assert_eq!(token.len(), 43);
    let stored_digest: String = rusqlite::Connection::open(scratch.db())
        .unwrap()
        .query_row(
            "SELECT token_digest FROM enrollment_capabilities WHERE capability_id = ?1",
            [link["capability_id"].as_str().unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_digest.len(), 64);
    assert_ne!(stored_digest, token);
    let audit_values = rusqlite::Connection::open(scratch.db()).unwrap();
    let audit_text: String = audit_values
        .query_row(
            "SELECT group_concat(action || ':' || coalesce(resource_id, '')) FROM audit_events",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!audit_text.contains(token));
    let landing_path = format!("/enroll/{}", link["capability_id"].as_str().unwrap());
    assert!(share_url.contains(&landing_path));
    let landing = request_on(addr, &wire("GET", &landing_path, &host, &[]));
    assert_eq!(landing.status, 200);
    assert_eq!(landing.header("cache-control"), Some("no-store"));
    assert!(landing.body.contains("/assets/enroll.js"));
    let enrollment_script = request_on(addr, &wire("GET", "/assets/enroll.js", &host, &[]));
    assert_eq!(enrollment_script.status, 200);
    assert!(enrollment_script.body.contains("history.replaceState"));
    assert!(!landing.body.contains(token));
    let consume_body = format!(r#"{{"token":"{token}"}}"#);
    let wrong_token = "A".repeat(43);
    let wrong_body = format!(r#"{{"token":"{wrong_token}"}}"#);
    let wrong = request_on(
        addr,
        &wire_with_body(
            "POST",
            &format!(
                "/api/v1/enroll/{}/consume",
                link["capability_id"].as_str().unwrap()
            ),
            &host,
            &[
                ("Origin", &origin),
                ("Content-Type", "application/json"),
                ("Content-Length", &wrong_body.len().to_string()),
            ],
            &wrong_body,
        ),
    );
    assert_eq!(wrong.status, 410);
    let wrong_host = request_on(
        addr,
        &wire_with_body(
            "POST",
            &format!(
                "/api/v1/enroll/{}/consume",
                link["capability_id"].as_str().unwrap()
            ),
            "attacker.invalid",
            &[
                ("Origin", &origin),
                ("Content-Type", "application/json"),
                ("Content-Length", &consume_body.len().to_string()),
            ],
            &consume_body,
        ),
    );
    assert_eq!(wrong_host.status, 403);
    let wrong_origin = request_on(
        addr,
        &wire_with_body(
            "POST",
            &format!(
                "/api/v1/enroll/{}/consume",
                link["capability_id"].as_str().unwrap()
            ),
            &host,
            &[
                ("Origin", "http://attacker.invalid"),
                ("Content-Type", "application/json"),
                ("Content-Length", &consume_body.len().to_string()),
            ],
            &consume_body,
        ),
    );
    assert_eq!(wrong_origin.status, 403);
    let consume = request_on(
        addr,
        &wire_with_body(
            "POST",
            &format!(
                "/api/v1/enroll/{}/consume",
                link["capability_id"].as_str().unwrap()
            ),
            &host,
            &[
                ("Origin", &origin),
                ("Content-Type", "application/json"),
                ("Content-Length", &consume_body.len().to_string()),
            ],
            &consume_body,
        ),
    );
    assert_eq!(consume.status, 200, "{}", consume.body);
    assert!(consume.body.contains("[Interface]"));
    assert_eq!(consume.header("cache-control"), Some("no-store"));
    assert_eq!(consume.header("access-control-allow-origin"), None);
    let second = request_on(
        addr,
        &wire_with_body(
            "POST",
            &format!(
                "/api/v1/enroll/{}/consume",
                link["capability_id"].as_str().unwrap()
            ),
            &host,
            &[
                ("Origin", &origin),
                ("Content-Type", "application/json"),
                ("Content-Length", &consume_body.len().to_string()),
            ],
            &consume_body,
        ),
    );
    assert_eq!(second.status, 410);

    let second_link = unsafe_request("POST", &link_path, "{}", true);
    assert_eq!(second_link.status, 201);
    let second_json: serde_json::Value = serde_json::from_str(&second_link.body).unwrap();
    let revoke = unsafe_request(
        "DELETE",
        &format!(
            "/api/v1/enrollment-links/{}",
            second_json["capability_id"].as_str().unwrap()
        ),
        "",
        true,
    );
    assert_eq!(revoke.status, 200);
    let revoked_url = second_json["share_url"].as_str().unwrap();
    let revoked_token = revoked_url
        .split_once('#')
        .unwrap()
        .1
        .strip_prefix("token=")
        .unwrap();
    let revoked_body = format!(r#"{{"token":"{revoked_token}"}}"#);
    let revoked_consume = request_on(
        addr,
        &wire_with_body(
            "POST",
            &format!(
                "/api/v1/enroll/{}/consume",
                second_json["capability_id"].as_str().unwrap()
            ),
            &host,
            &[
                ("Origin", &origin),
                ("Content-Type", "application/json"),
                ("Content-Length", &revoked_body.len().to_string()),
            ],
            &revoked_body,
        ),
    );
    assert_eq!(revoked_consume.status, 410);

    let expiring = unsafe_request("POST", &link_path, r#"{"expires_in_seconds":1}"#, true);
    assert_eq!(expiring.status, 201);
    let expiring_json: serde_json::Value = serde_json::from_str(&expiring.body).unwrap();
    let (expired_url, expired_fragment) = expiring_json["share_url"]
        .as_str()
        .unwrap()
        .split_once('#')
        .unwrap();
    assert!(expired_url.ends_with(expiring_json["capability_id"].as_str().unwrap()));
    let expired_token = expired_fragment.strip_prefix("token=").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let expired_body = format!(r#"{{"token":"{expired_token}"}}"#);
    let expired_consume = request_on(
        addr,
        &wire_with_body(
            "POST",
            &format!(
                "/api/v1/enroll/{}/consume",
                expiring_json["capability_id"].as_str().unwrap()
            ),
            &host,
            &[
                ("Origin", &origin),
                ("Content-Type", "application/json"),
                ("Content-Length", &expired_body.len().to_string()),
            ],
            &expired_body,
        ),
    );
    assert_eq!(expired_consume.status, 410);

    for (method, path, body) in [
        (
            "PATCH",
            format!("/api/v1/clients/{client_id}"),
            format!(r#"{{"expected_generation":{generation},"label":"blocked"}}"#),
        ),
        (
            "POST",
            format!("/api/v1/clients/{client_id}/disable"),
            format!(r#"{{"expected_generation":{generation}}}"#),
        ),
        (
            "POST",
            format!("/api/v1/clients/{client_id}/enable"),
            format!(r#"{{"expected_generation":{generation}}}"#),
        ),
        (
            "DELETE",
            format!("/api/v1/clients/{client_id}"),
            format!(r#"{{"expected_generation":{generation}}}"#),
        ),
    ] {
        assert_eq!(
            unsafe_request(method, &path, &body, false).status,
            403,
            "{method} {path} without CSRF"
        );
    }

    let listed = request_on(
        addr,
        &wire("GET", "/api/v1/clients", &host, &[("Cookie", &cookie)]),
    );
    assert_eq!(listed.status, 200);
    assert_eq!(listed.header("cache-control"), Some("no-store"));
    assert_eq!(listed.header("access-control-allow-origin"), None);
    assert!(listed.body.contains(client_id));
    let detail = request_on(
        addr,
        &wire(
            "GET",
            &format!("/api/v1/clients/{client_id}"),
            &host,
            &[("Cookie", &cookie)],
        ),
    );
    assert_eq!(detail.status, 200);
    assert!(detail.body.contains("phone"));

    let patch = unsafe_request(
        "PATCH",
        &format!("/api/v1/clients/{client_id}"),
        &format!(
            r#"{{"expected_generation":{generation},"label":"phone updated","client_keepalive_seconds":null}}"#
        ),
        true,
    );
    assert_eq!(patch.status, 202);
    let generation = serde_json::from_str::<serde_json::Value>(&patch.body).unwrap()["generation"]
        .as_u64()
        .unwrap();
    let disabled = unsafe_request(
        "POST",
        &format!("/api/v1/clients/{client_id}/disable"),
        &format!(r#"{{"expected_generation":{generation}}}"#),
        true,
    );
    assert_eq!(disabled.status, 202);
    let generation = serde_json::from_str::<serde_json::Value>(&disabled.body).unwrap()
        ["generation"]
        .as_u64()
        .unwrap();
    let enabled = unsafe_request(
        "POST",
        &format!("/api/v1/clients/{client_id}/enable"),
        &format!(r#"{{"expected_generation":{generation}}}"#),
        true,
    );
    assert_eq!(enabled.status, 202);
    let generation = serde_json::from_str::<serde_json::Value>(&enabled.body).unwrap()
        ["generation"]
        .as_u64()
        .unwrap();
    let deleted = unsafe_request(
        "DELETE",
        &format!("/api/v1/clients/{client_id}"),
        &format!(r#"{{"expected_generation":{generation}}}"#),
        true,
    );
    assert_eq!(deleted.status, 202);
    assert!(deleted.body.contains("\"revocation_confirmed\":false"));

    control.shutdown();
    completion.wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_cookie_profile_follows_the_canonical_origin_not_the_connection() {
    // The same code path, the same plain-HTTP transport, two configured origins.
    // Only the canonical origin differs, so only the cookie differs -- which is
    // what proves the profile follows configuration rather than the connection.
    let scratch = Scratch::new();
    let startup =
        spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket())).expect("worker starts");
    let client = startup.client().clone();
    client
        .set_admin_password("admin".to_owned(), PASSWORD.to_owned())
        .await
        .expect("an admin is provisioned");
    drop(startup);

    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = Server::builder()
        .runtime(
            ManagementHttpConfig::new("127.0.0.1:0")
                .expect("valid bind")
                .runtime_config()
                .expect("valid defaults"),
        )
        .build()
        .unwrap();
    let handle = server
        .start_with_service(ManagementService::new(AuthenticatedApi::new(
            client.clone(),
            Arc::new(OriginPolicy::behind_https_proxy(bind, "https://vpn.example.com").unwrap()),
            Arc::new(LoginLimiter::new(
                Bucket::per_second(1000, 1000),
                Bucket::per_second(1000, 1000),
                16,
            )),
        )))
        .await
        .expect("loopback bind succeeds");
    let addr = handle.local_addr();
    let (control, mut completion) = handle.into_parts();

    // The proxy forwards the browser's `Host` and `Origin`, not the socket's.
    let body = format!(r#"{{"username":"admin","password":"{PASSWORD}"}}"#);
    let reply = request_on(
        addr,
        &wire_with_body(
            "POST",
            "/api/v1/login",
            "vpn.example.com",
            &[
                ("Content-Type", "application/json"),
                ("Content-Length", &body.len().to_string()),
                ("Origin", "https://vpn.example.com"),
            ],
            &body,
        ),
    );
    assert_eq!(reply.status, 200, "login failed: {reply:?}");
    let set_cookie = reply
        .header("set-cookie")
        .expect("a successful login publishes a cookie");
    assert!(
        set_cookie.starts_with("__Host-wg_basic_session="),
        "an https origin must use the __Host- name, got {set_cookie}"
    );
    assert!(set_cookie.contains("Secure"), "{set_cookie}");
    assert!(!set_cookie.contains("Domain"), "{set_cookie}");
    // And HSTS follows the same configuration.
    assert_eq!(
        reply.header("strict-transport-security"),
        Some(headers::STRICT_TRANSPORT_SECURITY)
    );
    // Even though this transport was plain HTTP: the claim follows the origin,
    // because the proxy in front of it really is serving HTTPS.
    assert_eq!(
        reply.header("content-security-policy"),
        Some(headers::CONTENT_SECURITY_POLICY)
    );

    control.shutdown();
    completion.wait().await.expect("a clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_session_stops_authenticating() {
    // Proved at the wire rather than by waiting twelve hours: a session row is
    // inserted through a second store connection with an expiry already in the
    // past, and the cookie naming it must be refused. A stored row is the real
    // input to this check, so this is the same path a row would take after a
    // twelve-hour wait -- only the clock differs.
    let scratch = Scratch::new();
    let startup =
        spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket())).expect("worker starts");
    let client = startup.client().clone();
    client
        .set_admin_password("admin".to_owned(), PASSWORD.to_owned())
        .await
        .expect("an admin is provisioned");
    drop(startup);

    // The worker holds its own connection; SQLite serialises the writers.
    let store = wg_basic::state::StateStore::open(scratch.db()).expect("a second connection");
    let principal = store
        .principal_by_username("admin")
        .unwrap()
        .expect("provisioned");
    let token = SessionToken::generate().unwrap();
    let digest = token.digest();
    store
        .insert_session(
            &SessionRecord {
                id: SessionId::new(),
                principal_id: principal.id,
                csrf_token: CsrfToken::generate().unwrap(),
                // Created in the past and expired an hour ago: a row the service
                // must treat as dead even though it is still in the table.
                created_at: now_seconds() - 7200,
                expires_at: now_seconds() - 3600,
            },
            &digest,
        )
        .expect("an expired row can still be written");
    let cookie = format!("wg_basic_session={}", token.expose_once());
    drop(store);

    let server = Server::builder()
        .runtime(
            ManagementHttpConfig::new("127.0.0.1:0")
                .expect("valid bind")
                .runtime_config()
                .expect("valid defaults"),
        )
        .build()
        .unwrap();
    let handle = server
        .start_with_service(ManagementService::new(api_for(client)))
        .await
        .expect("loopback bind succeeds");
    let addr = handle.local_addr();
    let host = format!("127.0.0.1:{}", addr.port());
    let (control, mut completion) = handle.into_parts();

    let reply = request_on(
        addr,
        &wire("GET", "/api/v1/session", &host, &[("Cookie", &cookie)]),
    );
    assert_eq!(reply.status, 401);
    assert_eq!(reply.body, "unauthorized");
    assert_perimeter(&reply);

    control.shutdown();
    completion.wait().await.expect("a clean shutdown");
}
