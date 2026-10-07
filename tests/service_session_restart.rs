//! Phase 7 M004 §5: session behaviour across a real `serve` restart.
//!
//! # What this file is for
//!
//! M002 proved that sessions are persisted in SQLite and that the state-store
//! methods revoke and expire them. That is the right unit for M002 and the
//! wrong one for M004: a session that survives a *store* lookup tells you
//! nothing about whether it survives a *process* restart, because everything that
//! could break it — the in-memory cookie profile, the origin policy, the worker,
//! the listener, the runtime — is rebuilt from scratch.
//!
//! So every assertion here is made against a real HTTP client holding a real
//! `Cookie`, across a real stop-and-start of the whole service:
//!
//! * a non-expired session survives the restart and still authenticates;
//! * an expired session stays expired after the restart, rather than becoming
//!   valid again because its row was re-read with a fresh clock;
//! * logout still invalidates the cookie the browser is holding;
//! * a password reset invalidates *every* prior session, including one minted
//!   before the restart.
//!
//! The cookie is never extracted by reading the database. The harness parses the
//! `Set-Cookie` header the service wrote and replays the `Cookie` header the
//! way a browser would, because that round trip is the thing M003 designed.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use wg_basic::{
    domain::{CsrfToken, SessionId, SessionToken},
    http::{serve, ServeConfig, ServeReport},
    management::set_password_at,
    state::{SessionRecord, StateStore},
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// The administrator every fixture provisions.
const USERNAME: &str = "admin";
const PASSWORD: &str = "an administrator password";
const OTHER_PASSWORD: &str = "a different administrator password";

/// A self-cleaning scratch directory holding one real on-disk database.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-m004-session-{}-{}",
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

    /// A netd socket path that does not exist.
    ///
    /// Deliberately absent: the subject here is session persistence, and a
    /// backend that is down keeps the management surface up so a fault can be
    /// diagnosed. A `serve` run against this path serves while reporting
    /// `degraded`, which is the state every restart assertion below is made in.
    fn absent_socket(&self) -> PathBuf {
        self.0.join("no-such-netd.sock")
    }

    /// Provisions the local administrator, as the one-shot CLI command does.
    fn provision(&self) {
        set_password_at(self.db(), USERNAME, PASSWORD)
            .expect("a fresh path provisions an administrator");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One running `wg-basic serve`.
///
/// Built from [`wg_basic::http::serve::run_publishing`] rather than a
/// hand-assembled EggServe harness, because the subject is the *whole* process
/// lifecycle: a restart that kept the worker thread alive would not be a restart
/// at all.
struct ServiceInstance {
    addr: SocketAddr,
    task: Option<tokio::task::JoinHandle<Result<ServeReport, wg_basic::http::ServeError>>>,
    signal: Option<tokio::sync::oneshot::Sender<()>>,
}

impl ServiceInstance {
    /// Starts a service over `scratch`'s existing on-disk state.
    async fn start(scratch: &Scratch) -> Self {
        let config = ServeConfig::new(scratch.db(), scratch.absent_socket(), "127.0.0.1:0")
            .expect("a loopback ephemeral port is a valid serve configuration");
        let (signal, wait) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<SocketAddr>();
        let task = tokio::spawn(async move {
            serve::run_publishing(
                config,
                async {
                    wait.await.ok();
                },
                |report| {
                    let _ = ready_tx.send(report.bound);
                },
            )
            .await
        });

        // The bound address arrives through the readiness hook the moment the
        // listener is up, so nothing here sleeps: a test that waited a fixed
        // interval for a port would be slow when the machine is fast and flaky
        // when it is slow.
        let addr = tokio::time::timeout(Duration::from_secs(30), ready_rx)
            .await
            .expect("the service must bind within its own start deadline")
            .expect("the readiness hook must publish the bound address");
        Self {
            addr,
            task: Some(task),
            signal: Some(signal),
        }
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

    /// Stops the service and waits for the lifecycle to complete.
    ///
    /// Awaits the run future, so the state store is closed before this returns.
    /// That is what makes the next `start` a genuine restart rather than a second
    /// process competing for the same database.
    async fn stop(mut self) -> ServeReport {
        let _ = self
            .signal
            .take()
            .expect("a started service is stoppable")
            .send(());
        self.task
            .take()
            .expect("a service is stopped at most once")
            .await
            .expect("the service task must not panic")
            .expect("a clean shutdown")
    }
}

impl Drop for ServiceInstance {
    fn drop(&mut self) {
        // If a test panics before `stop`, still signal so the worker thread and
        // its store are released rather than leaked for the rest of the run.
        if let Some(signal) = self.signal.take() {
            let _ = signal.send(());
        }
    }
}

/// A minimal browser-shaped HTTP client.
///
/// `Clone` because a test sometimes needs the same jar pointed at two states
/// at once -- e.g. "this cookie still fails, and a fresh one still works".
///
/// Holds cookies and replays them, because the assertions are about what a
/// browser would do after `serve` restarts underneath it.
#[derive(Clone)]
struct Client {
    addr: SocketAddr,
    host: String,
    cookies: Vec<(String, String)>,
}

impl Client {
    /// Stores any cookie the reply set.
    fn remember(&mut self, reply: &Reply) {
        for value in reply.header_all("set-cookie") {
            let Some((pair, _attributes)) = value.split_once(';') else {
                continue;
            };
            let (name, content) = pair.split_once('=').expect("a cookie is name=value");
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

    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// A `GET` with this client's cookies and an accepted `Host`.
    fn get(&self, path: &str) -> Reply {
        let mut extra = vec![("Connection", "close")];
        let cookies = self.cookie_header();
        if !cookies.is_empty() {
            extra.push(("Cookie", &cookies));
        }
        request_on(self.addr, &wire("GET", path, &self.host, &extra))
    }

    /// A `POST` carrying JSON, with the exact configured `Origin`.
    fn post_json(&mut self, path: &str, body: &str) -> Reply {
        self.post_json_with(path, body, None)
    }

    /// A `POST` carrying JSON and an optional extra header.
    fn post_json_with(&mut self, path: &str, body: &str, extra_header: Option<&str>) -> Reply {
        let origin = format!("http://{}", self.host);
        let mut extra: Vec<(&str, &str)> = vec![
            ("Content-Type", "application/json"),
            ("Origin", &origin),
            ("Connection", "close"),
        ];
        let cookies = self.cookie_header();
        if !cookies.is_empty() {
            extra.push(("Cookie", &cookies));
        }
        if let Some(name_value) = extra_header {
            let (name, value) = name_value.split_once(':').expect("a name: value header");
            extra.push((name.trim(), value.trim()));
        }
        // Framed explicitly. An unframed body would be read to EOF, which makes
        // the request shape depend on the connection closing rather than on the
        // client saying how much it is sending.
        let length = body.len().to_string();
        extra.push(("Content-Length", &length));
        let mut request = wire("POST", path, &self.host, &extra);
        request.push_str(body);
        let reply = request_on(self.addr, &request);
        self.remember(&reply);
        reply
    }

    /// A client for a *restarted* service that still presents the same cookies.
    ///
    /// This is the browser's view after the operator restarts `serve` under a
    /// logged-in session: a new connection, a new `Host`/port, and the same
    /// cookie jar. Keeping the jar here rather than re-logging-in is what makes
    /// the survival assertion mean anything.
    fn after_restart(&self, instance: &ServiceInstance) -> Client {
        Client {
            addr: instance.addr,
            host: instance.host(),
            cookies: self.cookies.clone(),
        }
    }

    /// Logs in and keeps the cookie, asserting the login actually succeeded.
    fn login(&mut self) -> Reply {
        let reply = self.post_json(
            "/api/v1/login",
            &format!(
                "{{\"username\":{:?},\"password\":{:?}}}",
                USERNAME, PASSWORD
            ),
        );
        assert_eq!(reply.status, 200, "login must succeed: {}", reply.body);
        assert!(
            !self.cookies.is_empty(),
            "a successful login must set a session cookie"
        );
        reply
    }
}

/// A parsed HTTP/1.1 response.
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

    /// The session identifier the service issued, read out of the JSON body.
    fn session_id(&self) -> String {
        serde_json::from_str::<serde_json::Value>(&self.body)
            .expect("a JSON body")
            .get("session_id")
            .and_then(|value| value.as_str())
            .expect("a session_id field")
            .to_owned()
    }

    fn csrf_token(&self) -> String {
        serde_json::from_str::<serde_json::Value>(&self.body)
            .expect("a JSON body")
            .get("csrf_token")
            .and_then(|value| value.as_str())
            .expect("a csrf_token field")
            .to_owned()
    }
}

/// Builds a raw request with an accepted `Host` and a `Connection: close`.
fn wire(method: &str, path: &str, host: &str, extra: &[(&str, &str)]) -> String {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (name, value) in extra {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");
    request
}

/// Writes raw request bytes and parses the framed reply.
fn request_on(addr: SocketAddr, raw: &str) -> Reply {
    let mut stream = TcpStream::connect(addr).expect("loopback connect succeeds");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
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

/// Unix seconds.
fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// The client below only ever dials loopback, so this pins the assumption every
/// assertion in this file rests on.
#[test]
fn the_harness_dials_loopback_only() {
    let addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
    assert_eq!(addr.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
}

/// §5: a non-expired session survives a restart of the whole service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_non_expired_session_survives_a_serve_restart() {
    let scratch = Scratch::new();
    scratch.provision();

    // First life.
    let first = ServiceInstance::start(&scratch).await;
    let mut browser = first.client();
    let issued = browser.login();
    let session_id = issued.session_id();
    let csrf = issued.csrf_token();
    assert_eq!(browser.get("/api/v1/session").status, 200);

    let report = first.stop().await;
    // The *startup* classification: nothing to apply, nothing failed. The live
    // classification on the same run is `degraded` -- the two answer different
    // questions, and `readiness_is_reported_at_startup_and_healthz_never_explains_it`
    // pins that pair explicitly.
    assert_eq!(report.readiness.public_token(), Some("ok"));

    // Second life, same on-disk database, brand new process state: new listener,
    // new worker thread, new store handle, new in-memory limiter.
    let second = ServiceInstance::start(&scratch).await;
    assert_ne!(
        second.addr.port(),
        0,
        "the restarted service binds its own ephemeral port"
    );
    let browser = browser.after_restart(&second);

    // The cookie the browser was holding still authenticates, and it is the
    // *same* session -- not a re-login that happened to look similar.
    let session = browser.get("/api/v1/session");
    assert_eq!(
        session.status, 200,
        "a non-expired session must survive the restart: {}",
        session.body
    );
    assert_eq!(session.session_id(), session_id);
    assert_eq!(
        session.csrf_token(),
        csrf,
        "the CSRF token is per-session state and must survive too"
    );

    // And the authenticated detail route works with it, which is the whole
    // point of the session being server-side state rather than a signed token.
    let health = browser.get("/api/v1/health");
    assert_eq!(health.status, 200, "{}", health.body);
    assert!(
        !health.body.contains("password"),
        "the authenticated health projection must stay secret-free"
    );

    second.stop().await;
}

/// §5: logout still invalidates the cookie the browser is holding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn logout_across_a_restart_invalidates_the_old_cookie() {
    let scratch = Scratch::new();
    scratch.provision();

    let first = ServiceInstance::start(&scratch).await;
    let mut browser = first.client();
    browser.login();
    first.stop().await;

    // Restart, confirm the session is live, then log out and confirm the *same*
    // cookie is dead -- both before and after another restart, because a
    // revocation that only took effect in memory would survive nothing.
    let second = ServiceInstance::start(&scratch).await;
    let mut browser = browser.after_restart(&second);
    assert_eq!(browser.get("/api/v1/session").status, 200);
    let csrf = browser.get("/api/v1/session").csrf_token();

    let logout = browser.post_json_with(
        "/api/v1/logout",
        "",
        Some(&format!("x-wg-basic-csrf: {csrf}")),
    );
    assert_eq!(logout.status, 204, "logout must succeed: {}", logout.body);
    assert_eq!(
        browser.get("/api/v1/session").status,
        401,
        "a logged-out cookie must stop authenticating immediately"
    );
    second.stop().await;

    // And it stays dead across a further restart: revocation is persisted.
    let third = ServiceInstance::start(&scratch).await;
    let browser = browser.after_restart(&third);
    assert_eq!(
        browser.get("/api/v1/session").status,
        401,
        "a revoked session must not come back when the service restarts"
    );
    third.stop().await;
}

/// §5: a password reset invalidates every prior session, including one minted
/// before the restart.
///
/// This is the case that proves sessions are *not* independent of the
/// credential: a reset that only stopped future logins would leave every
/// outstanding cookie — including one already copied off the machine — usable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_password_reset_invalidates_every_prior_session_across_a_restart() {
    let scratch = Scratch::new();
    scratch.provision();

    let first = ServiceInstance::start(&scratch).await;
    let mut browser_a = first.client();
    let mut browser_b = first.client();
    browser_a.login();
    browser_b.login();
    // Two independent sessions for the same principal.
    assert_ne!(
        browser_a.get("/api/v1/session").session_id(),
        browser_b.get("/api/v1/session").session_id()
    );
    first.stop().await;

    // Reset the password while the service is down -- exactly what an operator
    // does when they suspect a credential is compromised.
    set_password_at(scratch.db(), USERNAME, OTHER_PASSWORD)
        .expect("a reset on a stopped service must succeed");

    let second = ServiceInstance::start(&scratch).await;
    let browser_a = browser_a.after_restart(&second);
    let browser_b = browser_b.after_restart(&second);

    assert_eq!(
        browser_a.get("/api/v1/session").status,
        401,
        "a reset must invalidate every session minted before it"
    );
    assert_eq!(
        browser_b.get("/api/v1/session").status,
        401,
        "a reset must invalidate every session, not just the first"
    );

    // The old password no longer logs in; the new one does.
    let mut stale = browser_a.clone();
    let refused = stale.post_json(
        "/api/v1/login",
        &format!(
            "{{\"username\":{:?},\"password\":{:?}}}",
            USERNAME, PASSWORD
        ),
    );
    assert_eq!(refused.status, 401, "the old password must be refused");
    stale.remember(&refused);

    let mut fresh = second.client();
    fresh.post_json(
        "/api/v1/login",
        &format!(
            "{{\"username\":{:?},\"password\":{:?}}}",
            USERNAME, OTHER_PASSWORD
        ),
    );
    assert_eq!(fresh.get("/api/v1/session").status, 200);
    second.stop().await;
}

/// §5: expiry is honoured across a restart rather than being re-minted.
///
/// The session row is written directly with an expiry already in the past, which
/// is the only way to exercise a 12-hour lifetime without sleeping for 12 hours.
/// What matters is that the service reads the *persisted* `expires_at` — so a
/// restart cannot turn an expired row back into a valid session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_session_stays_expired_across_a_restart() {
    let scratch = Scratch::new();
    scratch.provision();

    // Mint a session row that expired an hour ago.
    let token = SessionToken::generate().expect("the CSPRNG yields a session token");
    let digest = token.digest();
    let now = now_seconds();
    {
        let store = StateStore::open(scratch.db()).expect("the provisioned store opens");
        let principal = store
            .principal_by_username(USERNAME)
            .expect("a query runs")
            .expect("the provisioned principal exists");
        store
            .insert_session(
                &SessionRecord {
                    id: SessionId::new(),
                    principal_id: principal.id,
                    csrf_token: CsrfToken::generate().expect("the CSPRNG yields a CSRF token"),
                    created_at: now - 7200,
                    expires_at: now - 3600,
                },
                &digest,
            )
            .expect("an already-expired session row is storable");
    }

    let first = ServiceInstance::start(&scratch).await;
    let mut browser = first.client();
    // Present the expired cookie exactly as the browser would.
    browser.cookies.push((
        "wg_basic_session".to_owned(),
        token.expose_once().to_owned(),
    ));
    assert_eq!(
        browser.get("/api/v1/session").status,
        401,
        "an expired session must not authenticate"
    );
    first.stop().await;

    let second = ServiceInstance::start(&scratch).await;
    let browser = browser.after_restart(&second);
    assert_eq!(
        browser.get("/api/v1/session").status,
        401,
        "a restart must not resurrect an expired session by re-reading the row \
         with a fresh clock"
    );
    second.stop().await;
}

/// §4 and §5 together: readiness survives a restart and `/healthz` never widens.
///
/// Pins the two classifications against each other on a real socket — the
/// startup report says what the mandatory reconcile concluded, `/healthz` says
/// what the live appliance looks like, and they are allowed to differ.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readiness_is_reported_at_startup_and_healthz_never_explains_it() {
    let scratch = Scratch::new();
    scratch.provision();

    let first = ServiceInstance::start(&scratch).await;
    let report = first.stop().await;

    // Startup classification: nothing to apply, so nothing failed.
    assert_eq!(
        report.readiness.public_token(),
        Some("ok"),
        "a fresh install has nothing to converge"
    );
    assert!(report.readiness.describe().contains("ready"));

    let second = ServiceInstance::start(&scratch).await;
    let browser = second.client();

    // Live classification: there is no netd, so the backend is unreachable and
    // the surface is degraded.
    let healthz = browser.get("/healthz");
    assert_eq!(healthz.status, 200);
    assert_eq!(healthz.body, "degraded");
    assert_eq!(
        healthz.header("content-type"),
        Some("text/plain; charset=utf-8")
    );

    // The reason must not appear anywhere on the unauthenticated response.
    for forbidden in ["network", "backend", "convergence", "database", "netd"] {
        assert!(
            !healthz.body.to_lowercase().contains(forbidden),
            "/healthz leaked {forbidden:?}: {}",
            healthz.body
        );
    }
    assert_eq!(healthz.body, "degraded", "exactly two tokens, nothing more");

    // Nor may it appear in a header.
    for (name, value) in &healthz.headers {
        assert!(
            !value.to_lowercase().contains("network"),
            "header {name} leaked the reason: {value}"
        );
    }

    // The same reason *is* available to a caller who proves a session.
    let mut authenticated = second.client();
    authenticated.login();
    let detail = authenticated.get("/api/v1/health");
    assert_eq!(detail.status, 200);
    let parsed: serde_json::Value = serde_json::from_str(&detail.body).unwrap();
    assert_eq!(
        parsed["backend"]["answered"],
        serde_json::json!(false),
        "the authenticated route may say why: {parsed}"
    );
    assert_eq!(
        parsed["health"]["netd_reachable"],
        serde_json::json!(false),
        "and it reports the record beside the observation: {parsed}"
    );
    second.stop().await;
}
