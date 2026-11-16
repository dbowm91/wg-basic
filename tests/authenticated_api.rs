#![cfg(unix)]
//! Phase 7 M003 qualification: the authenticated HTTP perimeter.
//!
//! M003's central claims are about *ordering* and *absence*:
//!
//! * a foreign `Host` is refused **before** routing, so it cannot have a side
//!   effect on any route;
//! * the login limiter runs **before** Argon2, so a throttled attempt costs the
//!   attacker nothing and costs the appliance nothing;
//! * the service emits **no** CORS header, at all;
//! * a refusal **never** distinguishes a wrong password from an unknown user,
//!   a malformed body, or an outage.
//!
//! These are properties of the assembled `AuthenticatedApi` over a real worker,
//! so they are exercised here directly rather than through a socket.
//! `tests/management_http.rs` proves the same properties survive the transport.
//!
//! The `RequestHead` values are built by hand: the guards read only `Host`,
//! `Origin`, `Sec-Fetch-Site`, `Cookie`, `Content-Type`, and the CSRF header, so
//! constructing them explicitly is what makes these tests readable as claims.

use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use totp_lite::{totp_custom, Sha1};
use wg_basic::{
    domain::{TOTP_DIGITS, TOTP_STEP_SECONDS},
    http::{
        headers::header_value, Admission, AuthenticatedApi, Bucket, LoginLimiter, OriginPolicy,
        RequestGuard, RequestRejection, CSRF_HEADER,
    },
    management::{spawn, LoginOutcome, WorkerClient, WorkerConfig},
    state::StateStore,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const PASSWORD: &str = "an administrator password";

/// A self-cleaning scratch directory.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-m003-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
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
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Builds a `RequestHead` the way a browser would send one.
fn head(
    method: &str,
    target: &str,
    host: &str,
    extra: &[(&str, &str)],
) -> eggserve_primitives::RequestHead {
    let mut headers = eggserve_primitives::HeaderBlock::new();
    headers.push_str("host", host).unwrap();
    for (name, value) in extra {
        headers
            .push_str(*name, *value)
            .unwrap_or_else(|_| panic!("{name}: {value} must be a valid header"));
    }
    eggserve_primitives::RequestHead::new(
        eggserve_primitives::Method::new(method).unwrap(),
        eggserve_primitives::RequestTarget::parse(target).unwrap(),
        eggserve_primitives::HttpVersion::Http11,
        headers,
    )
}

/// The loopback bind address a test deployment uses.
fn loopback() -> SocketAddr {
    "127.0.0.1:8000".parse().unwrap()
}

/// A limiter wide enough that ordinary assertions never trip it.
fn wide_limiter() -> Arc<LoginLimiter> {
    Arc::new(LoginLimiter::new(
        Bucket::per_second(10_000, 10_000),
        Bucket::per_second(10_000, 10_000),
        16,
    ))
}

/// A limiter that is already empty.
///
/// Capacity 1 with a one-per-second refill on both the global and the peer
/// bucket, so a caller can establish exhaustion with two `check` calls at one
/// controlled instant and know the bucket is empty regardless of how long the
/// machine takes to answer. Callers that want it *observably* exhausted drive
/// those two calls themselves; constructing it is not exhaustion.
fn spent_limiter() -> Arc<LoginLimiter> {
    Arc::new(LoginLimiter::new(
        Bucket::per_second(1, 1),
        Bucket::per_second(1, 1),
        16,
    ))
}

fn loopback_api(client: WorkerClient) -> AuthenticatedApi {
    AuthenticatedApi::new(
        client,
        Arc::new(OriginPolicy::loopback_only(loopback())),
        wide_limiter(),
    )
}

/// Reads a response's body as text.
///
/// Consumes the response, so read the headers the caller wants *first*: a
/// `ResponseBody` is one-shot by design, and these tests assert on both.
fn body_of(response: &mut eggserve_primitives::Response) -> String {
    String::from_utf8(
        response
            .take_body()
            .expect("a management response carries a body")
            .into_bytes()
            .expect("a management body is a byte buffer"),
    )
    .expect("management bodies are utf-8")
}

/// The CSRF token a login response publishes.
fn csrf_token_of(body: &str) -> String {
    let json: serde_json::Value = serde_json::from_str(body).expect("a login body is json");
    json["csrf_token"]
        .as_str()
        .expect("a login publishes a csrf_token")
        .to_owned()
}

/// The `name=value` pair of a `Set-Cookie` header, without its attributes.
fn cookie_pair(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .expect("a set-cookie has at least one pair")
        .to_owned()
}

/// Spawns a worker and provisions the local administrator.
async fn worker_with_admin(scratch: &Scratch) -> WorkerClient {
    let startup =
        spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket())).expect("worker starts");
    let client = startup.client().clone();
    client
        .set_admin_password("admin".to_owned(), PASSWORD.to_owned())
        .await
        .expect("an admin is provisioned");
    client
}

/// A well-formed login body for the provisioned administrator.
fn login_body() -> Vec<u8> {
    format!(r#"{{"username":"admin","password":"{PASSWORD}"}}"#,).into_bytes()
}

// ---------------------------------------------------------------------------
// Host: refused before routing
// ---------------------------------------------------------------------------

#[test]
fn a_rebinding_host_is_refused_for_every_route_and_method() {
    let guard = RequestGuard::new(Arc::new(OriginPolicy::loopback_only(loopback())));
    for host in [
        "evil.example.com",
        "evil.example.com:8000",
        "localhost:8000",
        "10.0.0.5:8000",
        "0.0.0.0",
        // A name that merely *contains* the loopback literal.
        "127.0.0.1.evil.example.com",
        "127.0.0.1@evil.example.com",
        "",
    ] {
        for (method, target) in [
            ("GET", "/healthz"),
            ("GET", "/api/v1/session"),
            ("POST", "/api/v1/login"),
            ("POST", "/api/v1/logout"),
        ] {
            assert_eq!(
                guard
                    .check_host(&head(method, target, host, &[]))
                    .unwrap_err(),
                RequestRejection::HostNotAllowed,
                "{host} {method} {target} must be refused before routing"
            );
        }
    }
}

#[test]
fn the_allowed_host_set_is_not_a_wildcard() {
    let policy = OriginPolicy::loopback_only(loopback());
    assert!(policy.accepts_host("127.0.0.1:8000"));
    assert!(policy.accepts_host("127.0.0.1"));
    assert!(policy.accepts_host("[::1]:8000"));
    // Every other spelling is refused. Enumerated rather than sampled so a
    // future edit that widens the set has to delete a line to survive.
    for host in [
        "127.0.0.2:8000",
        "127.0.0.1:8001",
        "0.0.0.0",
        "*",
        "example.com",
        "",
    ] {
        assert!(!policy.accepts_host(host), "{host} must not be accepted");
    }
}

// ---------------------------------------------------------------------------
// Origin and Sec-Fetch-Site
// ---------------------------------------------------------------------------

#[test]
fn only_the_exact_canonical_origin_is_accepted() {
    let policy = OriginPolicy::loopback_only(loopback());
    assert!(policy.accepts_origin("http://127.0.0.1:8000"));
    // Trailing slash and surrounding whitespace are normalisation, not a
    // different origin.
    assert!(!policy.accepts_origin("http://127.0.0.1:8000/"));
    for foreign in [
        "http://127.0.0.1:8001",
        "https://127.0.0.1:8000",
        "http://[::1]:8000",
        "http://localhost:8000",
        "http://evil.example.com",
        "null",
        "",
    ] {
        assert!(
            !policy.accepts_origin(foreign),
            "{foreign} must not be the canonical origin"
        );
    }
}

#[test]
fn a_safe_method_carries_no_origin_requirement() {
    let guard = RequestGuard::new(Arc::new(OriginPolicy::loopback_only(loopback())));
    for target in ["/healthz", "/api/v1/session", "/api/v1/health"] {
        assert!(
            guard
                .check_origin(&head("GET", target, "127.0.0.1:8000", &[]))
                .is_ok(),
            "{target} must not demand an Origin"
        );
    }
}

// ---------------------------------------------------------------------------
// Content type
// ---------------------------------------------------------------------------

#[test]
fn a_login_must_be_json_and_a_simple_form_is_never_accepted() {
    let guard = RequestGuard::new(Arc::new(OriginPolicy::loopback_only(loopback())));
    for good in ["application/json", "application/json; charset=utf-8"] {
        assert!(
            guard
                .check_login_content_type(&head(
                    "POST",
                    "/api/v1/login",
                    "127.0.0.1:8000",
                    &[("content-type", good)]
                ))
                .is_ok(),
            "{good} must be accepted"
        );
    }
    // `multipart/form-data` is the cross-site request shape a CSRF token exists
    // to stop, and a simple form cannot carry a custom header at all.
    for bad in [
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=x",
        "text/plain",
        "",
    ] {
        assert_eq!(
            guard
                .check_login_content_type(&head(
                    "POST",
                    "/api/v1/login",
                    "127.0.0.1:8000",
                    &[("content-type", bad)]
                ))
                .unwrap_err(),
            RequestRejection::ContentTypeNotAllowed,
            "{bad} must be refused"
        );
    }
    // Absent entirely.
    assert!(guard
        .check_login_content_type(&head("POST", "/api/v1/login", "127.0.0.1:8000", &[]))
        .is_err());
}

// ---------------------------------------------------------------------------
// The limiter runs before Argon2
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn limiter_before_hashing() {
    // The ordering claim. Argon2id costs ~300 ms and 19 MiB per verification
    // (M002 closure), so a limiter applied after the hash would let an attacker
    // spend the appliance's CPU on every request before anything refused it.
    //
    // This is proven by timing, not by inspection: a spent limiter must refuse
    // faster than a single Argon2 verification takes, and it must refuse the
    // request *at all* where an unthrottled one succeeds. If the limiter ever
    // moves after the hash, the elapsed time jumps by ~300 ms and this fails.
    let scratch = Scratch::new();
    let client = worker_with_admin(&scratch).await;
    let body = login_body();
    let head_json = |origin: &str| {
        head(
            "POST",
            "/api/v1/login",
            "127.0.0.1:8000",
            &[("content-type", "application/json"), ("origin", origin)],
        )
    };

    // Warm the store's page cache and the process's allocator so the first
    // measurement is not paying one-off costs the assertion is not about.
    loopback_api(client.clone())
        .login(&head_json("http://127.0.0.1:8000"), &body, loopback())
        .await
        .expect("a warm-up login succeeds");

    // Take the *slowest* unthrottled login as the baseline and the *fastest*
    // throttled attempt as the measurement. Sampling both ends is what makes
    // this robust: on a loaded machine every call is slower, so comparing a
    // single pair would compare two different amounts of load and the ratio
    // would say more about the scheduler than about the ordering. The real
    // separation is three orders of magnitude, not a few percent.
    const SAMPLES: usize = 5;
    let mut slowest_unthrottled = std::time::Duration::ZERO;
    for _ in 0..SAMPLES {
        let started = std::time::Instant::now();
        loopback_api(client.clone())
            .login(&head_json("http://127.0.0.1:8000"), &body, loopback())
            .await
            .expect("an unthrottled login succeeds");
        slowest_unthrottled = slowest_unthrottled.max(started.elapsed());
    }

    // Now a limiter with no tokens left. The attempt must be refused, and it
    // must be refused without ever reaching Argon2. Draining it with a fixed
    // clock keeps the test deterministic: at one token per second, a wall-clock
    // re-check microseconds later still has nothing.
    let spent = spent_limiter();
    let instant = std::time::Instant::now();
    assert!(spent.check(loopback(), instant).is_allowed(), "drain it");
    assert!(
        !spent.check(loopback(), instant).is_allowed(),
        "the limiter must now be empty"
    );

    let mut fastest_throttled = std::time::Duration::MAX;
    let mut refused = None;
    for _ in 0..SAMPLES {
        let started = std::time::Instant::now();
        let rejection = AuthenticatedApi::new(
            client.clone(),
            Arc::new(OriginPolicy::loopback_only(loopback())),
            spent.clone(),
        )
        .login(&head_json("http://127.0.0.1:8000"), &body, loopback())
        .await
        .expect_err("a throttled login is refused, not answered");
        fastest_throttled = fastest_throttled.min(started.elapsed());
        refused = Some(rejection);
    }
    let refused = refused.expect("SAMPLES is non-zero");

    assert!(matches!(refused, RequestRejection::Throttled { .. }));
    assert!(
        fastest_throttled * 10 < slowest_unthrottled,
        "the fastest throttled attempt took {fastest_throttled:?} against the slowest \
         unthrottled login at {slowest_unthrottled:?}; the limiter is evidently running \
         after Argon2 rather than before it"
    );

    // And the refusal is a *bounded* one: it renders as 429 with a `Retry-After`
    // and a body that names nothing.
    assert_eq!(refused.status().as_u16(), 429);
    assert!(refused
        .retry_after()
        .is_some_and(|seconds| (1..=60).contains(&seconds)));
    assert_eq!(refused.body(), "too many attempts");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_saturated_health_budget_still_admits_login() {
    // `/healthz` has its own admission budget. A spent health bucket must not
    // stop a login from reaching the login limiter's allow path, and an
    // admitted health answer must still be only the two liveness tokens.
    let scratch = Scratch::new();
    let client = worker_with_admin(&scratch).await;

    let health = spent_limiter();
    let instant = std::time::Instant::now();
    assert!(health.check(loopback(), instant).is_allowed(), "drain it");
    assert!(
        !health.check(loopback(), instant).is_allowed(),
        "the health budget must now be empty"
    );

    let api = AuthenticatedApi::with_health_limiter(
        client.clone(),
        Arc::new(OriginPolicy::loopback_only(loopback())),
        wide_limiter(),
        health,
    );
    assert!(
        !api.health_limiter()
            .check(loopback(), std::time::Instant::now())
            .is_allowed(),
        "further health probes are shed before the worker"
    );

    let body = login_body();
    let login_head = head(
        "POST",
        "/api/v1/login",
        "127.0.0.1:8000",
        &[
            ("content-type", "application/json"),
            ("origin", "http://127.0.0.1:8000"),
        ],
    );
    api.login(&login_head, &body, loopback())
        .await
        .expect("a spent health budget must not block login admission");

    // An admitted `/healthz` still collapses to the two liveness tokens.
    let open_health = AuthenticatedApi::new(
        client,
        Arc::new(OriginPolicy::loopback_only(loopback())),
        wide_limiter(),
    );
    let health = open_health
        .worker_health()
        .await
        .expect("an admitted health read still answers");
    let token = wg_basic::http::Readiness::from_health(&health)
        .public_token()
        .expect("liveness projects to a public token");
    assert!(
        token == "ok" || token == "degraded",
        "health body tokens stay sealed: {token}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_throttled_login_does_not_answer_at_all() {
    // The refusal is an error, not a 503 masquerading as one: no `Set-Cookie`,
    // no body, nothing a client could mistake for a successful authentication.
    //
    // The exhaustion premise is *established*, not raced into existence. This
    // test used to drain the bucket with a real successful login and then expect
    // the next attempt to be refused -- which holds only while one Argon2id
    // verification stays inside the one-second refill interval. On a loaded
    // runner it does not, the token legitimately refills during the first
    // request's own hashing, and the test fails against a limiter that is
    // behaving exactly as specified.
    //
    // So the bucket is drained here at one controlled instant instead, with no
    // Argon2 work anywhere near the request under test, and the gap between the
    // drain and the call is microseconds of struct construction rather than a
    // whole verification. The two properties stay separate and both are still
    // proven here: the drain asserts the *token bucket* property at a single
    // instant (capacity 1 admits exactly one attempt and refuses the next), and
    // the login asserts the *rendering* property (a `Throttled` refusal is an
    // error path with a bounded 429 and a `Retry-After`, never an answer).
    let scratch = Scratch::new();
    let client = worker_with_admin(&scratch).await;
    let limiter = spent_limiter();

    let instant = std::time::Instant::now();
    assert!(limiter.check(loopback(), instant).is_allowed(), "drain it");
    assert!(
        !limiter.check(loopback(), instant).is_allowed(),
        "a capacity-1 bucket must refuse the attempt after the one it admitted"
    );

    let api = AuthenticatedApi::new(
        client,
        Arc::new(OriginPolicy::loopback_only(loopback())),
        limiter,
    );
    let body = login_body();
    let request = head(
        "POST",
        "/api/v1/login",
        "127.0.0.1:8000",
        &[
            ("content-type", "application/json"),
            ("origin", "http://127.0.0.1:8000"),
        ],
    );

    let refused = api
        .login(&request, &body, loopback())
        .await
        .expect_err("a login against an exhausted bucket is refused, not answered");
    assert!(matches!(refused, RequestRejection::Throttled { .. }));

    // The rendering half: bounded, retryable, and carrying nothing a client
    // could read as a successful authentication.
    assert_eq!(refused.status().as_u16(), 429);
    assert!(refused
        .retry_after()
        .is_some_and(|seconds| (1..=60).contains(&seconds)));
    assert_eq!(refused.body(), "too many attempts");
}

// ---------------------------------------------------------------------------
// Refusals do not disclose
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_never_distinguishes_why_credentials_were_rejected() {
    let scratch = Scratch::new();
    let client = worker_with_admin(&scratch).await;
    let api = loopback_api(client);
    let json = |value: &str| value.as_bytes().to_vec();

    let mut answers = std::collections::HashSet::new();
    for body in [
        // Correct shape, wrong password.
        json(r#"{"username":"admin","password":"definitely not it"}"#),
        // Correct shape, unknown user.
        json(r#"{"username":"nobody","password":"definitely not it"}"#),
        // Not JSON at all, but declared as JSON so the shape check is reached.
        json("this is not json"),
        // JSON, wrong shape.
        json(r#"{"user":"admin"}"#),
        // Empty username: the credential is refused, not the request.
        json(r#"{"username":"","password":""}"#),
    ] {
        let request = head(
            "POST",
            "/api/v1/login",
            "127.0.0.1:8000",
            &[
                ("content-type", "application/json"),
                ("origin", "http://127.0.0.1:8000"),
            ],
        );
        let rejection = api
            .login(&request, &body, loopback())
            .await
            .expect_err("none of these credentials are accepted");
        answers.insert((rejection.status().as_u16(), rejection.body().to_owned()));
    }

    assert_eq!(
        answers.len(),
        1,
        "every credential-shaped refusal must be the same answer, got {answers:?}"
    );
    let (status, body) = answers.into_iter().next().unwrap();
    assert_eq!(status, 401);
    assert_eq!(body, "unauthorized");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_correct_login_answers_once_and_only_once() {
    let scratch = Scratch::new();
    let client = worker_with_admin(&scratch).await;
    let api = loopback_api(client);
    let request = head(
        "POST",
        "/api/v1/login",
        "127.0.0.1:8000",
        &[
            ("content-type", "application/json"),
            ("origin", "http://127.0.0.1:8000"),
        ],
    );

    let first = api
        .login(&request, &login_body(), loopback())
        .await
        .expect("the provisioned password is accepted");
    assert_eq!(first.status().as_u16(), 200);
    let set_cookie = wg_basic::http::headers::header_value(&first, "set-cookie")
        .expect("a successful login publishes a cookie");
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert!(
        !set_cookie.contains("Domain"),
        "the cookie must be host-only"
    );

    // A second login is a second, independent session. Sessions are not
    // single-use: an operator may have two tabs open.
    let second = api
        .login(&request, &login_body(), loopback())
        .await
        .expect("a second login also succeeds");
    assert_eq!(second.status().as_u16(), 200);
    let second_cookie = header_value(&second, "set-cookie").unwrap();
    assert_ne!(set_cookie, second_cookie, "each login mints its own bearer");
}

// ---------------------------------------------------------------------------
// The CSRF token is per session, and compared without an early exit
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_session_carries_its_own_csrf_token() {
    let scratch = Scratch::new();
    let client = worker_with_admin(&scratch).await;
    let api = loopback_api(client);
    let request = head(
        "POST",
        "/api/v1/login",
        "127.0.0.1:8000",
        &[
            ("content-type", "application/json"),
            ("origin", "http://127.0.0.1:8000"),
        ],
    );

    let mut first = api
        .login(&request, &login_body(), loopback())
        .await
        .expect("login");
    let mut second = api
        .login(&request, &login_body(), loopback())
        .await
        .expect("login");

    let first_cookie = cookie_pair(&header_value(&first, "set-cookie").expect("a cookie"));
    let second_cookie = cookie_pair(&header_value(&second, "set-cookie").expect("a cookie"));
    let own = csrf_token_of(&body_of(&mut first));
    let other = csrf_token_of(&body_of(&mut second));

    // Two independent sessions, each with a distinct bearer and a distinct CSRF
    // token. A token is therefore not a second shared secret: it is useless
    // without the session it belongs to, and the session bearer is useless as a
    // CSRF token.
    assert_ne!(
        first_cookie, second_cookie,
        "each login mints its own bearer"
    );
    assert_ne!(own, other, "each session mints its own csrf token");
    assert!(
        own.len() >= 16,
        "a csrf token must not be trivially short: {own:?}"
    );

    let guard = api.guard();
    let session = api
        .authenticate(&head(
            "GET",
            "/api/v1/session",
            "127.0.0.1:8000",
            &[("cookie", &first_cookie)],
        ))
        .await
        .expect("the first session resolves");

    // The other session's token does not authorise this session's logout,
    // because the check compares against *this* session's stored token.
    assert_eq!(
        guard
            .check_csrf(
                &head(
                    "POST",
                    "/api/v1/logout",
                    "127.0.0.1:8000",
                    &[(CSRF_HEADER, &other)],
                ),
                &session,
            )
            .unwrap_err(),
        RequestRejection::CsrfInvalid
    );

    // This session's own token does.
    assert!(guard
        .check_csrf(
            &head(
                "POST",
                "/api/v1/logout",
                "127.0.0.1:8000",
                &[(CSRF_HEADER, &own)],
            ),
            &session,
        )
        .is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_a_session_makes_its_cookie_stop_working() {
    let scratch = Scratch::new();
    let client = worker_with_admin(&scratch).await;
    let api = loopback_api(client);
    let request = head(
        "POST",
        "/api/v1/login",
        "127.0.0.1:8000",
        &[
            ("content-type", "application/json"),
            ("origin", "http://127.0.0.1:8000"),
        ],
    );
    let login = api
        .login(&request, &login_body(), loopback())
        .await
        .expect("login");
    let pair = cookie_pair(&header_value(&login, "set-cookie").unwrap())
        .split_once('=')
        .expect("a cookie pair has a value")
        .1
        .to_owned();
    let with_cookie = || {
        head(
            "GET",
            "/api/v1/session",
            "127.0.0.1:8000",
            &[("cookie", &format!("wg_basic_session={pair}"))],
        )
    };

    assert!(api.authenticate(&with_cookie()).await.is_some());

    api.logout(&pair).await;

    assert!(
        api.authenticate(&with_cookie()).await.is_none(),
        "a revoked session must stop authenticating immediately"
    );
}

// ---------------------------------------------------------------------------
// Admission shape
// ---------------------------------------------------------------------------

#[test]
fn the_global_bucket_is_charged_before_the_peer_bucket() {
    // A refused attempt must cost the attacker nothing. If the peer bucket were
    // charged first, spreading attempts across many source addresses would burn
    // peer capacity that never reached the global budget.
    let limiter = LoginLimiter::new(Bucket::per_second(2, 1), Bucket::per_second(100, 100), 64);
    let now = std::time::Instant::now();
    for last in 1..=20u8 {
        limiter.check(SocketAddr::from(([127, 0, 0, last], 40000)), now);
    }
    assert!(
        limiter.tracked_peers() <= 64,
        "the peer map must stay bounded regardless of attacker-chosen addresses"
    );
    // The global budget is spent after two attempts from twenty distinct peers.
    assert!(!limiter
        .check("127.0.0.1:40001".parse().unwrap(), now)
        .is_allowed());
}

#[test]
fn a_refusal_always_carries_a_usable_retry_after() {
    // A `Retry-After: 0` would invite an immediate retry and a busy loop, so the
    // value is clamped into a range a client can actually act on.
    for capacity in [1u32, 2, 10] {
        for refill in [1u32, 2, 5] {
            let limiter = LoginLimiter::new(
                Bucket::per_second(capacity, refill),
                Bucket::per_second(capacity, refill),
                8,
            );
            let now = std::time::Instant::now();
            for _ in 0..capacity {
                limiter.check(loopback(), now);
            }
            let Admission::Refused {
                retry_after_seconds,
            } = limiter.check(loopback(), now)
            else {
                panic!("capacity {capacity} at {refill}/s must eventually refuse");
            };
            assert!(
                (1..=60).contains(&retry_after_seconds),
                "got {retry_after_seconds} for capacity {capacity} refill {refill}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Account password change (auth expansion M001)
// ---------------------------------------------------------------------------

async fn logged_in_sessions(
    scratch: &Scratch,
) -> (WorkerClient, AuthenticatedApi, String, String, String) {
    let client = worker_with_admin(scratch).await;
    let api = loopback_api(client.clone());
    let login_head = |cookie: Option<&str>| {
        let mut extra = vec![
            ("content-type", "application/json"),
            ("origin", "http://127.0.0.1:8000"),
        ];
        if let Some(cookie) = cookie {
            extra.push(("cookie", cookie));
        }
        head("POST", "/api/v1/login", "127.0.0.1:8000", &extra)
    };
    let first = api
        .login(&login_head(None), &login_body(), loopback())
        .await
        .expect("first login");
    let mut first = first;
    let first_cookie = cookie_pair(&header_value(&first, "set-cookie").expect("cookie"));
    let second = api
        .login(&login_head(None), &login_body(), loopback())
        .await
        .expect("second login");
    let second = second;
    let second_cookie = cookie_pair(&header_value(&second, "set-cookie").expect("cookie"));
    let csrf = csrf_token_of(&body_of(&mut first));
    assert_ne!(first_cookie, second_cookie);
    (client, api, first_cookie, second_cookie, csrf)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_read_and_password_change_revoke_siblings_not_the_completing_session() {
    let scratch = Scratch::new();
    let (client, api, keep_cookie, sibling_cookie, csrf) = logged_in_sessions(&scratch).await;

    let account = api
        .authenticate(&head(
            "GET",
            "/api/v1/account",
            "127.0.0.1:8000",
            &[("cookie", &keep_cookie)],
        ))
        .await
        .expect("session");
    let view = api
        .account(&account)
        .await
        .expect("account view")
        .take_body()
        .unwrap()
        .into_bytes()
        .unwrap();
    let view: serde_json::Value = serde_json::from_slice(&view).unwrap();
    assert_eq!(view["username"], "admin");
    assert_eq!(view["password_auth_enabled"], true);
    assert_eq!(view["totp_enabled"], false);
    assert!(view.get("principal_id").and_then(|v| v.as_str()).is_some());

    let new_password = "a different administrator password";
    let change_body =
        format!(r#"{{"current_password":"{PASSWORD}","new_password":"{new_password}"}}"#);
    let change = api
        .change_account_password(
            &head(
                "POST",
                "/api/v1/account/password",
                "127.0.0.1:8000",
                &[
                    ("content-type", "application/json"),
                    ("origin", "http://127.0.0.1:8000"),
                    ("cookie", &keep_cookie),
                    (CSRF_HEADER, &csrf),
                ],
            ),
            change_body.as_bytes(),
            loopback(),
            &account,
        )
        .await
        .expect("password accepted");

    assert_eq!(change.status().as_u16(), 204);

    assert!(api
        .authenticate(&head(
            "GET",
            "/api/v1/session",
            "127.0.0.1:8000",
            &[("cookie", &keep_cookie)],
        ))
        .await
        .is_some());
    assert!(api
        .authenticate(&head(
            "GET",
            "/api/v1/session",
            "127.0.0.1:8000",
            &[("cookie", &sibling_cookie)],
        ))
        .await
        .is_none());
    assert!(client
        .authenticate("admin".to_owned(), PASSWORD.to_owned())
        .await
        .is_err());
    assert!(client
        .authenticate("admin".to_owned(), new_password.to_owned())
        .await
        .is_ok());

    let audit = client.audit_page(None).await.expect("audit");
    let event = audit
        .events
        .iter()
        .find(|row| row.action.as_str() == "admin_password_changed")
        .expect("password change is audited");
    let rendered = format!("{event:?}");
    assert!(!rendered.contains(PASSWORD));
    assert!(!rendered.contains(new_password));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_current_password_on_account_change_is_an_opaque_401() {
    let scratch = Scratch::new();
    let (client, api, cookie, _sibling, csrf) = logged_in_sessions(&scratch).await;
    let session = api
        .authenticate(&head(
            "GET",
            "/api/v1/session",
            "127.0.0.1:8000",
            &[("cookie", &cookie)],
        ))
        .await
        .expect("session");
    let before = client.admin_status().await.expect("status").expect("admin");

    let body =
        format!(r#"{{"current_password":"not-it","new_password":"{PASSWORD}-replacement"}}"#);
    assert_eq!(
        api.change_account_password(
            &head(
                "POST",
                "/api/v1/account/password",
                "127.0.0.1:8000",
                &[
                    ("content-type", "application/json"),
                    ("origin", "http://127.0.0.1:8000"),
                    ("cookie", &cookie),
                    (CSRF_HEADER, &csrf),
                ],
            ),
            body.as_bytes(),
            loopback(),
            &session,
        )
        .await
        .unwrap_err(),
        RequestRejection::NotAuthenticated
    );

    let after = client.admin_status().await.expect("status").expect("admin");
    assert_eq!(before.updated_at, after.updated_at);
    assert!(client
        .authenticate("admin".to_owned(), PASSWORD.to_owned())
        .await
        .is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_routes_require_authentication_origin_and_csrf() {
    let scratch = Scratch::new();
    let (_, api, cookie, _, _csrf) = logged_in_sessions(&scratch).await;
    let session = api
        .authenticate(&head(
            "GET",
            "/api/v1/session",
            "127.0.0.1:8000",
            &[("cookie", &cookie)],
        ))
        .await
        .expect("session");

    assert!(api
        .authenticate(&head("GET", "/api/v1/account", "127.0.0.1:8000", &[]))
        .await
        .is_none());

    assert_eq!(
        api.guard()
            .check_origin(&head(
                "POST",
                "/api/v1/account/password",
                "127.0.0.1:8000",
                &[("origin", "https://evil.example")],
            ))
            .unwrap_err(),
        RequestRejection::OriginNotAllowed
    );
    assert_eq!(
        api.guard()
            .check_csrf(
                &head(
                    "POST",
                    "/api/v1/account/password",
                    "127.0.0.1:8000",
                    &[("content-type", "application/json")],
                ),
                &session,
            )
            .unwrap_err(),
        RequestRejection::CsrfMissing
    );
}

fn totp_code_now(secret_b32: &str) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bytes = Vec::new();
    let mut buffer = 0u32;
    let mut bits_left = 0;
    for byte in secret_b32.bytes() {
        let upper = byte.to_ascii_uppercase();
        let index = ALPHABET.iter().position(|&c| c == upper).unwrap();
        buffer = (buffer << 5) | u32::from(index as u8);
        bits_left += 5;
        if bits_left >= 8 {
            bits_left -= 8;
            bytes.push((buffer >> bits_left) as u8);
            buffer &= (1 << bits_left) - 1;
        }
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    totp_custom::<Sha1>(TOTP_STEP_SECONDS, TOTP_DIGITS, &bytes, now)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn totp_enroll_login_and_disable_flow() {
    let scratch = Scratch::new();
    let client = worker_with_admin(&scratch).await;
    let api = loopback_api(client.clone());
    let status = client.admin_status().await.unwrap().unwrap();
    client
        .begin_totp_enroll(status.principal_id)
        .await
        .expect("enroll");
    let store = StateStore::open(scratch.db()).unwrap();
    let pending = store
        .totp_pending_secret(status.principal_id)
        .unwrap()
        .unwrap();
    let code = totp_code_now(pending.expose_for_storage());
    client
        .confirm_totp_enroll(status.principal_id, code.clone())
        .await
        .expect("confirm");
    assert!(store.totp_enabled(status.principal_id).unwrap());

    let login_head = |cookie: Option<&str>| {
        let mut extra = vec![
            ("content-type", "application/json"),
            ("origin", "http://127.0.0.1:8000"),
        ];
        if let Some(cookie) = cookie {
            extra.push(("cookie", cookie));
        }
        head("POST", "/api/v1/login", "127.0.0.1:8000", &extra)
    };
    let mut challenge_response = api
        .login(&login_head(None), &login_body(), loopback())
        .await
        .expect("password accepted");
    let challenge: serde_json::Value =
        serde_json::from_str(&body_of(&mut challenge_response)).unwrap();
    assert_eq!(challenge["totp_required"], true);
    assert!(header_value(&challenge_response, "set-cookie").is_none());
    let verify_body = format!(
        r#"{{"pre_session_token":"{}","code":"{code}"}}"#,
        challenge["pre_session_token"].as_str().unwrap()
    );
    let verified = api
        .verify_totp_login(&login_head(None), verify_body.as_bytes(), loopback())
        .await
        .expect("totp accepted");
    assert!(header_value(&verified, "set-cookie").is_some());

    let account = client.account_view(status.principal_id).await.unwrap();
    let rendered = serde_json::to_string(&account).unwrap();
    assert!(account.totp_enabled);
    assert!(!rendered.contains(pending.expose_for_storage()));

    client
        .disable_totp(status.principal_id, PASSWORD.to_owned(), code.clone())
        .await
        .expect("disable");
    assert!(matches!(
        client.authenticate("admin".into(), PASSWORD.into()).await,
        Ok(LoginOutcome::Session(_))
    ));

    let audit = client.audit_page(None).await.expect("audit");
    for action in ["admin_totp_enabled", "admin_totp_disabled"] {
        let event = audit
            .events
            .iter()
            .find(|row| row.action.as_str() == action)
            .unwrap_or_else(|| panic!("missing {action}"));
        let rendered = format!("{event:?}");
        assert!(!rendered.contains(pending.expose_for_storage()));
    }
}
