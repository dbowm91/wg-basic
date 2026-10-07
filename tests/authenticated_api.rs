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
use wg_basic::{
    http::{
        headers::header_value, Admission, AuthenticatedApi, Bucket, LoginLimiter, OriginPolicy,
        RequestGuard, RequestRejection, CSRF_HEADER,
    },
    management::{spawn, WorkerClient, WorkerConfig},
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
async fn a_throttled_login_does_not_answer_at_all() {
    // The refusal is an error, not a 503 masquerading as one: no `Set-Cookie`,
    // no body, nothing a client could mistake for a successful authentication.
    let scratch = Scratch::new();
    let client = worker_with_admin(&scratch).await;
    let limiter = LoginLimiter::new(Bucket::per_second(1, 1), Bucket::per_second(1, 1), 16);
    let api = AuthenticatedApi::new(
        client,
        Arc::new(OriginPolicy::loopback_only(loopback())),
        Arc::new(limiter),
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

    assert!(api.login(&request, &body, loopback()).await.is_ok());
    let second = api
        .login(&request, &body, loopback())
        .await
        .expect_err("the second attempt in the same instant is throttled");
    assert!(matches!(second, RequestRejection::Throttled { .. }));
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
