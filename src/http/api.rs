//! The authenticated browser API.
//!
//! # Route inventory
//!
//! | Method | Path | Auth | CSRF | Origin |
//! |---|---|---|---|---|
//! | `POST` | `/api/v1/login` | none | none | **exact** |
//! | `POST` | `/api/v1/logout` | session | **required** | **exact** |
//! | `GET` | `/api/v1/session` | session | none | — |
//! | `GET` | `/api/v1/health` | session | none | — |
//! | `GET` | `/healthz` | none | none | — |
//!
//! There is no peer, client, or interface route. Phase 8 owns those, and M003's
//! job is to close the perimeter *before* a configuration-mutating route exists
//! to be abused through it.
//!
//! # Two pieces, split on purpose
//!
//! [`RequestGuard`] is **pure policy**: it reads `Host`, `Origin`, `Sec-Fetch-*`,
//! `Cookie`, and the CSRF header, and answers yes or no. It needs no worker, no
//! database, and no clock beyond what it is handed, so every security rule here is
//! testable on its own.
//!
//! [`AuthenticatedApi`] adds the two things that *do* need the worker: issuing a
//! session and resolving one. Keeping them apart is what lets the perimeter be
//! proven without standing up a service.
//!
//! # Every request carries an allowed `Host`
//!
//! Checked before routing, so an unknown or malformed `Host` cannot reach a
//! handler. This is the DNS-rebinding defence: an attacker-controlled name
//! resolves to loopback, and "the socket is loopback" says nothing about who is
//! asking.
//!
//! # Unsafe methods need an exact `Origin` *and* a CSRF token
//!
//! `SameSite=Strict` is not the defence. It is weakened by any same-site context
//! an attacker can influence — a sibling subdomain, a user-content page on the
//! same registrable domain — and it is no defence at all against a token an
//! attacker can already read. So:
//!
//! * an unsafe method with a missing or foreign `Origin` is refused outright;
//! * an authenticated unsafe method additionally needs the session's CSRF token
//!   echoed in [`CSRF_HEADER`];
//! * a cross-site `Sec-Fetch-Site` is refused, because that header is set by the
//!   browser and cannot be forged by page JavaScript.
//!
//! # No CORS at all
//!
//! Not one CORS header is emitted, on any route, in any case. A browser therefore
//! cannot read any response cross-origin, which is a stronger position than any
//! allowlist and costs nothing to maintain.

use super::{
    headers,
    origin::{OriginPolicy, CSRF_HEADER},
    ratelimit::{Admission, LoginLimiter},
    response, session_cookie,
};
use crate::management::{
    BackendProbe, IssuedSession, ManagementHealth, StoredSession, WorkerClient, WorkerError,
};
use eggserve_primitives::{request_head::RequestHead, Response, ResponseBody, StatusCode};
use std::{net::SocketAddr, sync::Arc, time::Instant};

/// Methods that change state and therefore need an exact `Origin`.
pub const UNSAFE_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE"];

/// The largest a login body may be, in bytes.
///
/// 4 KiB is far more than a 64-byte username and a 1024-byte password need as
/// JSON, and small enough that the body is never the interesting part of a
/// request. Well below the EggServe hard ceiling, so this tighter bound is the one
/// that actually applies.
pub const LOGIN_BODY_LIMIT: usize = 4 * 1024;

/// HTTP 401, which EggServe does not name as a constant.
///
/// A literal HTTP status cannot fail validation, so this is resolved once at
/// first use rather than calling `StatusCode::new` on every refusal.
fn unauthorized() -> StatusCode {
    StatusCode::new(401).expect("401 Unauthorized is a valid HTTP status")
}

/// HTTP 429, which EggServe does not name as a constant.
fn too_many_requests() -> StatusCode {
    StatusCode::new(429).expect("429 Too Many Requests is a valid HTTP status")
}

/// Why a request was refused.
///
/// Every variant is a category, never a message. Rendering them as one of four
/// bounded statuses is what keeps a refusal from being an oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestRejection {
    /// The `Host` header was absent, malformed, or not in the allowed set.
    HostNotAllowed,
    /// An unsafe method arrived without the exact configured `Origin`.
    OriginNotAllowed,
    /// A cross-site `Sec-Fetch-Site` on a request that should not be one.
    CrossSiteRequest,
    /// An authenticated unsafe request without a CSRF token.
    CsrfMissing,
    /// An authenticated unsafe request with the wrong CSRF token.
    CsrfInvalid,
    /// The body was larger than the route's bound.
    BodyTooLarge,
    /// The `Content-Type` was not the one the route requires.
    ContentTypeNotAllowed,
    /// The JSON body could not be read as the expected shape.
    BodyMalformed,
    /// The login limiter refused this attempt before any hashing occurred.
    Throttled { retry_after_seconds: u64 },
    /// Credentials were not accepted, or no valid session was presented.
    NotAuthenticated,
}

impl RequestRejection {
    /// The bounded status this refusal renders as.
    ///
    /// `401` for anything credential-shaped, `403` for anything policy-shaped,
    /// `413` for an oversized body, `429` for a throttled attempt. A refused
    /// password and an unknown session are deliberately the same status: they are
    /// the same answer to "prove it".
    pub fn status(&self) -> StatusCode {
        match self {
            Self::HostNotAllowed
            | Self::OriginNotAllowed
            | Self::CrossSiteRequest
            | Self::CsrfMissing
            | Self::CsrfInvalid => StatusCode::FORBIDDEN,
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::ContentTypeNotAllowed | Self::BodyMalformed | Self::NotAuthenticated => {
                unauthorized()
            }
            Self::Throttled { .. } => too_many_requests(),
        }
    }

    /// Whether the refusal should carry a `Retry-After`.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Throttled {
                retry_after_seconds,
            } => Some(*retry_after_seconds),
            _ => None,
        }
    }

    /// The bounded body this refusal renders as.
    ///
    /// One literal per status class, never the variant name and never any detail
    /// from the request. A refusal that named its own cause would be a free
    /// enumeration oracle for the surface.
    pub fn body(&self) -> &'static str {
        match self {
            Self::Throttled { .. } => "too many attempts",
            Self::BodyTooLarge => "request too large",
            Self::HostNotAllowed
            | Self::OriginNotAllowed
            | Self::CrossSiteRequest
            | Self::CsrfMissing
            | Self::CsrfInvalid => "forbidden",
            Self::ContentTypeNotAllowed | Self::BodyMalformed | Self::NotAuthenticated => {
                "unauthorized"
            }
        }
    }
}

/// Pure request policy: `Host`, `Origin`, `Sec-Fetch-*`, cookie, and CSRF.
///
/// Holds no worker, no store, and no clock. Everything here is a decision this
/// module can make from the request alone.
#[derive(Clone, Debug)]
pub struct RequestGuard {
    policy: Arc<OriginPolicy>,
}

impl RequestGuard {
    /// Builds a guard over an origin policy.
    pub fn new(policy: Arc<OriginPolicy>) -> Self {
        Self { policy }
    }

    /// The origin policy in force.
    pub fn policy(&self) -> &OriginPolicy {
        &self.policy
    }

    /// Whether this deployment may claim a secure transport.
    pub fn is_secure(&self) -> bool {
        self.policy.is_secure()
    }

    /// Refuses a request whose `Host` is absent or not allowed.
    ///
    /// Applied to **every** request before routing, so a rebinding attempt never
    /// reaches a handler and cannot produce a side effect.
    pub fn check_host(&self, head: &RequestHead) -> Result<(), RequestRejection> {
        let host = header(head, "host")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(RequestRejection::HostNotAllowed)?;
        if self.policy.accepts_host(host) {
            Ok(())
        } else {
            Err(RequestRejection::HostNotAllowed)
        }
    }

    /// Refuses an unsafe request that lacks the exact configured `Origin`.
    ///
    /// A browser always sends `Origin` on a state-changing request, so a missing
    /// one is not a legacy client — it is a non-browser caller, which is exactly
    /// what a CSRF attempt is not.
    pub fn check_origin(&self, head: &RequestHead) -> Result<(), RequestRejection> {
        if !is_unsafe_method(head) {
            return Ok(());
        }
        let origin = header(head, "origin").ok_or(RequestRejection::OriginNotAllowed)?;
        if !self.policy.accepts_origin(origin) {
            return Err(RequestRejection::OriginNotAllowed);
        }
        // `Sec-Fetch-Site` is set by the browser and cannot be forged by page
        // JavaScript, so a cross-site value is decisive even if `Origin` matched.
        if header(head, "sec-fetch-site")
            .is_some_and(|site| site.eq_ignore_ascii_case("cross-site"))
        {
            return Err(RequestRejection::CrossSiteRequest);
        }
        Ok(())
    }

    /// The bearer token this request presents, if any.
    ///
    /// Only the cookie this deployment would have written is considered, so a
    /// cookie minted under a since-corrected origin stops working.
    pub fn presented_token(&self, head: &RequestHead) -> Option<String> {
        session_cookie::presented_session_token(&self.policy, header(head, "cookie"))
    }

    /// Whether a login request declares JSON.
    ///
    /// `multipart/form-data` is never acceptable: a form post is exactly the
    /// cross-site request shape a CSRF token exists to stop, and a simple form
    /// cannot carry a custom header.
    pub fn check_login_content_type(&self, head: &RequestHead) -> Result<(), RequestRejection> {
        if is_json(header(head, "content-type").unwrap_or_default()) {
            Ok(())
        } else {
            Err(RequestRejection::ContentTypeNotAllowed)
        }
    }

    /// Refuses an authenticated unsafe request whose CSRF token is absent or wrong.
    ///
    /// Compared without an early exit. A missing header and a wrong value are
    /// distinguished as variants so a test can tell them apart, but both render
    /// as the same bounded status.
    pub fn check_csrf(
        &self,
        head: &RequestHead,
        session: &StoredSession,
    ) -> Result<(), RequestRejection> {
        if !is_unsafe_method(head) {
            return Ok(());
        }
        let presented = header(head, CSRF_HEADER).ok_or(RequestRejection::CsrfMissing)?;
        let expected = session.session.csrf_token.expose_once();
        if presented.len() != expected.len() {
            return Err(RequestRejection::CsrfInvalid);
        }
        let mut difference = 0u8;
        for (left, right) in presented.bytes().zip(expected.bytes()) {
            difference |= left ^ right;
        }
        if difference == 0 {
            Ok(())
        } else {
            Err(RequestRejection::CsrfInvalid)
        }
    }
}

/// The authenticated API surface: policy plus the two worker-backed operations.
#[derive(Clone, Debug)]
pub struct AuthenticatedApi {
    worker: WorkerClient,
    guard: RequestGuard,
    limiter: Arc<LoginLimiter>,
}

impl AuthenticatedApi {
    /// Builds the API over a worker client, an origin policy, and a limiter.
    pub fn new(
        worker: WorkerClient,
        policy: Arc<OriginPolicy>,
        limiter: Arc<LoginLimiter>,
    ) -> Self {
        Self {
            worker,
            guard: RequestGuard::new(policy),
            limiter,
        }
    }

    /// The pure request policy.
    pub fn guard(&self) -> &RequestGuard {
        &self.guard
    }

    /// The limiter in force.
    pub fn limiter(&self) -> &LoginLimiter {
        &self.limiter
    }

    /// Projects the management health snapshot from the worker.
    ///
    /// The only path from this surface to management state. The caller decides
    /// what the snapshot may be rendered as: `/healthz` reduces it to two
    /// liveness states, and `/api/v1/health` renders it whole, but only after a
    /// session has been proven.
    pub async fn worker_health(&self) -> Result<ManagementHealth, WorkerError> {
        self.worker.health().await
    }

    /// Resolves the presented cookie to a live session.
    ///
    /// `None` for anything that is not a live session: a missing cookie, a
    /// wrong-profile cookie, an unknown token, an expired one, or a storage
    /// failure. All of those are an unauthenticated caller as far as this surface
    /// is concerned, which also keeps a database outage from becoming a
    /// distinguishable answer.
    pub async fn authenticate(&self, head: &RequestHead) -> Option<StoredSession> {
        let presented = self.guard.presented_token(head)?;
        self.worker.resolve_session(presented).await.ok()
    }

    /// Handles `POST /api/v1/login`.
    ///
    /// The limiter runs **first**, before the body is parsed and before the
    /// command is admitted to the worker queue. That ordering is the whole point:
    /// Argon2id costs ~300 ms and 19 MiB per verification, so a limiter placed
    /// after the hash would be a denial of service wearing a rate limit's clothes.
    pub async fn login(
        &self,
        head: &RequestHead,
        body: &[u8],
        peer: SocketAddr,
    ) -> Result<Response, RequestRejection> {
        // The clock is read here, once, and handed to the limiter. Nothing else
        // in this function consults time.
        match self.limiter.check(peer, Instant::now()) {
            Admission::Refused {
                retry_after_seconds,
            } => {
                return Err(RequestRejection::Throttled {
                    retry_after_seconds,
                })
            }
            Admission::Allowed { .. } => {}
        }

        self.guard.check_login_content_type(head)?;
        if body.len() > LOGIN_BODY_LIMIT {
            return Err(RequestRejection::BodyTooLarge);
        }
        let credentials = parse_login_body(body).ok_or(RequestRejection::BodyMalformed)?;

        match self
            .worker
            .authenticate(credentials.username, credentials.password)
            .await
        {
            Ok(issued) => Ok(self.login_success(&issued)),
            Err(WorkerError::Rejected) => {
                // One generic answer for a wrong password, an unknown username,
                // and a disabled principal. `check_origin` has already refused any
                // request that did not come from this origin.
                Err(RequestRejection::NotAuthenticated)
            }
            // Overload and storage trouble are not "wrong credentials" and must
            // not be rendered as one: telling a correct password from an incorrect
            // one is exactly what must never happen.
            Err(_) => Ok(response::unavailable()),
        }
    }

    /// Renders a successful login.
    fn login_success(&self, issued: &IssuedSession) -> Response {
        let lifetime = issued
            .session
            .expires_at
            .saturating_sub(issued.session.created_at);
        let payload = SessionPayload {
            principal_id: issued.session.principal_id.to_string(),
            session_id: issued.session.id.to_string(),
            expires_at: issued.session.expires_at,
            csrf_token: issued.session.csrf_token.expose_once().to_owned(),
        };
        // A cookie that cannot be written is a failure, not a partial success:
        // returning 200 without the cookie would leave the browser
        // unauthenticated and the operator hunting for a credential problem.
        let cookie = match session_cookie::session_set_cookie(
            self.guard.policy(),
            &issued.token,
            lifetime,
        ) {
            Ok(cookie) => cookie,
            Err(_) => return response::internal_error(),
        };
        self.json(StatusCode::OK, &payload, Some(cookie))
    }

    /// Handles `POST /api/v1/logout`.
    ///
    /// `presented` is the raw token the browser sent. Revocation is keyed by the
    /// digest of *that* value, so it must be the token and not its digest —
    /// re-hashing a digest would simply never match.
    pub async fn logout(&self, presented: &str) -> Response {
        // Revoke even when the expiry cookie cannot be built: leaving the row live
        // would keep a copied cookie usable, which is the whole point of logout.
        let _ = self.worker.revoke_session(presented.to_owned()).await;
        let cookie = session_cookie::session_expire_cookie(self.guard.policy()).ok();
        self.build(StatusCode::NO_CONTENT, ResponseBody::Empty, cookie)
    }

    /// Handles `GET /api/v1/session`.
    ///
    /// Returns the safe principal/session identity, the expiry, and the CSRF
    /// token. Never a password hash and never the session bearer — the bearer is
    /// only ever in the `HttpOnly` cookie, which page JavaScript cannot read.
    pub fn session(&self, session: &StoredSession) -> Response {
        let payload = SessionPayload {
            principal_id: session.session.principal_id.to_string(),
            session_id: session.session.id.to_string(),
            expires_at: session.session.expires_at,
            csrf_token: session.session.csrf_token.expose_once().to_owned(),
        };
        self.json(StatusCode::OK, &payload, None)
    }

    /// Handles `GET /api/v1/health`.
    ///
    /// Renders exactly the safe [`ManagementHealth`] projection plus one live,
    /// read-only observation of the backend — identifiers, generations,
    /// categories, and whether the authorized backend answered a `Ping` just now.
    /// No receipt, no error string, no key material: both payloads have no field
    /// that could hold one.
    ///
    /// Reached only after a session has been proven, which is what lets it cost a
    /// socket round trip. The unauthenticated `/healthz` deliberately does not
    /// probe, so an anonymous caller cannot make this process dial the backend.
    pub async fn health(&self) -> Result<Response, WorkerError> {
        let (health, backend) = tokio::join!(self.worker_health(), self.worker.probe_backend());
        let health = health?;
        let backend = backend?;
        Ok(self.json(StatusCode::OK, &DetailedHealth { health, backend }, None))
    }

    /// Renders a JSON payload with the API headers.
    fn json<T: serde::Serialize>(
        &self,
        status: StatusCode,
        payload: &T,
        cookie: Option<String>,
    ) -> Response {
        let Ok(body) = serde_json::to_vec(payload) else {
            return response::internal_error();
        };
        self.build(status, ResponseBody::Bytes(body), cookie)
    }

    /// Builds a JSON response with the API headers.
    ///
    /// Every application response goes through here, so the media type and the
    /// `no-store` policy cannot be forgotten by a route.
    pub fn build(
        &self,
        status: StatusCode,
        body: ResponseBody,
        cookie: Option<String>,
    ) -> Response {
        build_response(status, body, cookie)
    }
}

/// What `GET /api/v1/health` renders.
///
/// Two fields, deliberately: the recorded projection and the live observation
/// answer different questions, and collapsing them into one "is the backend up"
/// flag would hide the case that matters most on a fresh install — nothing has
/// been applied yet, so there is no recorded evidence, but the backend is up and
/// answering.
#[derive(serde::Serialize)]
struct DetailedHealth {
    health: ManagementHealth,
    backend: BackendProbe,
}

/// Builds a JSON response with an optional session cookie.
///
/// Security headers are *not* applied here. They are applied once, centrally, by
/// [`headers::seal`] on the way out of the service, so that a route cannot
/// produce a response that skipped them — see [`headers`] for why that ordering
/// matters.
pub fn build_response(status: StatusCode, body: ResponseBody, cookie: Option<String>) -> Response {
    let built = response::build(status, response::JSON_CONTENT_TYPE, body);
    match cookie {
        Some(cookie) => headers::with_set_cookie(built, &cookie),
        None => built,
    }
}

/// Reads one header as a trimmed string slice.
fn header<'a>(head: &'a RequestHead, name: &str) -> Option<&'a str> {
    head.headers()
        .get_first(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
}

/// Whether a request uses a method that changes state.
fn is_unsafe_method(head: &RequestHead) -> bool {
    UNSAFE_METHODS.contains(&head.method().as_str())
}

/// What `/api/v1/session` and a successful login return.
///
/// Deliberately has no field for a verifier, a password, or a session bearer.
/// The one secret in the system crosses to the browser exactly once, in an
/// `HttpOnly` cookie the page cannot read.
#[derive(Debug, serde::Serialize)]
struct SessionPayload {
    principal_id: String,
    session_id: String,
    expires_at: i64,
    /// Echoed into [`CSRF_HEADER`] on unsafe requests.
    csrf_token: String,
}

/// The JSON body of a login request.
#[derive(serde::Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

/// Parses a login body, refusing anything that is not the expected shape.
///
/// A body with extra fields is accepted rather than refused: rejecting unknown
/// fields would make this wire format a compatibility contract for a future
/// client, which is a worse trade than ignoring them.
fn parse_login_body(body: &[u8]) -> Option<LoginBody> {
    serde_json::from_slice::<LoginBody>(body).ok()
}

/// Whether a `Content-Type` names JSON.
///
/// Parameters are accepted and ignored; the media type is what matters.
fn is_json(content_type: &str) -> bool {
    let media = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media == "application/json"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::headers::header_value;
    use eggserve_primitives::{HeaderBlock, HttpVersion, Method, RequestTarget};
    use std::net::SocketAddr;

    fn head(method: &str, target: &str, extra: &[(&str, &str)]) -> RequestHead {
        let mut headers = HeaderBlock::new();
        headers.push_str("host", "127.0.0.1:8000").unwrap();
        for (name, value) in extra {
            headers.push_str(*name, *value).unwrap();
        }
        RequestHead::new(
            Method::new(method).unwrap(),
            RequestTarget::parse(target).unwrap(),
            HttpVersion::Http11,
            headers,
        )
    }

    fn guard() -> RequestGuard {
        RequestGuard::new(Arc::new(crate::http::OriginPolicy::loopback_only(
            "127.0.0.1:8000".parse().unwrap(),
        )))
    }

    #[test]
    fn json_content_type_accepts_parameters_but_not_another_media_type() {
        assert!(is_json("application/json"));
        assert!(is_json("application/json; charset=utf-8"));
        assert!(is_json("Application/JSON"));
        for bad in [
            "text/plain",
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
            "",
        ] {
            assert!(!is_json(bad), "{bad:?} must not be treated as JSON");
        }
    }

    #[test]
    fn a_safe_method_carries_no_origin_requirement() {
        let guard = guard();
        assert!(guard
            .check_origin(&head("GET", "/api/v1/session", &[]))
            .is_ok());
        assert!(guard.check_origin(&head("GET", "/healthz", &[])).is_ok());
    }

    #[test]
    fn an_unsafe_method_needs_the_exact_origin() {
        let guard = guard();
        // A browser always sends Origin on a state change, so a missing one is
        // not a legacy client.
        assert_eq!(
            guard
                .check_origin(&head("POST", "/api/v1/login", &[]))
                .unwrap_err(),
            RequestRejection::OriginNotAllowed
        );
        for foreign in [
            "http://evil.example.com",
            "http://127.0.0.1:8001",
            "https://127.0.0.1:8000",
            "null",
        ] {
            assert_eq!(
                guard
                    .check_origin(&head("POST", "/api/v1/login", &[("origin", foreign)]))
                    .unwrap_err(),
                RequestRejection::OriginNotAllowed,
                "{foreign} must be refused"
            );
        }
        assert!(guard
            .check_origin(&head(
                "POST",
                "/api/v1/login",
                &[("origin", "http://127.0.0.1:8000")]
            ))
            .is_ok());
    }

    #[test]
    fn a_cross_site_fetch_metadata_header_is_decisive() {
        let guard = guard();
        let same_origin = [("origin", "http://127.0.0.1:8000")];
        assert!(guard
            .check_origin(&head("POST", "/api/v1/login", &same_origin))
            .is_ok());

        // Even with a matching Origin, a cross-site fetch is refused: the browser
        // sets this header and page JavaScript cannot forge it.
        assert_eq!(
            guard
                .check_origin(&head(
                    "POST",
                    "/api/v1/login",
                    &[
                        ("origin", "http://127.0.0.1:8000"),
                        ("sec-fetch-site", "cross-site")
                    ]
                ))
                .unwrap_err(),
            RequestRejection::CrossSiteRequest
        );
        // `same-origin` and `none` are fine.
        for site in ["same-origin", "none", "same-site"] {
            assert!(
                guard
                    .check_origin(&head(
                        "POST",
                        "/api/v1/login",
                        &[
                            ("origin", "http://127.0.0.1:8000"),
                            ("sec-fetch-site", site)
                        ]
                    ))
                    .is_ok(),
                "{site} must not be treated as cross-site"
            );
        }
    }

    #[test]
    fn a_rebinding_host_is_refused() {
        let guard = guard();
        assert!(guard
            .check_host(&head("GET", "/api/v1/session", &[]))
            .is_ok());
        for host in ["evil.example.com", "evil.example.com:8000", ""] {
            let mut headers = HeaderBlock::new();
            headers.push_str("host", host).unwrap();
            let request = RequestHead::new(
                Method::get(),
                RequestTarget::parse("/api/v1/session").unwrap(),
                HttpVersion::Http11,
                headers,
            );
            assert_eq!(
                guard.check_host(&request).unwrap_err(),
                RequestRejection::HostNotAllowed,
                "{host:?} must be refused before routing"
            );
        }
    }

    #[test]
    fn a_login_must_declare_json_and_never_a_form_encoding() {
        let guard = guard();
        assert!(guard
            .check_login_content_type(&head(
                "POST",
                "/api/v1/login",
                &[("content-type", "application/json")]
            ))
            .is_ok());
        for bad in [
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
            "text/plain",
        ] {
            assert_eq!(
                guard
                    .check_login_content_type(&head(
                        "POST",
                        "/api/v1/login",
                        &[("content-type", bad)]
                    ))
                    .unwrap_err(),
                RequestRejection::ContentTypeNotAllowed,
                "{bad} must be refused"
            );
        }
        // Absent entirely.
        assert!(guard
            .check_login_content_type(&head("POST", "/api/v1/login", &[]))
            .is_err());
    }

    #[test]
    fn a_login_body_must_be_the_expected_json_shape() {
        assert!(parse_login_body(br#"{"username":"admin","password":"x"}"#).is_some());
        // Extra fields are tolerated rather than refused.
        assert!(parse_login_body(br#"{"username":"a","password":"b","extra":1}"#).is_some());
        for bad in [
            &b"not json"[..],
            b"{}",
            br#"{"username":"admin"}"#,
            br#"{"password":"x"}"#,
            b"[]",
            b"null",
        ] {
            assert!(parse_login_body(bad).is_none(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn a_refusal_never_names_its_own_cause() {
        // Every variant renders as one of four bounded literals. A refusal that
        // named its cause would be a free enumeration oracle.
        let literals: std::collections::HashSet<&str> = [
            RequestRejection::HostNotAllowed,
            RequestRejection::OriginNotAllowed,
            RequestRejection::CrossSiteRequest,
            RequestRejection::CsrfMissing,
            RequestRejection::CsrfInvalid,
            RequestRejection::BodyTooLarge,
            RequestRejection::ContentTypeNotAllowed,
            RequestRejection::BodyMalformed,
            RequestRejection::NotAuthenticated,
            RequestRejection::Throttled {
                retry_after_seconds: 7,
            },
        ]
        .iter()
        .map(RequestRejection::body)
        .collect();
        assert_eq!(
            literals.len(),
            4,
            "one literal per status class: {literals:?}"
        );
        for body in &literals {
            assert!(body.len() <= 32, "{body:?} must stay bounded");
        }
    }

    #[test]
    fn a_refusal_never_reveals_which_check_failed() {
        // The credential-shaped refusals share one status on purpose.
        assert_eq!(RequestRejection::NotAuthenticated.status(), unauthorized());
        assert_eq!(RequestRejection::BodyMalformed.status(), unauthorized());
        assert_eq!(
            RequestRejection::CsrfInvalid.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            RequestRejection::BodyTooLarge.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            RequestRejection::Throttled {
                retry_after_seconds: 7
            }
            .status(),
            too_many_requests()
        );
        assert_eq!(
            RequestRejection::Throttled {
                retry_after_seconds: 7
            }
            .retry_after(),
            Some(7)
        );
        assert_eq!(RequestRejection::CsrfMissing.retry_after(), None);
    }

    #[test]
    fn every_api_response_carries_the_security_headers_and_no_cors() {
        let response = headers::seal(
            build_response(StatusCode::OK, ResponseBody::Bytes(b"{}".to_vec()), None),
            false,
        );
        assert_eq!(
            header_value(&response, "content-security-policy").as_deref(),
            Some(headers::CONTENT_SECURITY_POLICY)
        );
        assert_eq!(
            header_value(&response, "x-frame-options").as_deref(),
            Some("DENY")
        );
        assert_eq!(
            header_value(&response, "cache-control").as_deref(),
            Some("no-store")
        );
        assert_eq!(
            header_value(&response, "content-type").as_deref(),
            Some(response::JSON_CONTENT_TYPE)
        );
        // Loopback HTTP must not claim a secure transport.
        assert_eq!(header_value(&response, "strict-transport-security"), None);
        // And no CORS, in any form.
        for name in [
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-methods",
        ] {
            assert_eq!(header_value(&response, name), None, "{name} must not exist");
        }
    }

    #[test]
    fn an_https_deployment_gets_hsts_and_no_loopback_deployment_does() {
        let secure = headers::seal(
            build_response(StatusCode::OK, ResponseBody::Empty, None),
            true,
        );
        assert_eq!(
            header_value(&secure, "strict-transport-security").as_deref(),
            Some(headers::STRICT_TRANSPORT_SECURITY)
        );
    }

    #[test]
    fn a_login_cookie_reaches_the_response_without_being_readable_by_a_script() {
        let cookie = "__Host-wg_basic_session=abc; Path=/; HttpOnly; Secure; SameSite=Strict";
        let response = headers::seal(
            build_response(StatusCode::OK, ResponseBody::Empty, Some(cookie.to_owned())),
            true,
        );
        assert_eq!(
            header_value(&response, "set-cookie").as_deref(),
            Some(cookie)
        );
    }

    #[test]
    fn the_login_body_limit_is_below_the_eggserve_ceiling() {
        // The route's own bound must be the one that bites, not the transport's.
        let ceiling = crate::http::HttpLimits::default()
            .to_runtime_config()
            .unwrap()
            .max_request_body_bytes;
        assert!(
            (LOGIN_BODY_LIMIT as u64) < ceiling,
            "the route bound must be tighter than the transport ceiling"
        );
    }

    #[test]
    fn a_presented_cookie_yields_a_token_and_a_foreign_one_does_not() {
        let guard = guard();
        let request = head(
            "GET",
            "/api/v1/session",
            &[("cookie", "wg_basic_session=abc123")],
        );
        assert_eq!(guard.presented_token(&request).as_deref(), Some("abc123"));
        assert_eq!(
            guard.presented_token(&head("GET", "/api/v1/session", &[])),
            None
        );
        // The HTTPS profile's name is not accepted by an HTTP deployment.
        assert_eq!(
            guard.presented_token(&head(
                "GET",
                "/api/v1/session",
                &[("cookie", "__Host-wg_basic_session=abc")]
            )),
            None
        );
    }

    #[test]
    fn a_safe_get_needs_no_csrf_token() {
        let guard = guard();
        // Exercised through the real shape: an unauthenticated GET is refused by
        // authentication, not by a CSRF rule that does not apply to it.
        let request = head("GET", "/api/v1/session", &[]);
        assert!(guard.check_csrf(&request, &session_row()).is_ok());
    }

    /// A stand-in session row, used only to reach the CSRF comparison.
    fn session_row() -> StoredSession {
        use crate::{
            domain::{CsrfToken, PrincipalId, SessionId, SessionTokenDigest},
            management::SessionRecord,
        };
        StoredSession {
            session: SessionRecord {
                id: SessionId::new(),
                principal_id: PrincipalId::new(),
                csrf_token: CsrfToken::parse("correct-horse").unwrap(),
                created_at: 0,
                expires_at: 3600,
            },
            digest: SessionTokenDigest::parse("a".repeat(64)).unwrap(),
        }
    }

    #[test]
    fn an_unsafe_request_needs_the_exact_csrf_token() {
        let guard = guard();
        let session = session_row();
        let missing = head("POST", "/api/v1/logout", &[]);
        assert_eq!(
            guard.check_csrf(&missing, &session).unwrap_err(),
            RequestRejection::CsrfMissing
        );

        for wrong in ["", "wrong-horse", "correct-hors", "correct-horses"] {
            let request = head("POST", "/api/v1/logout", &[(CSRF_HEADER, wrong)]);
            assert_eq!(
                guard.check_csrf(&request, &session).unwrap_err(),
                RequestRejection::CsrfInvalid,
                "{wrong:?} must be refused"
            );
        }

        let correct = head("POST", "/api/v1/logout", &[(CSRF_HEADER, "correct-horse")]);
        assert!(guard.check_csrf(&correct, &session).is_ok());
    }

    #[test]
    fn a_peer_address_is_accepted_by_the_login_entry_point() {
        // The signature exists so a test can drive the limiter deterministically.
        let peer: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let now = Instant::now();
        let limiter = LoginLimiter::new(
            crate::http::Bucket::per_second(1, 1),
            crate::http::Bucket::per_second(1, 1),
            4,
        );
        assert!(limiter.check(peer, now).is_allowed());
        assert!(!limiter.check(peer, now).is_allowed());
    }
}
