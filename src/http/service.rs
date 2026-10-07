//! The EggServe [`Service`] implementation for the management surface.
//!
//! # The request pipeline
//!
//! Every request crosses the same fixed sequence, and the order is the contract:
//!
//! 1. **Body policy** — decided by the transport *before* this service runs, so a
//!    read-only route can never make the process buffer attacker-chosen bytes.
//! 2. **`Host`** — refused unless it is in the configured allowed set. A
//!    rebinding attempt dies here, before routing, so it cannot produce a side
//!    effect on any route.
//! 3. **Route** — an exact path match against a closed enum.
//! 4. **Method** — refused unless the matched route answers it.
//! 5. **`Origin`** — refused for an unsafe method that does not carry the exact
//!    configured origin.
//! 6. **Session and CSRF** — for the authenticated routes.
//! 7. **Handler**.
//!
//! Steps 2 and 5 run before step 7 for every route. That is the point: a
//! security check that only some routes remember to perform is a security check
//! waiting to be forgotten by the next route.
//!
//! # Routing is a closed match
//!
//! [`route`] matches a request target against a closed enum, not a handler
//! closure. That keeps three properties checkable by reading one function:
//!
//! * **Exhaustive.** Adding a route without deciding its method set is a compile
//!   error, so "unknown method" cannot silently become a new capability.
//! * **Closed.** Anything unmatched is [`Route::Unknown`], which renders as a
//!   bounded 404. There is no catch-all, no prefix match, and no dispatch on a
//!   path segment, so no future route can be reached by accident.
//! * **Body-declaring.** A route that accepts a body says so here, and the
//!   transport enforces it. Everything else is refused at the boundary.
//!
//! # No dynamic disclosure
//!
//! The service never formats an internal value into a response body. It maps a
//! matched [`Route`] and a bounded [`RequestRejection`] onto fixed literals, so
//! there is no error path that can print a path, a socket address, a generation,
//! or an internal type.

use super::{
    api::{AuthenticatedApi, RequestRejection, LOGIN_BODY_LIMIT},
    headers,
    response::{self, Liveness},
};
use crate::management::WorkerError;
use eggserve_primitives::{
    request_body_policy::RequestBodyPolicy, request_head::RequestHead, Request, Response,
    ResponseBody,
};
use eggserve_server::service::{Service, ServiceFuture};
use futures_util::StreamExt;
use std::net::SocketAddr;

/// The single unauthenticated liveness route.
///
/// Named as a constant so the routing table, the tests, and the documentation
/// cannot drift apart.
pub const HEALTHZ_PATH: &str = "/healthz";

/// The credential-issuing route.
pub const LOGIN_PATH: &str = "/api/v1/login";

/// The session-revoking route.
pub const LOGOUT_PATH: &str = "/api/v1/logout";

/// The session-introspection route.
pub const SESSION_PATH: &str = "/api/v1/session";

/// The authenticated health route.
pub const API_HEALTH_PATH: &str = "/api/v1/health";

/// What a request target matched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// The unauthenticated liveness probe.
    Healthz,
    /// Credential issuance.
    Login,
    /// Session revocation.
    Logout,
    /// Session introspection.
    Session,
    /// Authenticated management health.
    ApiHealth,
    /// A path this surface does not have.
    Unknown,
}

impl Route {
    /// Whether this route accepts a request body.
    ///
    /// Only login does. Everything else is refused by the transport before this
    /// service runs, so a `GET` route can never be made to buffer bytes.
    pub fn accepts_body(&self) -> bool {
        matches!(self, Self::Login)
    }

    /// The methods this route answers.
    ///
    /// `HEAD` is deliberately *not* answered anywhere: a probe that cannot
    /// distinguish `HEAD` from `GET` is not this probe, and accepting a second
    /// method here would set the precedent that methods are added implicitly.
    fn accepts(&self, method: &str) -> bool {
        match self {
            Self::Healthz | Self::Session | Self::ApiHealth => method == "GET",
            Self::Login | Self::Logout => method == "POST",
            Self::Unknown => false,
        }
    }

    /// Whether a known route was reached by a method it does not answer.
    fn rejects_method(&self, method: &str) -> bool {
        if matches!(self, Self::Unknown) {
            return false;
        }
        !self.accepts(method)
    }
}

/// Resolves a request target to a route.
///
/// Only an exact path match counts. `/healthz/` and `/healthz?x=1`-style
/// suffixes are unknown routes, not near misses, so the surface has no
/// normalisation rules an attacker could lean on.
pub fn route(path: &str) -> Route {
    match path {
        HEALTHZ_PATH => Route::Healthz,
        LOGIN_PATH => Route::Login,
        LOGOUT_PATH => Route::Logout,
        SESSION_PATH => Route::Session,
        API_HEALTH_PATH => Route::ApiHealth,
        _ => Route::Unknown,
    }
}

/// The management HTTP service.
#[derive(Clone, Debug)]
pub struct ManagementService {
    api: AuthenticatedApi,
}

impl ManagementService {
    /// Builds the service over the authenticated API.
    pub fn new(api: AuthenticatedApi) -> Self {
        Self { api }
    }

    /// The origin policy and limiter in force.
    pub fn api(&self) -> &AuthenticatedApi {
        &self.api
    }

    /// Runs the pipeline for one request and seals the answer.
    ///
    /// [`headers::seal`] is applied here, once, on **every** path — success,
    /// refusal, unknown route, and worker failure alike. That is what makes the
    /// security headers total: a [`Response`] does not exist until routing has
    /// chosen one, and it cannot leave this function unsealed.
    async fn dispatch(&self, head: &RequestHead, body: &[u8], peer: SocketAddr) -> Response {
        let answer = self.route_request(head, body, peer).await;
        headers::seal(answer, self.api.guard().is_secure())
    }

    /// Steps 2 through 7 of the pipeline for one request.
    ///
    /// Separated from [`ManagementService::dispatch`] so that the sealing
    /// guarantee has exactly one call site to audit: this function is free to
    /// return early from anywhere, because every early return still goes back
    /// through [`ManagementService::dispatch`].
    async fn route_request(&self, head: &RequestHead, body: &[u8], peer: SocketAddr) -> Response {
        let guard = self.api.guard();

        // 2. Host, before routing, for every request without exception. A
        //    rebinding attempt dies here, so it cannot produce a side effect on
        //    any route — including the ones that change state.
        if let Err(rejection) = guard.check_host(head) {
            return refusal(rejection);
        }

        // 3 and 4. Route and method.
        let matched = route(head.target().path());
        if !matched.accepts(head.method().as_str()) {
            // A known route reached by an unknown method says so; an unknown
            // route stays a 404 so a prober cannot enumerate the surface.
            return if matched.rejects_method(head.method().as_str()) {
                response::method_not_allowed()
            } else {
                response::not_found()
            };
        }

        // 5. Origin, for every unsafe method on every route.
        if let Err(rejection) = guard.check_origin(head) {
            return refusal(rejection);
        }

        // 6 and 7. Session, CSRF, and the handler.
        match matched {
            Route::Healthz => match self.api.worker_health().await {
                Ok(health) => response::liveness(Liveness::from_health(&health)),
                Err(error) => response_for_worker_error(error),
            },
            Route::Login => match self.api.login(head, body, peer).await {
                Ok(response) => response,
                Err(rejection) => refusal(rejection),
            },
            Route::Logout => {
                // Both checks run before anything is revoked. A logout without a
                // CSRF token is an attacker's request, and revoking on it would
                // turn a cross-site request into a working denial of service.
                let Some(session) = self.api.authenticate(head).await else {
                    return refusal(RequestRejection::NotAuthenticated);
                };
                if let Err(rejection) = guard.check_csrf(head, &session) {
                    return refusal(rejection);
                }
                // Keyed by the raw presented token: revocation looks up the
                // digest of exactly this value, so re-hashing would never match.
                let presented = guard
                    .presented_token(head)
                    .expect("authentication resolved only from a presented cookie");
                self.api.logout(&presented).await
            }
            Route::Session => {
                let Some(session) = self.api.authenticate(head).await else {
                    return refusal(RequestRejection::NotAuthenticated);
                };
                self.api.session(&session)
            }
            Route::ApiHealth => {
                if self.api.authenticate(head).await.is_none() {
                    return refusal(RequestRejection::NotAuthenticated);
                }
                match self.api.worker_health().await {
                    Ok(health) => self.api.health(&health),
                    Err(error) => response_for_worker_error(error),
                }
            }
            Route::Unknown => response::not_found(),
        }
    }
}

/// Renders a bounded refusal.
///
/// One literal per status class. The `Retry-After` is the only variable header,
/// and it exists solely so a throttled client knows when to come back.
fn refusal(rejection: RequestRejection) -> Response {
    let built = super::api::build_response(
        rejection.status(),
        ResponseBody::Bytes(rejection.body().as_bytes().to_vec()),
        None,
    );
    match rejection.retry_after() {
        Some(retry_after) => headers::with_retry_after(built, retry_after),
        None => built,
    }
}

/// Maps a worker failure onto the bounded HTTP vocabulary.
///
/// Overload and a stopped worker are retryable and are not the client's fault, so
/// they are one answer. A product failure is a server fault. A refused credential
/// is neither: it renders as `401` through the route's own refusal path and never
/// reaches this function, because the route needs to know that a refusal happened
/// rather than that a command succeeded.
fn response_for_worker_error(error: WorkerError) -> Response {
    match error {
        WorkerError::Saturated | WorkerError::TimedOut | WorkerError::Stopped => {
            response::unavailable()
        }
        WorkerError::Failed(_) => response::internal_error(),
        // A refusal or a storage failure that reached a *read-only* route. The
        // login route renders these itself, because it must distinguish a wrong
        // password from an outage.
        WorkerError::Rejected | WorkerError::Unavailable | WorkerError::Storage => {
            response::unavailable()
        }
    }
}

impl Service for ManagementService {
    /// Only the login route may carry a body.
    ///
    /// The runtime consults this before routing, so a body on any other route is
    /// refused by the transport rather than by application code, and the login
    /// route's own 4 KiB bound is enforced in the route as well as here.
    fn request_body_policy(&self, head: &RequestHead) -> RequestBodyPolicy {
        match route(head.target().path()) {
            matched if matched.accepts_body() => RequestBodyPolicy::Buffer {
                max_bytes: LOGIN_BODY_LIMIT as u64,
            },
            _ => RequestBodyPolicy::Reject,
        }
    }

    fn call(&self, request: Request) -> ServiceFuture<'_> {
        let head = request.head().clone();
        // Observed at accept time by the transport, never derived from a
        // forwarding header. The fallback is unreachable for a TCP listener —
        // EggServe always populates it — and collapses such a request into one
        // shared limiter bucket rather than inventing a per-attacker budget.
        let peer = request
            .connection()
            .remote_addr
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
        let accepts_body = route(head.target().path()).accepts_body();
        let service = self.clone();
        Box::pin(async move {
            // The body is read only for the one route whose body policy allows
            // it. Every other route is `Reject`, so the runtime never hands one
            // bytes to buffer.
            let body = if accepts_body {
                collect_bounded_body(request.into_body(), LOGIN_BODY_LIMIT).await
            } else {
                Vec::new()
            };
            Ok(service.dispatch(&head, &body, peer).await)
        })
    }
}

/// Reads at most `limit` bytes from a request body.
///
/// Stops at the limit rather than truncating, so a client that sends more than
/// the route allows is refused for sending too much instead of having its request
/// silently shortened into something it did not send.
async fn collect_bounded_body(mut body: eggserve_primitives::RequestBody, limit: usize) -> Vec<u8> {
    let mut collected = Vec::new();
    while let Some(chunk) = body.next().await {
        let Ok(chunk) = chunk else {
            // A transport error mid-body is indistinguishable from an empty body
            // to the route, which will refuse it as malformed.
            break;
        };
        if collected.len().saturating_add(chunk.len()) > limit {
            // Pad to exactly the limit so the route's own bound is the one that
            // rejects it. Truncating below the limit would turn an oversized
            // request into a well-formed smaller one.
            collected.resize(limit, 0);
            return collected;
        }
        collected.extend_from_slice(&chunk);
    }
    collected
}

#[cfg(test)]
mod tests {
    use super::*;
    use eggserve_primitives::StatusCode;

    #[test]
    fn routing_is_an_exact_match_over_a_closed_set() {
        assert_eq!(route("/healthz"), Route::Healthz);
        assert_eq!(route("/api/v1/login"), Route::Login);
        assert_eq!(route("/api/v1/logout"), Route::Logout);
        assert_eq!(route("/api/v1/session"), Route::Session);
        assert_eq!(route("/api/v1/health"), Route::ApiHealth);

        for target in [
            "/",
            "",
            "/healthz/",
            "/api/v1/",
            "/api/v1",
            "/api/v1/login/",
            "/api/v1/peers",
            "/api/v1/clients",
            "/api/v1/interfaces",
            "/API/V1/LOGIN",
            "/api/v1/login%00",
            "/api/v2/login",
        ] {
            assert_eq!(route(target), Route::Unknown, "{target:?} must not match");
        }
    }

    #[test]
    fn only_login_accepts_a_body() {
        // Phase 8 owns the configuration routes; this is the whole body-accepting
        // surface today.
        assert!(Route::Login.accepts_body());
        for matched in [
            Route::Healthz,
            Route::Logout,
            Route::Session,
            Route::ApiHealth,
            Route::Unknown,
        ] {
            assert!(!matched.accepts_body(), "{matched:?} must accept no body");
        }
    }

    #[test]
    fn each_route_answers_exactly_one_method() {
        assert!(Route::Healthz.accepts("GET"));
        assert!(Route::Session.accepts("GET"));
        assert!(Route::ApiHealth.accepts("GET"));
        assert!(Route::Login.accepts("POST"));
        assert!(Route::Logout.accepts("POST"));

        // HEAD is answered nowhere, so a prober cannot use it to read a body it
        // was not allowed a GET for.
        for matched in [
            Route::Healthz,
            Route::Session,
            Route::ApiHealth,
            Route::Login,
            Route::Logout,
        ] {
            assert!(!matched.accepts("HEAD"), "{matched:?} must refuse HEAD");
        }
        // A known route with the wrong method is distinguishable from an unknown
        // route, which stays a 404 so the surface cannot be enumerated.
        assert!(Route::Healthz.rejects_method("POST"));
        assert!(!Route::Unknown.rejects_method("POST"));
        assert!(!Route::Unknown.accepts("GET"));
    }

    #[test]
    fn the_surface_publishes_no_phase_8_configuration_route() {
        // Proof that this milestone added authentication and not peer/client
        // management, which Phase 8 owns.
        for target in [
            "/api/v1/peers",
            "/api/v1/clients",
            "/api/v1/interfaces",
            "/api/v1/network-policy",
        ] {
            assert_eq!(route(target), Route::Unknown, "{target} must not exist yet");
        }
    }

    #[test]
    fn a_refusal_renders_one_of_four_bounded_literals() {
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
                retry_after_seconds: 1,
            },
        ]
        .iter()
        .map(RequestRejection::body)
        .collect();
        assert_eq!(literals.len(), 4, "{literals:?}");
    }

    #[test]
    fn status_selection_matches_the_documented_vocabulary() {
        assert_eq!(
            RequestRejection::NotAuthenticated.status().as_u16(),
            401,
            "an unauthenticated caller is 401"
        );
        assert_eq!(
            RequestRejection::CsrfInvalid.status().as_u16(),
            403,
            "a policy refusal is 403"
        );
        assert_eq!(
            RequestRejection::BodyTooLarge.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            RequestRejection::Throttled {
                retry_after_seconds: 3
            }
            .status()
            .as_u16(),
            429,
            "a throttled attempt is 429, so a client can distinguish it and back off"
        );
    }
}
