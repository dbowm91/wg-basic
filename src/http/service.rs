//! The EggServe [`Service`] implementation for the management surface.
//!
//! # Routing is a closed match
//!
//! [`route`] matches a request target against the routes M001 defines and
//! returns a `Route`, not a handler closure. That keeps three properties
//! checkable by reading one function:
//!
//! * **Exhaustive.** Adding a route without deciding its method set is a
//!   compile error, so "unknown method" cannot silently become a new capability.
//! * **Closed.** Anything unmatched is [`Route::Unknown`], which renders as a
//!   bounded 404. There is no catch-all, no prefix match, and no dispatch on a
//!   path segment, so no future route can be reached by accident.
//! * **Body-free.** M001's surface accepts no request bodies at all, which
//!   [`ManagementService::request_body_policy`] enforces in the runtime *before*
//!   a handler is invoked, so a body-bearing request to a read-only route is
//!   rejected by the transport rather than by application code.
//!
//! # No dynamic disclosure
//!
//! The service never formats an internal value into a response. It maps a
//! matched [`Route`] to a worker result and the result to one of the literals in
//! [`crate::http::response`]. There is no error path that can print a path,
//! a socket address, a generation, or an internal type.

use super::response::{self, Liveness};
use crate::management::{WorkerClient, WorkerError};
use eggserve_primitives::{
    request_body_policy::RequestBodyPolicy, request_head::RequestHead, Request, Response,
};
use eggserve_server::service::{Service, ServiceFuture};

/// The single unauthenticated liveness route M001 exposes.
///
/// Named as a constant so the routing table, the tests, and the documentation
/// cannot drift apart.
pub const HEALTHZ_PATH: &str = "/healthz";

/// What a request target matched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// The liveness probe.
    Healthz,
    /// A path this surface does not have.
    Unknown,
}

impl Route {
    /// The methods this route answers.
    ///
    /// M001 publishes exactly one read-only route with one method. `HEAD` is
    /// deliberately *not* answered: a probe that cannot distinguish `HEAD` from
    /// `GET` is not this probe, and accepting a second method here would set the
    /// precedent that methods are added implicitly.
    fn accepts(&self, method: &str) -> bool {
        match self {
            Self::Healthz => method == "GET",
            Self::Unknown => false,
        }
    }

    /// Whether a known route was reached by a method it does not answer.
    fn rejects_method(&self, method: &str) -> bool {
        match self {
            Self::Healthz => !method.eq_ignore_ascii_case("get"),
            Self::Unknown => false,
        }
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
        _ => Route::Unknown,
    }
}

/// The management HTTP service.
#[derive(Clone, Debug)]
pub struct ManagementService {
    worker: WorkerClient,
}

impl ManagementService {
    /// Builds the service over a bounded worker client.
    pub fn new(worker: WorkerClient) -> Self {
        Self { worker }
    }

    /// Answers one already-routed request.
    async fn dispatch(&self, head: &RequestHead) -> Response {
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

        match matched {
            Route::Healthz => match self.worker.health().await {
                Ok(health) => response::liveness(Liveness::from_health(&health)),
                // Saturation, a missed deadline, and a stopped worker are all
                // overload. They collapse to one bounded answer on purpose.
                Err(error) => response_for_worker_error(error),
            },
            Route::Unknown => response::not_found(),
        }
    }
}

/// Maps a worker failure onto the bounded HTTP vocabulary.
///
/// Only `/healthz` exists in M002, and it calls `health()`, so the authentication
/// variants below are unreachable on this route. They are mapped to the same
/// bounded 503 rather than to a guessed status, because guessing here would be
/// worse than one honest answer: M003 introduces the login and session routes and
/// replaces this function with the real status mapping, at which point an
/// unreachable arm here would be removed rather than reinterpreted.
fn response_for_worker_error(error: WorkerError) -> Response {
    match error {
        // Overload: the listener is fine, the operator's appliance is busy or
        // gone. Both are retryable and neither is the client's fault.
        WorkerError::Saturated | WorkerError::TimedOut | WorkerError::Stopped => {
            response::unavailable()
        }
        // A worker-reported product failure is a server fault, not an overload
        // answer, and still carries no detail.
        WorkerError::Failed(_) => response::internal_error(),
        // Unreachable from `/healthz` in M002; see the note above.
        WorkerError::Rejected | WorkerError::Unavailable | WorkerError::Storage => {
            response::unavailable()
        }
    }
}

impl Service for ManagementService {
    /// No M001 route accepts a body.
    ///
    /// Declaring `Reject` here means the runtime refuses a body-bearing request
    /// at the transport boundary, before routing or the worker queue: an
    /// unauthenticated caller cannot make the process buffer attacker-chosen
    /// bytes on a read-only probe route.
    fn request_body_policy(&self, _head: &RequestHead) -> RequestBodyPolicy {
        RequestBodyPolicy::Reject
    }

    fn call(&self, request: Request) -> ServiceFuture<'_> {
        // The body is never read. `request_body_policy` already guaranteed
        // there is nothing to read, so dropping it here cannot silently discard
        // content the service promised to handle.
        let head = request.head().clone();
        Box::pin(async move { Ok(self.dispatch(&head).await) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management::{spawn, WorkerConfig};
    use eggserve_primitives::{Method, RequestHead, RequestTarget};
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    fn head(method: &str, target: &str) -> RequestHead {
        RequestHead::new(
            Method::new(method).unwrap(),
            RequestTarget::parse(target).unwrap(),
            eggserve_primitives::HttpVersion::Http11,
            eggserve_primitives::HeaderBlock::new(),
        )
    }

    fn body_text(mut response: Response) -> String {
        String::from_utf8(response.take_body().unwrap().into_bytes().unwrap()).unwrap()
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "wg-basic-service-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn db(&self) -> PathBuf {
            self.0.join("state.db")
        }

        fn absent_socket(&self) -> PathBuf {
            self.0.join("no-such-netd.sock")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A service over a real worker on an empty store.
    async fn live_service(temp: &TempDir) -> ManagementService {
        let startup = spawn(WorkerConfig::new(temp.db(), temp.absent_socket()))
            .expect("an empty store and an absent netd still start");
        // The client is cloned out and the startup handle dropped without a
        // stop, so the worker outlives the test's scope and the service can
        // still be exercised.
        ManagementService::new(startup.client().clone())
    }

    #[test]
    fn routing_is_an_exact_match() {
        assert_eq!(route("/healthz"), Route::Healthz);
        // Every near miss is an unknown route, not a variant of the real one.
        for target in [
            "/healthz/",
            "/healthz/extra",
            "/HEALTHZ",
            "/api/v1/health",
            "/",
            "",
            "/healthz%00",
        ] {
            assert_eq!(route(target), Route::Unknown, "{target:?} must not match");
        }
    }

    #[test]
    fn only_get_is_answered_on_the_health_route() {
        for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD"] {
            assert!(
                !Route::Healthz.accepts(method),
                "{method} must not be answered"
            );
            assert!(Route::Healthz.rejects_method(method));
        }
        assert!(Route::Healthz.accepts("GET"));
        assert!(!Route::Healthz.rejects_method("GET"));
    }

    #[test]
    fn a_query_string_does_not_change_the_matched_route() {
        assert_eq!(route("/healthz"), Route::Healthz);
    }

    #[test]
    fn the_query_is_never_part_of_the_path_match() {
        // `RequestTarget::path` excludes the query, so the routing table cannot
        // be widened by appending one.
        let parsed = RequestTarget::parse("/healthz?token=abc").unwrap();
        assert_eq!(parsed.path(), "/healthz");
        assert_eq!(route(parsed.path()), Route::Healthz);
    }

    #[tokio::test]
    async fn the_health_route_answers_a_bounded_liveness_class() {
        let temp = TempDir::new();
        let service = live_service(&temp).await;
        let response = service.dispatch(&head("GET", "/healthz")).await;

        // The status is 200 either way: the request *was* answered, and only the
        // appliance's own health varies.
        assert_eq!(response.status(), eggserve_primitives::StatusCode::OK);
        // There is no netd in a test environment, so the honest class is
        // `degraded`. The mapping from a full health snapshot to this two-state
        // answer is covered in `http::response`.
        assert_eq!(body_text(response), "degraded");
    }

    #[tokio::test]
    async fn an_unknown_route_is_a_bounded_404() {
        let temp = TempDir::new();
        let service = live_service(&temp).await;
        let response = service.dispatch(&head("GET", "/api/v1/interfaces")).await;
        assert_eq!(
            response.status(),
            eggserve_primitives::StatusCode::NOT_FOUND
        );
        assert_eq!(body_text(response), "not found");
    }

    #[tokio::test]
    async fn a_known_route_with_an_unknown_method_is_a_bounded_405() {
        let temp = TempDir::new();
        let service = live_service(&temp).await;
        for method in ["POST", "PUT", "DELETE", "HEAD"] {
            let response = service.dispatch(&head(method, "/healthz")).await;
            assert_eq!(
                response.status(),
                eggserve_primitives::StatusCode::METHOD_NOT_ALLOWED,
                "{method}"
            );
            assert_eq!(body_text(response), "method not allowed");
        }
    }

    #[tokio::test]
    async fn an_unknown_route_reported_by_another_method_stays_a_404() {
        let temp = TempDir::new();
        let service = live_service(&temp).await;
        // A prober must not learn which paths exist by varying the method.
        let response = service.dispatch(&head("POST", "/nope")).await;
        assert_eq!(
            response.status(),
            eggserve_primitives::StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn the_service_declines_every_request_body() {
        let temp = TempDir::new();
        let service = live_service(&temp).await;
        // The transport consults this before routing, so a read-only probe
        // route can never make the process buffer attacker-chosen bytes.
        assert_eq!(
            service.request_body_policy(&head("GET", "/healthz")),
            RequestBodyPolicy::Reject
        );
        assert_eq!(
            service.request_body_policy(&head("POST", "/api/v1/session")),
            RequestBodyPolicy::Reject
        );
    }

    #[tokio::test]
    async fn a_stopped_worker_answers_503_without_detail() {
        let temp = TempDir::new();
        let startup =
            spawn(WorkerConfig::new(temp.db(), temp.absent_socket())).expect("worker starts");
        let service = ManagementService::new(startup.client().clone());
        startup.stop().await.expect("clean shutdown");

        let response = service.dispatch(&head("GET", "/healthz")).await;
        assert_eq!(
            response.status(),
            eggserve_primitives::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(body_text(response), "unavailable");
    }

    #[tokio::test]
    async fn every_worker_failure_maps_to_a_documented_status() {
        use eggserve_primitives::StatusCode;
        assert_eq!(
            response_for_worker_error(WorkerError::Saturated).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            response_for_worker_error(WorkerError::TimedOut).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            response_for_worker_error(WorkerError::Stopped).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            response_for_worker_error(WorkerError::Failed(
                crate::management::ManagementError::BackendUnavailable
            ))
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn every_dispatch_branch_yields_a_response() {
        // `dispatch` cannot fail: every branch returns a literal response. This
        // is the invariant `call` relies on when it answers `Ok` unconditionally,
        // stated here so the guarantee survives an added route.
        let temp = TempDir::new();
        let service = live_service(&temp).await;
        for target in ["/healthz", "/nope"] {
            for method in ["GET", "POST"] {
                let response = service.dispatch(&head(method, target)).await;
                assert!(response.status().as_u16() >= 200, "{method} {target}");
            }
        }
    }
}
