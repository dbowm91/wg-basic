//! Bounded response construction for the management surface.
//!
//! # Why every body is a literal
//!
//! An administration surface is probed by people who are not the operator. If
//! an error path formats an internal type, a [`std::io::Error`], a filesystem
//! path, or a [`ManagementError`] into a response body, it has built an
//! information-disclosure bug rather than a debug message. So this module
//! exposes a closed set of fixed-literal bodies and no formatting hook at all:
//! there is no way to pass a dynamic string into one.
//!
//! The service layer therefore cannot leak by accident. Its only remaining job
//! is to choose *which* literal to use.

use eggserve_primitives::{Response, ResponseBody, StatusCode};

/// The whole-body ceiling for a management response.
///
/// Every literal in this module is far below it. The constant exists so the
/// invariant is stated once and can be asserted, rather than assumed.
pub const MAX_MANAGEMENT_BODY_BYTES: usize = 256;

/// `text/plain` responses are never cached by a browser or an intermediary.
///
/// The management surface serves an operator's appliance state; a shared cache
/// holding `ok`/`degraded` answers after an outage would be worse than no
/// answer at all.
const NO_STORE: &str = "no-store";

/// The media type for the JSON API responses.
pub const JSON_CONTENT_TYPE: &str = "application/json";

/// The media type for the bounded literal responses.
///
/// `text/plain` is used rather than JSON for the refusals and the liveness probe
/// because these bodies are not structured documents — they are single tokens or
/// short phrases that must not invite a parser.
pub const TEXT_CONTENT_TYPE: &str = "text/plain; charset=utf-8";

/// Builds a response with an explicit media type.
///
/// The one construction path. `Response::builder()` is not reachable from
/// anywhere else in `src/http/`, so the media type and the `no-store` policy
/// cannot be forgotten by a route that builds its own response.
///
/// The body is **not** length-checked here. Every body in this module is a fixed
/// literal, and the API bodies are bounded by the routes that read them; the
/// ceiling exists to make that a stated invariant rather than an assumption.
pub fn build(status: StatusCode, content_type: &'static str, body: ResponseBody) -> Response {
    debug_assert!(
        body.len() <= MAX_MANAGEMENT_BODY_BYTES as u64,
        "management bodies are bounded by construction"
    );
    // Both header values are constants chosen to be valid, so the construction
    // cannot fail. Asserted rather than branched on: there is no error here to
    // recover to, and a fallback response would be a second code path to audit.
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .expect("a constant media type is a valid header")
        .header("cache-control", NO_STORE)
        .expect("a constant cache policy is a valid header")
        .body(body)
        .expect("a status was set")
}

/// The two-state liveness answer this surface publishes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Liveness {
    /// The service is serving and its backing state is healthy.
    Ok,
    /// The service is serving, but something it depends on is not.
    Degraded,
}

impl Liveness {
    /// The bounded token written into the response body.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Degraded => "degraded",
        }
    }

    /// The status this liveness class is served with.
    ///
    /// Both classes are 200 on purpose. "Degraded" describes the appliance, not
    /// the request: the request was answered. Serving it as 503 would conflate
    /// "the thing you asked about is unhealthy" with "this endpoint is
    /// unavailable", and would make a liveness probe restart a healthy listener.
    pub fn status(&self) -> StatusCode {
        StatusCode::OK
    }

    /// Classifies a management health snapshot without disclosing it.
    ///
    /// Only the boolean outcome crosses this boundary. No installation ID,
    /// generation, path, desired-state fact, or backend failure category is
    /// consulted, because none of them may reach an unauthenticated caller.
    pub fn from_health(health: &crate::management::ManagementHealth) -> Self {
        if health.is_healthy() {
            Self::Ok
        } else {
            Self::Degraded
        }
    }
}

/// Builds a `text/plain` response with a fixed literal body.
///
/// The signature admits no dynamic string, which is the whole point: there is no
/// way to format an error, a path, or an internal type into a management body.
fn literal(status: StatusCode, body: &'static str) -> Response {
    build(
        status,
        TEXT_CONTENT_TYPE,
        ResponseBody::Bytes(body.as_bytes().to_vec()),
    )
}

/// `200 ok` or `200 degraded` — the entire M001 health answer.
pub fn liveness(answer: Liveness) -> Response {
    literal(answer.status(), answer.as_str())
}

/// `404 not found` for a route this surface does not have.
pub fn not_found() -> Response {
    literal(StatusCode::NOT_FOUND, "not found")
}

/// `405 method not allowed` for a known route reached by an unknown method.
pub fn method_not_allowed() -> Response {
    literal(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
}

/// `503 unavailable` for worker saturation, a missed deadline, or a stopped
/// worker.
///
/// The three causes are deliberately indistinguishable to the caller: a client
/// that could tell them apart would learn whether the operator's appliance is
/// merely slow or entirely gone.
pub fn unavailable() -> Response {
    literal(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
}

/// `500 internal error` for a response that could not be constructed.
///
/// Reached only by a coding error, never by user input.
pub fn internal_error() -> Response {
    literal(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_text(mut response: Response) -> String {
        String::from_utf8(response.take_body().unwrap().into_bytes().unwrap()).unwrap()
    }

    #[test]
    fn every_body_is_a_bounded_literal() {
        let responses = [
            liveness(Liveness::Ok),
            liveness(Liveness::Degraded),
            not_found(),
            method_not_allowed(),
            unavailable(),
            internal_error(),
        ];
        for response in responses {
            let body = body_text(response);
            assert!(
                body.len() <= MAX_MANAGEMENT_BODY_BYTES,
                "{body:?} exceeds the management body ceiling"
            );
        }
    }

    #[test]
    fn every_response_declares_itself_uncacheable() {
        let response = liveness(Liveness::Ok);
        let cache = response
            .headers()
            .get_first("cache-control")
            .expect("every management response sets cache-control");
        assert_eq!(cache.to_str().unwrap(), NO_STORE);
    }

    #[test]
    fn both_liveness_classes_are_served_as_200() {
        // A degraded appliance is still an answered request; conflating the two
        // would make a liveness probe restart a healthy listener.
        assert_eq!(liveness(Liveness::Ok).status(), StatusCode::OK);
        assert_eq!(liveness(Liveness::Degraded).status(), StatusCode::OK);
        assert_eq!(body_text(liveness(Liveness::Ok)), "ok");
        assert_eq!(body_text(liveness(Liveness::Degraded)), "degraded");
    }

    #[test]
    fn overload_answers_are_indistinguishable_from_each_other() {
        // One literal backs all three worker failures on purpose.
        let saturated = unavailable();
        assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body_text(unavailable()), body_text(saturated));
        assert_eq!(body_text(unavailable()), "unavailable");
    }

    #[test]
    fn unknown_routes_and_methods_are_bounded_and_distinct() {
        assert_eq!(not_found().status(), StatusCode::NOT_FOUND);
        assert_eq!(body_text(not_found()), "not found");
        assert_eq!(
            method_not_allowed().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(body_text(method_not_allowed()), "method not allowed");
    }

    #[test]
    fn a_health_snapshot_is_reduced_to_two_states() {
        let healthy = crate::management::ManagementHealth {
            database_healthy: true,
            netd_reachable: true,
            installation_id: Some(crate::domain::InstallationId::new()),
            current_desired_generation: Some(crate::domain::INITIAL_DESIRED_GENERATION),
            last_converged_generation: Some(crate::domain::INITIAL_DESIRED_GENERATION),
            convergence: crate::management::ConvergenceState::Converged,
            last_failure_category: None,
        };
        assert_eq!(Liveness::from_health(&healthy), Liveness::Ok);

        // Every unhealthy field collapses to the same answer, so the liveness
        // body cannot be used as an oracle for any one of them.
        let degraded = crate::management::ManagementHealth {
            database_healthy: true,
            netd_reachable: false,
            ..healthy
        };
        assert_eq!(Liveness::from_health(&degraded), Liveness::Degraded);
    }
}
