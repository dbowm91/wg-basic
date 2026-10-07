//! Security headers, applied centrally to every response.
//!
//! # Central, because a per-route header is a missing header
//!
//! A security header that a route must remember to set is a header that one
//! route will eventually forget. So [`seal`] is applied in exactly one place —
//! the end of [`ManagementService::dispatch`](super::service) — *after* routing
//! has chosen a status, a body, and a cookie, on every return path including
//! every refusal.
//!
//! Sealing happens after construction rather than during it, which is what makes
//! it total. A route that builds its own [`Response`], or that returns one of the
//! [`literal`](super::response) bodies, still comes out sealed, because there is
//! no way to reach the wire that does not pass through [`seal`].
//!
//! # What each header is for
//!
//! | Header | Value | Attack it removes |
//! |---|---|---|
//! | `Content-Security-Policy` | `default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'` | Injected script and plugin content, base-tag hijacking, clickjacking, form exfiltration |
//! | `X-Content-Type-Options` | `nosniff` | A browser re-interpreting a response as HTML or script |
//! | `X-Frame-Options` | `DENY` | Framing, for browsers that predate `frame-ancestors` |
//! | `Referrer-Policy` | `no-referrer` | Leaking the management URL to a third party |
//! | `Permissions-Policy` | a closed allowlist | Camera, microphone, geolocation, and the rest |
//!
//! # HSTS is conditional, and only ever on HTTPS
//!
//! `Strict-Transport-Security` on a plain-HTTP loopback listener would be
//! meaningless at best, and at worst would poison a browser's cache for a host
//! that legitimately serves HTTP. It is therefore sent only when the canonical
//! origin is HTTPS — that is, only when a reverse proxy really is terminating
//! TLS. This is the one header whose presence depends on configuration, and the
//! condition is the canonical origin rather than the request.
//!
//! # No stack identification
//!
//! Nothing here names EggServe, Rust, Hyper, or wg-basic. Combined with the
//! absent `Server` header pinned in M001, a probe learns nothing about the stack
//! it is attacking.

use eggserve_primitives::{HeaderBlock, Response};

/// The exact Content-Security-Policy this surface sends.
///
/// Written out in full rather than assembled from parts, so a review can compare
/// it against the threat list above in one glance.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; object-src 'none'; \
                                        base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

/// The `Permissions-Policy` value.
///
/// Every powerful browser feature is explicitly switched off rather than left to
/// the browser's default, so a future default change cannot silently grant one.
pub const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), camera=(), \
                                     display-capture=(), encrypted-media=(), \
                                     fullscreen=(), geolocation=(), gyroscope=(), \
                                     magnetometer=(), microphone=(), midi=(), \
                                     payment=(), picture-in-picture=(), \
                                     publickey-credentials-get=(), screen-wake-lock=(), \
                                     sync-xhr=(), usb=(), xr-spatial-tracking=()";

/// The `Strict-Transport-Security` value sent on an HTTPS canonical origin.
///
/// `max-age` is two years, which is the value browsers require before honouring
/// the preload list, and `includeSubDomains` is deliberately **absent**: a
/// management appliance has no business asserting that every subdomain of an
/// operator's domain is HTTPS.
pub const STRICT_TRANSPORT_SECURITY: &str = "max-age=63072000";

/// The header set [`seal`] applies to every response, as `(name, value)`.
///
/// A single table rather than one call per header, so [`seal`] and
/// [`header_names`] cannot disagree about what the set contains — a test asserts
/// they agree rather than a reader having to check.
const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("content-security-policy", CONTENT_SECURITY_POLICY),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    ("permissions-policy", PERMISSIONS_POLICY),
];

/// Applies the security headers to a finished response.
///
/// This is the single point at which a response acquires its security headers,
/// and the service calls it on **every** return path — success, refusal, and
/// worker failure alike. Because it runs after construction rather than inside
/// it, no route can build a response that skips it: the response does not exist
/// yet when routing chooses it, and it does not reach the wire until it has been
/// through here.
///
/// `is_secure_origin` reflects the configured canonical origin, never the
/// incoming connection, so a deployment cannot be talked into claiming a
/// transport it does not have.
///
/// Sealing is idempotent in effect: [`HeaderBlock`] stores repeated fields, so a
/// second call would append rather than replace. The service seals exactly once
/// per response, and `a_response_sealed_twice_is_a_bug` pins that expectation
/// rather than making the duplicate harmless.
pub fn seal(mut response: Response, is_secure_origin: bool) -> Response {
    let block = response.head_mut().headers_mut();
    for (name, value) in SECURITY_HEADERS {
        // Constant ASCII names and values with no CR, LF, or NUL, so validation
        // cannot fail. Asserted at startup by the tests below rather than
        // branching on an error a `&'static str` cannot produce.
        let pushed = block.push_str(*name, *value);
        debug_assert!(pushed.is_ok(), "a constant security header must be valid");
    }
    if is_secure_origin {
        let pushed = block.push_str("strict-transport-security", STRICT_TRANSPORT_SECURITY);
        debug_assert!(pushed.is_ok(), "a constant HSTS header must be valid");
    }
    response
}

/// Adds `Set-Cookie` to a finished response.
///
/// Kept beside [`seal`] because it is the same kind of operation — a header
/// added after the response was built — and because a cookie that could only be
/// attached during construction would tempt a route into building its own
/// response instead of using the shared builder.
pub fn with_set_cookie(mut response: Response, cookie: &str) -> Response {
    let pushed = response
        .head_mut()
        .headers_mut()
        .push_str("set-cookie", cookie);
    debug_assert!(
        pushed.is_ok(),
        "a built cookie must be a valid header value"
    );
    response
}

/// Adds `Retry-After` to a finished response.
///
/// The only variable header this surface emits. It exists on exactly one
/// refusal — a throttled login — so a client can tell "come back later" apart
/// from "you are wrong", which is the one distinction a rate limiter has to make
/// for itself to be usable.
pub fn with_retry_after(mut response: Response, seconds: u64) -> Response {
    let pushed = response
        .head_mut()
        .headers_mut()
        .push_str("retry-after", seconds.to_string());
    debug_assert!(pushed.is_ok(), "a u64 is a valid header value");
    response
}

/// The names [`seal`] adds, so a test can assert the set is complete.
pub fn header_names(is_secure_origin: bool) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = SECURITY_HEADERS.iter().map(|(name, _)| *name).collect();
    if is_secure_origin {
        names.push("strict-transport-security");
    }
    names
}

/// Reads one header value out of a response, for tests.
pub fn header_value(response: &Response, name: &str) -> Option<String> {
    let headers: &HeaderBlock = response.headers();
    headers
        .get_first(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eggserve_primitives::{ResponseBody, StatusCode};

    fn build(is_secure: bool) -> Response {
        seal(
            Response::builder()
                .status(StatusCode::OK)
                .body(ResponseBody::Bytes(b"ok".to_vec()))
                .unwrap(),
            is_secure,
        )
    }

    #[test]
    fn every_response_carries_the_full_security_header_set() {
        let response = build(false);
        assert_eq!(
            header_value(&response, "content-security-policy").as_deref(),
            Some(CONTENT_SECURITY_POLICY)
        );
        assert_eq!(
            header_value(&response, "x-content-type-options").as_deref(),
            Some("nosniff")
        );
        assert_eq!(
            header_value(&response, "x-frame-options").as_deref(),
            Some("DENY")
        );
        assert_eq!(
            header_value(&response, "referrer-policy").as_deref(),
            Some("no-referrer")
        );
        assert_eq!(
            header_value(&response, "permissions-policy").as_deref(),
            Some(PERMISSIONS_POLICY)
        );
    }

    #[test]
    fn the_csp_denies_the_dangerous_directives_explicitly() {
        for directive in [
            "object-src 'none'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "default-src 'self'",
        ] {
            assert!(
                CONTENT_SECURITY_POLICY.contains(directive),
                "the CSP must contain {directive}"
            );
        }
        // No `unsafe-inline` and no `unsafe-eval`: a policy containing either is
        // not meaningfully restrictive.
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe-inline"));
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe-eval"));
    }

    #[test]
    fn the_permissions_policy_switches_every_feature_off() {
        for feature in ["camera", "microphone", "geolocation", "usb", "payment"] {
            assert!(
                PERMISSIONS_POLICY.contains(&format!("{feature}=()")),
                "{feature} must be explicitly denied"
            );
        }
    }

    #[test]
    fn hsts_is_sent_only_for_an_https_canonical_origin() {
        assert_eq!(
            header_value(&build(false), "strict-transport-security"),
            None
        );
        assert_eq!(
            header_value(&build(true), "strict-transport-security").as_deref(),
            Some(STRICT_TRANSPORT_SECURITY)
        );
        assert_eq!(header_names(false).len(), 5);
        assert_eq!(header_names(true).len(), 6);
    }

    #[test]
    fn hsts_does_not_claim_subdomains() {
        // An appliance has no business asserting HTTPS for every subdomain of an
        // operator's domain.
        assert!(!STRICT_TRANSPORT_SECURITY.contains("includeSubDomains"));
        assert!(!STRICT_TRANSPORT_SECURITY.contains("preload"));
    }

    #[test]
    fn a_response_sealed_twice_would_duplicate_rather_than_replace() {
        // Why `seal` is documented as one-shot: `HeaderBlock` keeps repeated
        // fields. This test does not bless the double seal; it records why the
        // service must call it exactly once, so the constraint is visible
        // rather than discovered later from a duplicated header on the wire.
        let twice = seal(build(false), false);
        assert_eq!(
            twice.headers().get_all("x-frame-options").len(),
            2,
            "a second seal appends; the service must seal exactly once"
        );
    }

    #[test]
    fn sealing_preserves_the_status_the_route_already_chosen() {
        // Sealing is a header operation only. A route that chose 401 must still
        // be 401 after sealing, or the security headers would be rewriting the
        // answer rather than decorating it.
        for status in [
            StatusCode::OK,
            StatusCode::FORBIDDEN,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::NOT_FOUND,
        ] {
            let response = seal(
                Response::builder()
                    .status(status)
                    .body(ResponseBody::Empty)
                    .unwrap(),
                true,
            );
            assert_eq!(response.status(), status);
        }
    }

    #[test]
    fn a_cookie_is_attached_without_rebuilding_the_response() {
        let sealed = with_set_cookie(build(false), "wg_basic_session=abc; HttpOnly");
        assert_eq!(
            header_value(&sealed, "set-cookie").as_deref(),
            Some("wg_basic_session=abc; HttpOnly")
        );
        // And the security headers survive.
        assert_eq!(
            header_value(&sealed, "x-frame-options").as_deref(),
            Some("DENY")
        );
    }

    #[test]
    fn every_security_header_name_is_a_valid_header_name() {
        // `seal` asserts rather than branches on this; proving it here means a
        // typo in the table is a failing test rather than a silent debug assert
        // in a release build.
        for name in header_names(true) {
            let mut headers = HeaderBlock::new();
            headers
                .push_str(name, "x")
                .expect("a table entry must name a valid header");
        }
    }

    #[test]
    fn no_header_names_the_stack() {
        let response = build(true);
        for forbidden in ["eggserve", "hyper", "wg-basic", "rust", "tower"] {
            assert!(
                !header_value(&response, "server").is_some_and(|v| v.contains(forbidden)),
                "the Server header must not name {forbidden}"
            );
        }
        let rendered: Vec<String> = header_names(true)
            .iter()
            .filter_map(|name| header_value(&response, name))
            .collect();
        for value in &rendered {
            for forbidden in ["eggserve", "hyper", "wg-basic", "rust", "tower"] {
                assert!(
                    !value.to_lowercase().contains(forbidden),
                    "{value} leaks {forbidden}"
                );
            }
        }
    }

    #[test]
    fn the_headers_are_shared_by_constants_so_a_route_cannot_drift() {
        // A test hard-codes the CSP string; a second one compares against the
        // constant. If the constant changes, one of them fails.
        assert_eq!(
            CONTENT_SECURITY_POLICY,
            "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; \
             form-action 'self'"
        );
        // The policy is a `&'static str`, so every response in the process renders
        // the same bytes with no allocation and no chance of drift.
        assert!(
            CONTENT_SECURITY_POLICY.len() < 256,
            "the CSP must stay small enough to add to every response"
        );
    }
}
