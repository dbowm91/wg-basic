//! The session cookie: how an opaque bearer token reaches a browser.
//!
//! # Attribute policy, and why each attribute is here
//!
//! | Attribute | Value | Reason |
//! |---|---|---|
//! | `HttpOnly` | always | JavaScript must not be able to read the bearer. |
//! | `SameSite` | `Strict` | A cross-site request must not carry it at all. This is defence in depth, not the CSRF defence: `SameSite` cannot be relied on alone. |
//! | `Path` | `/` | Required by the `__Host-` prefix. |
//! | `Domain` | never set | Host-only. Required by `__Host-`, and it stops a sibling subdomain receiving it. |
//! | `Max-Age` | server expiry | The cookie must die when the session does, so a stale cookie cannot outlive it in the browser. |
//! | `Secure` | only for an HTTPS canonical origin | See below. |
//! | `__Host-` prefix | only for an HTTPS canonical origin | See below. |
//!
//! # Why the profile follows the canonical origin and not the connection
//!
//! A `Secure` cookie sent over plain loopback HTTP is **never stored** by a
//! browser. Setting it unconditionally would therefore produce a service that
//! appears to authenticate and then silently fails — the worst possible failure
//! mode, because it looks like a credential problem.
//!
//! So the cookie profile is a function of the configured canonical origin:
//!
//! * HTTPS origin → `__Host-wg_basic_session`, `Secure`. The prefix makes the
//!   browser enforce `Secure`, no `Domain`, and `Path=/` itself.
//! * HTTP loopback origin → `wg_basic_session`, no `Secure`, no prefix, with
//!   explicit local-only documentation.
//!
//! There is no third option and no per-request negotiation: a request cannot
//! choose to be treated as secure.

use super::origin::{OriginPolicy, SESSION_COOKIE_NAME, SESSION_COOKIE_SECURE_NAME};
use crate::domain::SessionToken;
use cookie::{time::Duration as CookieDuration, Cookie, SameSite};

/// How a session cookie was configured for this deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CookieProfile {
    /// A plain-HTTP loopback deployment: host-only, no `Secure`, no prefix.
    LoopbackHttp,
    /// An HTTPS canonical origin: `__Host-` prefixed and `Secure`.
    HttpsOrigin,
}

impl CookieProfile {
    /// The profile implied by a canonical origin.
    pub fn for_policy(policy: &OriginPolicy) -> Self {
        if policy.is_secure() {
            Self::HttpsOrigin
        } else {
            Self::LoopbackHttp
        }
    }

    /// The cookie name for this profile.
    pub fn cookie_name(&self) -> &'static str {
        match self {
            Self::LoopbackHttp => SESSION_COOKIE_NAME,
            Self::HttpsOrigin => SESSION_COOKIE_SECURE_NAME,
        }
    }
}

/// Why a `Set-Cookie` value could not be built.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SessionCookieError {
    /// The session had already expired when the cookie was written.
    #[error("a session cannot be published with a non-positive lifetime")]
    NonPositiveLifetime,
}

/// Builds the `Set-Cookie` value that publishes a freshly issued session.
///
/// `max_age_seconds` is the *server-side* remaining lifetime, so the browser's
/// copy can never outlive the row it names.
pub fn session_set_cookie(
    policy: &OriginPolicy,
    token: &SessionToken,
    max_age_seconds: i64,
) -> Result<String, SessionCookieError> {
    if max_age_seconds <= 0 {
        // Writing a cookie that is already dead would be a silent login failure.
        return Err(SessionCookieError::NonPositiveLifetime);
    }
    let profile = CookieProfile::for_policy(policy);
    let mut cookie = Cookie::build((profile.cookie_name(), token.expose_once().to_owned()))
        .http_only(true)
        .path("/")
        .same_site(SameSite::Strict)
        .max_age(CookieDuration::seconds(max_age_seconds));
    if matches!(profile, CookieProfile::HttpsOrigin) {
        cookie = cookie.secure(true);
        // Never set a Domain: the `__Host-` prefix is only honoured without one,
        // and a host-only cookie is what keeps a sibling subdomain from seeing it.
    }
    Ok(cookie.build().to_string())
}

/// Builds the `Set-Cookie` value that expires the session cookie.
///
/// Same name, same attributes, and an immediate expiry. A logout that only
/// deleted the row would leave a working cookie in the browser that fails on
/// every later request.
pub fn session_expire_cookie(policy: &OriginPolicy) -> Result<String, SessionCookieError> {
    let profile = CookieProfile::for_policy(policy);
    let mut cookie = Cookie::build((profile.cookie_name(), "".to_owned()))
        .http_only(true)
        .path("/")
        .same_site(SameSite::Strict)
        .max_age(CookieDuration::ZERO);
    if matches!(profile, CookieProfile::HttpsOrigin) {
        cookie = cookie.secure(true);
    }
    Ok(cookie.build().to_string())
}

/// Extracts the presented session token from a request's cookies.
///
/// Returns `None` for a missing, malformed, or wrong-profile cookie rather than
/// an error: an unauthenticated caller presenting nonsense is an ordinary
/// unauthenticated caller.
///
/// Only the cookie this deployment would have written is considered. Accepting
/// the other profile's name would mean a `Secure` cookie set by an earlier
/// misconfiguration kept working after the origin was corrected.
pub fn presented_session_token(
    policy: &OriginPolicy,
    cookie_header: Option<&str>,
) -> Option<String> {
    let raw = cookie_header?;
    // Parsed one pair at a time with the library's own strict parser rather than
    // by splitting on `=` by hand. A pair that does not parse is skipped, not
    // fatal: a malformed `Cookie` header should degrade to "no session", not
    // abort a request handler.
    let mut jar = cookie::CookieJar::new();
    for pair in raw.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Ok(parsed) = cookie::Cookie::parse(pair.to_owned()) {
            jar.add_original(parsed);
        }
    }
    let profile = CookieProfile::for_policy(policy);
    jar.get(profile.cookie_name())
        .map(|value| value.value().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    fn loopback_policy() -> OriginPolicy {
        OriginPolicy::loopback_only(SocketAddr::from((Ipv4Addr::LOCALHOST, 8000)))
    }

    fn proxy_policy() -> OriginPolicy {
        OriginPolicy::behind_https_proxy(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 8000)),
            "https://vpn.example.com",
        )
        .unwrap()
    }

    fn token() -> SessionToken {
        SessionToken::generate().unwrap()
    }

    #[test]
    fn a_loopback_session_cookie_is_host_only_and_makes_no_secure_claim() {
        let policy = loopback_policy();
        let raw = token();
        let header = session_set_cookie(&policy, &raw, 3600).unwrap();

        assert!(header.starts_with("wg_basic_session="));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("SameSite=Strict"));
        assert!(header.contains("Path=/"));
        assert!(header.contains("Max-Age=3600"));
        // The three properties that would break a browser or leak the cookie.
        assert!(!header.contains("Secure"), "{header}");
        assert!(!header.contains("Domain"), "{header}");
        assert!(!header.starts_with("__Host-"), "{header}");
        assert!(header.contains(raw.expose_once()));
    }

    #[test]
    fn an_https_origin_gets_a_secure_prefixed_cookie() {
        let policy = proxy_policy();
        let raw = token();
        let header = session_set_cookie(&policy, &raw, 3600).unwrap();

        assert!(header.starts_with("__Host-wg_basic_session="));
        assert!(header.contains("Secure"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("SameSite=Strict"));
        assert!(header.contains("Path=/"));
        // `__Host-` is only honoured with no Domain; setting one would make the
        // browser reject the cookie outright.
        assert!(!header.contains("Domain"), "{header}");
    }

    #[test]
    fn the_cookie_profile_follows_the_origin_not_the_request() {
        // The same token, two deployments, two different profiles. A request
        // cannot negotiate its way into a secure profile it does not belong in.
        let raw = token();
        assert!(!session_set_cookie(&loopback_policy(), &raw, 60)
            .unwrap()
            .contains("Secure"));
        assert!(session_set_cookie(&proxy_policy(), &raw, 60)
            .unwrap()
            .contains("Secure"));
    }

    #[test]
    fn a_session_whose_lifetime_has_elapsed_is_never_published() {
        let policy = loopback_policy();
        let raw = token();
        for lifetime in [0, -1] {
            assert_eq!(
                session_set_cookie(&policy, &raw, lifetime).unwrap_err(),
                SessionCookieError::NonPositiveLifetime,
                "an expired session must not be handed to a browser"
            );
        }
    }

    #[test]
    fn logout_expires_the_cookie_with_matching_attributes() {
        let policy = loopback_policy();
        let header = session_expire_cookie(&policy).unwrap();
        assert!(header.starts_with("wg_basic_session="));
        assert!(header.contains("Max-Age=0"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("SameSite=Strict"));
        // Same attributes as the issuing cookie, or the browser may keep a
        // second copy under different rules.
        assert!(!header.contains("Secure"));

        let secure = session_expire_cookie(&proxy_policy()).unwrap();
        assert!(secure.starts_with("__Host-wg_basic_session="));
        assert!(secure.contains("Secure"));
    }

    #[test]
    fn a_presented_cookie_yields_its_token() {
        let policy = loopback_policy();
        let raw = token();
        let header = session_set_cookie(&policy, &raw, 3600).unwrap();
        let request_cookie = header.split(';').next().unwrap();
        assert_eq!(
            presented_session_token(&policy, Some(request_cookie)),
            Some(raw.expose_once().to_owned())
        );
    }

    #[test]
    fn a_missing_malformed_or_foreign_cookie_is_simply_absent() {
        let policy = loopback_policy();
        assert_eq!(presented_session_token(&policy, None), None);
        assert_eq!(presented_session_token(&policy, Some("")), None);
        assert_eq!(presented_session_token(&policy, Some("not a cookie")), None);
        // Another cookie entirely.
        assert_eq!(
            presented_session_token(&policy, Some("other=value; x=1")),
            None
        );
        // The HTTPS profile's name is not accepted by an HTTP deployment.
        assert_eq!(
            presented_session_token(&policy, Some("__Host-wg_basic_session=abc")),
            None
        );
        // An empty value is not a session.
        assert_eq!(
            presented_session_token(&policy, Some("wg_basic_session=")),
            None
        );
    }

    #[test]
    fn the_secure_cookie_is_not_readable_by_a_loopback_deployment() {
        // Correcting an origin must actually invalidate cookies minted under the
        // old profile, or a misconfiguration would persist forever.
        let secure = proxy_policy();
        let raw = token();
        let header = session_set_cookie(&secure, &raw, 3600).unwrap();
        let request_cookie = header.split(';').next().unwrap();
        assert_eq!(
            presented_session_token(&secure, Some(request_cookie)),
            Some(raw.expose_once().to_owned())
        );
        assert_eq!(
            presented_session_token(&loopback_policy(), Some(request_cookie)),
            None
        );
    }
}
