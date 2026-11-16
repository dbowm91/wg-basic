//! Narrow SameSite=Lax carveout for OIDC callback completion only.
//!
//! Product session cookies remain Strict (`session_cookie.rs`). The completion
//! cookie is a one-shot bearer read on a same-origin GET upgrade handoff.

use super::origin::OriginPolicy;
use crate::domain::SessionToken;
use cookie::{time::Duration as CookieDuration, Cookie, SameSite};

pub const OIDC_COMPLETION_COOKIE_NAME: &str = "wg_basic_oidc_complete";

/// Max-Age for the one-shot Lax completion cookie (must match store lifetime).
pub const OIDC_COMPLETION_COOKIE_MAX_AGE_SECONDS: i64 = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OidcCookieError {
    #[error("a completion cookie cannot be published with a non-positive lifetime")]
    NonPositiveLifetime,
}

pub fn completion_set_cookie(
    policy: &OriginPolicy,
    token: &SessionToken,
    max_age_seconds: i64,
) -> Result<String, OidcCookieError> {
    if max_age_seconds <= 0 {
        return Err(OidcCookieError::NonPositiveLifetime);
    }
    let mut cookie = Cookie::build((OIDC_COMPLETION_COOKIE_NAME, token.expose_once().to_owned()))
        .http_only(true)
        .path("/")
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(max_age_seconds));
    if policy.is_secure() {
        cookie = cookie.secure(true);
    }
    Ok(cookie.build().to_string())
}

pub fn completion_expire_cookie(policy: &OriginPolicy) -> String {
    let mut cookie = Cookie::build((OIDC_COMPLETION_COOKIE_NAME, ""))
        .http_only(true)
        .path("/")
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::ZERO);
    if policy.is_secure() {
        cookie = cookie.secure(true);
    }
    cookie.build().to_string()
}

pub fn presented_completion_token(cookie_header: Option<&str>) -> Option<String> {
    let raw = cookie_header?;
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
    jar.get(OIDC_COMPLETION_COOKIE_NAME)
        .map(|value| value.value().to_owned())
        .filter(|value| !value.is_empty())
}
