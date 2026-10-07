//! Bind and canonical-origin configuration: the answer to "who may talk to this
//! service, and over what origin".
//!
//! # Why this is configuration and not an inference
//!
//! A loopback listener is reachable by any process on the host and, through a
//! browser, by any page the operator visits — that is DNS rebinding. The
//! request's `Host` header is attacker-controlled in exactly that scenario, so
//! "the listener is loopback" is not evidence of who is asking. The plan is
//! explicit about this: trust must not be derived from `Host` merely because the
//! socket is loopback.
//!
//! So the operator states an allowed host set and, separately, a canonical
//! external origin. Everything else follows from those two facts.
//!
//! # The four profiles
//!
//! | Mode | Listener | Canonical origin | Session cookie |
//! |---|---|---|---|
//! | Loopback HTTP (default) | `127.0.0.1:8000` | `http://127.0.0.1:8000` | host-only, **not** `Secure` |
//! | Loopback + HTTPS proxy | `127.0.0.1:8000` | `https://vpn.example.com` | `__Host-` prefix, `Secure` |
//! | Explicit non-loopback | `0.0.0.0:8000` | stated explicitly | as per origin scheme |
//! | TLS terminator on the listener | n/a in Phase 7 | — | — |
//!
//! Direct TLS is explicitly not implemented. An HTTPS canonical origin means a
//! reverse proxy terminates TLS in front of a loopback listener.
//!
//! # Non-loopback requires acknowledgement
//!
//! Binding off-host serves the management surface to the network. Phase 7 has no
//! TLS of its own, so that is only acceptable behind a proxy the operator has
//! configured — which is why it needs an explicit acknowledgement flag rather
//! than being merely permitted.

use std::{fmt, net::IpAddr};

/// How the listener is exposed, and therefore what origin is canonical.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExposureMode {
    /// Listener bound to a loopback address. The default.
    LoopbackOnly,
    /// Listener bound to a routable address, acknowledged by the operator.
    AcknowledgedOffHost,
}

impl ExposureMode {
    /// Whether this mode can be reached from another host.
    pub fn is_off_host(&self) -> bool {
        matches!(self, Self::AcknowledgedOffHost)
    }
}

/// Why an origin configuration was refused.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OriginConfigError {
    /// An off-host listener without the explicit acknowledgement flag.
    #[error(
        "binding a routable address serves the management surface to the network; \
             pass --allow-non-loopback to acknowledge it"
    )]
    UnacknowledgedOffHost,
    /// The canonical origin is not an absolute `http`/`https` URL.
    #[error(
        "the canonical origin must be an absolute http(s) origin such as https://vpn.example.com"
    )]
    NotAnOrigin,
    /// The canonical origin's host or port could not be understood.
    #[error("`{0}` is not a usable http(s) origin authority")]
    NotAnAuthority(String),
    /// The canonical origin carries a path, query, or fragment.
    #[error("the canonical origin must be scheme://host[:port] with no path, query, or fragment")]
    OriginNotBare,
    /// The canonical origin is HTTPS while the listener is a routable address.
    #[error(
        "a routable listener cannot claim an https origin without TLS; \
             terminate TLS in a reverse proxy and keep the listener on loopback"
    )]
    HttpsClaimWithoutProxy,
    /// No host would be accepted.
    #[error("the allowed host set is empty, so no request could ever be served")]
    NoAllowedHosts,
}

/// The canonical origin, as `scheme://host[:port]` with nothing else.
///
/// Deliberately bare: an origin per RFC 6454 is exactly this. Accepting a
/// trailing path here would mean accepting an origin comparison that quietly
/// differs from what a browser sends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalOrigin {
    /// `http` or `https`.
    pub scheme: OriginScheme,
    /// The host, already lowercased and without a port.
    pub host: String,
    /// The explicit port, when one was given or implied by the scheme.
    pub port: u16,
}

/// Whether the canonical origin is HTTP or HTTPS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginScheme {
    /// Plain HTTP. Only ever correct on loopback without a proxy.
    Http,
    /// HTTPS. Either terminated by a reverse proxy in Phase 7.
    Https,
}

impl OriginScheme {
    /// Whether this scheme puts the request on a secure transport.
    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Https)
    }
}

impl CanonicalOrigin {
    /// Parses `scheme://host[:port]`.
    ///
    /// The port is implied when absent: 443 for HTTPS, 80 for HTTP. Storing the
    /// implied port means an `Origin` header that omits it and one that states it
    /// compare equal, which is what a browser actually sends.
    pub fn parse(raw: &str) -> Result<Self, OriginConfigError> {
        let raw = raw.trim();
        let (scheme, rest) = raw
            .split_once("://")
            .ok_or(OriginConfigError::NotAnOrigin)?;
        let scheme = match scheme.to_ascii_lowercase().as_str() {
            "http" => OriginScheme::Http,
            "https" => OriginScheme::Https,
            _ => return Err(OriginConfigError::NotAnOrigin),
        };
        // Anything after the authority is not part of an origin.
        if rest.contains('/') || rest.contains('?') || rest.contains('#') {
            return Err(OriginConfigError::OriginNotBare);
        }
        if rest.is_empty() {
            return Err(OriginConfigError::NotAnAuthority(raw.to_owned()));
        }

        // An IPv6 literal is bracketed, so split on the last colon that is not
        // inside brackets rather than the first.
        let (host, port) = split_authority(rest)
            .ok_or_else(|| OriginConfigError::NotAnAuthority(raw.to_owned()))?;
        if host.is_empty() {
            return Err(OriginConfigError::NotAnAuthority(raw.to_owned()));
        }
        let port = match port {
            Some(port) => port
                .parse::<u16>()
                .ok()
                .filter(|port| *port > 0)
                .ok_or_else(|| OriginConfigError::NotAnAuthority(raw.to_owned()))?,
            None => match scheme {
                OriginScheme::Https => 443,
                OriginScheme::Http => 80,
            },
        };
        Ok(Self {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// The `scheme://host[:port]` form, omitting the port when it is the default.
    pub fn as_header_value(&self) -> String {
        let default_port = match self.scheme {
            OriginScheme::Https => 443,
            OriginScheme::Http => 80,
        };
        if self.port == default_port {
            format!("{}://{}", self.scheme_name(), format_host(&self.host))
        } else {
            format!(
                "{}://{}:{}",
                self.scheme_name(),
                format_host(&self.host),
                self.port
            )
        }
    }

    /// The scheme as it appears on the wire.
    pub fn scheme_name(&self) -> &'static str {
        match self.scheme {
            OriginScheme::Https => "https",
            OriginScheme::Http => "http",
        }
    }

    /// The `Host` header value this origin implies, with the port only when it
    /// is not the scheme default.
    ///
    /// This is what goes into the allowed-host set, so a browser reaching the
    /// service at the canonical origin and a proxy forwarding to it agree.
    pub fn implied_host_header(&self) -> String {
        let default_port = match self.scheme {
            OriginScheme::Https => 443,
            OriginScheme::Http => 80,
        };
        if self.port == default_port {
            format_host(&self.host)
        } else {
            format!("{}:{}", format_host(&self.host), self.port)
        }
    }
}

/// Re-brackets an IPv6 literal so it can be used in a URL.
fn format_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// Splits `host[:port]`, tolerating a bracketed IPv6 literal.
fn split_authority(authority: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        return match after.strip_prefix(':') {
            Some(port) => Some((host, Some(port))),
            None if after.is_empty() => Some((host, None)),
            None => None,
        };
    }
    match authority.rsplit_once(':') {
        // More than one colon means a bare IPv6 literal, which must be bracketed.
        Some(_) if authority.matches(':').count() > 1 => Some((authority, None)),
        Some((host, port)) => Some((host, Some(port))),
        None => Some((authority, None)),
    }
}

/// How this deployment's management surface is addressed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginPolicy {
    /// Where the browser is told the service lives.
    pub canonical: CanonicalOrigin,
    /// Every `Host` header value that will be accepted.
    pub allowed_hosts: Vec<String>,
    /// Whether the listener is reachable off-host.
    pub exposure: ExposureMode,
    /// Whether the listener was configured on an ephemeral port.
    ///
    /// Port 0 is a *request* for a free port, not a fact: only after the
    /// listener is up does anyone know what it is, which is after the policy has
    /// already been built. Rather than refuse every request — the browser sends
    /// `Host: 127.0.0.1:45123` and a policy that only knows `127.0.0.1:0` would
    /// reject it — the port is matched loosely.
    ///
    /// Loosely means **the port only**. The host must still be a literal in the
    /// allowed set, and a listener on an ephemeral port is loopback in every real
    /// deployment. A rebinding attacker owns a *name*, and the name is what `Host`
    /// carries, so this does not weaken the DNS-rebinding defence: `evil.com` is
    /// refused here exactly as before.
    ///
    /// This is a test-and-integration affordance, not a production shape. The
    /// default bind is `127.0.0.1:8000`.
    port_is_ephemeral: bool,
}

/// Whether `host` names an allowed host with any well-formed port spelled.
///
/// The port is discarded on both sides; the host must match an allowed entry
/// exactly. A malformed port is a refusal rather than a wildcard, so
/// `Host: 127.0.0.1:evil` does not slip through as a bare `127.0.0.1`.
fn matches_portless_loopback(host: &str, allowed_hosts: &[String]) -> bool {
    let Some(bare) = strip_host_port(host) else {
        return false;
    };
    let normalized = normalize_host(&bare);
    allowed_hosts.iter().any(|allowed| {
        // The allowed entry's host part. `rfind` rather than `split` because an
        // IPv6 entry is bracketed, so its last colon is the port separator.
        let allowed_host = match allowed.rfind(':') {
            Some(index) => &allowed[..index],
            None => allowed.as_str(),
        };
        allowed_host.eq_ignore_ascii_case(&normalized)
    })
}

/// Splits a `Host` value into its host, discarding a well-formed port.
///
/// `None` for anything malformed: a value with no host, an unterminated IPv6
/// literal, more than one colon outside brackets, or a port that is not a number.
fn strip_host_port(host: &str) -> Option<String> {
    if let Some(rest) = host.strip_prefix('[') {
        let end = rest.find(']')?;
        let literal = format!("[{}]", &rest[..end]);
        return match &rest[end + 1..] {
            "" => Some(literal),
            tail => tail
                .strip_prefix(':')
                .filter(|port| port.parse::<u16>().is_ok())
                .map(|_| literal),
        };
    }
    match host.rsplit_once(':') {
        // A bare IPv6 literal is not legal in a `Host` header at all.
        Some(_) if host.matches(':').count() > 1 => None,
        Some((bare, port)) => port.parse::<u16>().ok().map(|_| bare.to_owned()),
        None => Some(host.to_owned()),
    }
}

impl OriginPolicy {
    /// Builds the default policy: loopback only, `http://127.0.0.1:<port>`.
    ///
    /// The allowed-host set contains both `127.0.0.1` and `[::1]` forms and the
    /// explicit port, because an operator who typed one and a browser that
    /// resolved the other must both work — and neither is attacker-controlled.
    pub fn loopback_only(bind: std::net::SocketAddr) -> Self {
        let canonical = CanonicalOrigin::parse(&format!(
            "http://{}",
            bind.ip().to_string().replace("::1", "[::1]")
        ))
        .expect("a socket address is a valid HTTP origin authority");
        let mut canonical = canonical;
        canonical.port = bind.port();
        Self {
            allowed_hosts: allowed_hosts_for(&canonical, &["127.0.0.1", "[::1]"]),
            canonical,
            exposure: ExposureMode::LoopbackOnly,
            port_is_ephemeral: bind.port() == 0,
        }
    }

    /// Builds the policy for a reverse proxy in front of a loopback listener.
    ///
    /// The canonical origin is HTTPS and external; the listener stays on loopback.
    /// Forwarded headers stay untrusted, so `Host` is still checked against an
    /// explicit set rather than believed.
    pub fn behind_https_proxy(
        bind: std::net::SocketAddr,
        external: &str,
    ) -> Result<Self, OriginConfigError> {
        let canonical = CanonicalOrigin::parse(external)?;
        if !canonical.scheme.is_secure() {
            // An "external origin" that is plain HTTP would claim a stable public
            // name over an insecure transport, which is the exact confusion
            // `__Host-` exists to prevent.
            return Err(OriginConfigError::NotAnAuthority(external.to_owned()));
        }
        let _ = bind;
        Ok(Self {
            allowed_hosts: allowed_hosts_for(&canonical, &[]),
            canonical,
            exposure: ExposureMode::LoopbackOnly,
            port_is_ephemeral: false,
        })
    }

    /// Builds the policy for an explicitly acknowledged routable listener.
    pub fn acknowledged_off_host(
        bind: std::net::SocketAddr,
        external: &str,
    ) -> Result<Self, OriginConfigError> {
        if bind.ip().is_loopback() {
            return Err(OriginConfigError::UnacknowledgedOffHost);
        }
        let canonical = CanonicalOrigin::parse(external)?;
        if canonical.scheme.is_secure() {
            // This service speaks no TLS, so an https claim on a routable
            // listener would be false. The operator must terminate TLS.
            return Err(OriginConfigError::HttpsClaimWithoutProxy);
        }
        Ok(Self {
            allowed_hosts: allowed_hosts_for(&canonical, &[]),
            canonical,
            exposure: ExposureMode::AcknowledgedOffHost,
            port_is_ephemeral: false,
        })
    }

    /// Whether the listener was configured on an ephemeral port.
    pub fn port_is_ephemeral(&self) -> bool {
        self.port_is_ephemeral
    }

    /// Whether a `Host` header value is acceptable.
    ///
    /// Compared case-insensitively against an explicit set. Never derived from
    /// the socket's address at request time — the whole point is that the socket
    /// says nothing about who is asking.
    ///
    /// The one exception is an explicitly ephemeral port (see
    /// [`OriginPolicy::loopback_only`]), where the port is matched loosely but
    /// the host is not.
    pub fn accepts_host(&self, host: &str) -> bool {
        let candidate = normalize_host(host);
        if self
            .allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&candidate))
        {
            return true;
        }
        self.port_is_ephemeral && matches_portless_loopback(host, &self.allowed_hosts)
    }

    /// Whether an `Origin` header value is exactly the canonical origin.
    ///
    /// Exact match, scheme included. A cross-origin page sends a different
    /// scheme, host, or port, and all three are compared.
    pub fn accepts_origin(&self, origin: &str) -> bool {
        let candidate = origin.trim();
        // Some clients send `null` for a sandboxed or opaque origin. It is never
        // the canonical origin, and it is exactly what an attacker wants.
        if candidate.is_empty() || candidate.eq_ignore_ascii_case("null") {
            return false;
        }
        let Ok(parsed) = CanonicalOrigin::parse(candidate) else {
            return false;
        };
        if parsed == self.canonical {
            return true;
        }
        // An ephemeral listener has not chosen a port, so the port cannot be part
        // of what it asserts — the same reasoning as `accepts_host`, applied so
        // the two stay symmetric. Scheme and host still have to match exactly, so
        // this is not a wildcard: `https://vpn.example.com` and
        // `http://vpn.example.com` remain different from the canonical origin.
        self.port_is_ephemeral
            && parsed.scheme == self.canonical.scheme
            && parsed.host == self.canonical.host
    }

    /// Whether responses should claim a secure transport.
    ///
    /// This is what decides the `Secure` cookie attribute and whether HSTS is
    /// sent. It is driven by the canonical origin, never by the connection: a
    /// `Secure` cookie sent over plain loopback HTTP would simply never be
    /// stored, which is a silent login failure rather than a safe default.
    pub fn is_secure(&self) -> bool {
        self.canonical.scheme.is_secure()
    }

    /// The session cookie name for this deployment.
    ///
    /// The `__Host-` prefix is mandatory for an HTTPS origin and forbidden
    /// without it: the prefix is only honoured by browsers over a secure
    /// connection, and naming a cookie that way over plain HTTP would produce a
    /// cookie that is silently dropped.
    pub fn session_cookie_name(&self) -> &'static str {
        if self.is_secure() {
            SESSION_COOKIE_SECURE_NAME
        } else {
            SESSION_COOKIE_NAME
        }
    }

    /// A one-line description of the effective mode, for startup output.
    pub fn describe(&self) -> String {
        format!(
            "canonical origin {}, {} (bind {})",
            self.canonical.as_header_value(),
            match self.exposure {
                ExposureMode::LoopbackOnly => "loopback listener",
                ExposureMode::AcknowledgedOffHost => {
                    "ROUTABLE LISTENER, ACKNOWLEDGED — serve only behind a TLS proxy"
                }
            },
            if self.exposure.is_off_host() {
                "non-loopback"
            } else {
                "loopback"
            }
        )
    }
}

/// The session cookie name for plain HTTP loopback.
pub const SESSION_COOKIE_NAME: &str = "wg_basic_session";

/// The session cookie name for an HTTPS canonical origin.
///
/// The `__Host-` prefix makes a browser refuse the cookie unless it is
/// `Secure`, has no `Domain`, and has `Path=/`. That turns three server-side
/// promises into something the browser enforces.
pub const SESSION_COOKIE_SECURE_NAME: &str = "__Host-wg_basic_session";

/// The header a browser echoes the CSRF token back in.
pub const CSRF_HEADER: &str = "x-wg-basic-csrf";

/// The `Host` values this deployment accepts: the canonical one, plus the bare
/// host, plus any extra loopback spellings the operator's browser might use.
fn allowed_hosts_for(canonical: &CanonicalOrigin, extra_loopback: &[&str]) -> Vec<String> {
    let mut hosts = vec![canonical.implied_host_header()];
    // The bare host is accepted as well, so `https://vpn.example.com` and an
    // explicit `:443` are not distinguished by the browser's Host header.
    if canonical.port
        == match canonical.scheme {
            OriginScheme::Https => 443,
            OriginScheme::Http => 80,
        }
    {
        hosts.push(format_host(&canonical.host));
    }
    for extra in extra_loopback {
        hosts.push((*extra).to_owned());
        hosts.push(format!("{extra}:{}", canonical.port));
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Normalizes a `Host` header for comparison.
///
/// Lowercases and strips a trailing dot, because `vpn.example.com.` and
/// `vpn.example.com` are the same name to DNS and a browser may send either. It
/// deliberately does **not** strip a port or a bracket: those change which
/// origin is being addressed and must be compared.
pub(crate) fn normalize_host(host: &str) -> String {
    let trimmed = host.trim();
    trimmed
        .strip_suffix('.')
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
}

/// Whether a listener address is loopback.
pub fn is_loopback_bind(ip: IpAddr) -> bool {
    ip.is_loopback()
}

impl fmt::Display for CanonicalOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_header_value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    fn bind(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    #[test]
    fn an_origin_is_scheme_host_and_implied_port_only() {
        let parsed = CanonicalOrigin::parse("https://vpn.example.com").unwrap();
        assert_eq!(parsed.scheme, OriginScheme::Https);
        assert_eq!(parsed.host, "vpn.example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.as_header_value(), "https://vpn.example.com");
        assert_eq!(parsed.implied_host_header(), "vpn.example.com");

        let plain = CanonicalOrigin::parse("http://127.0.0.1:8000").unwrap();
        assert_eq!(plain.port, 8000);
        assert_eq!(plain.as_header_value(), "http://127.0.0.1:8000");
        assert_eq!(plain.implied_host_header(), "127.0.0.1:8000");

        // An explicit default port is the same origin as the implied one, so a
        // browser that states `:443` is not rejected for it.
        let explicit = CanonicalOrigin::parse("https://vpn.example.com:443").unwrap();
        assert_eq!(explicit, parsed);
    }

    #[test]
    fn an_origin_with_a_path_query_or_fragment_is_refused() {
        for raw in [
            "https://vpn.example.com/",
            "https://vpn.example.com/admin",
            "https://vpn.example.com/?x=1",
            "https://vpn.example.com#frag",
        ] {
            assert_eq!(
                CanonicalOrigin::parse(raw).unwrap_err(),
                OriginConfigError::OriginNotBare,
                "{raw} must be refused"
            );
        }
        for raw in ["vpn.example.com", "ftp://vpn.example.com", "", "https://"] {
            assert!(
                CanonicalOrigin::parse(raw).is_err(),
                "{raw} must be refused"
            );
        }
    }

    #[test]
    fn an_ipv6_literal_origin_round_trips() {
        let parsed = CanonicalOrigin::parse("http://[::1]:8000").unwrap();
        assert_eq!(parsed.host, "::1");
        assert_eq!(parsed.port, 8000);
        assert_eq!(parsed.as_header_value(), "http://[::1]:8000");
    }

    #[test]
    fn the_default_policy_is_loopback_and_accepts_both_loopback_spellings() {
        let policy = OriginPolicy::loopback_only(bind(8000));
        assert_eq!(policy.exposure, ExposureMode::LoopbackOnly);
        assert_eq!(policy.canonical.as_header_value(), "http://127.0.0.1:8000");
        assert!(!policy.is_secure());
        assert!(policy.accepts_host("127.0.0.1:8000"));
        assert!(policy.accepts_host("127.0.0.1"));
        assert!(policy.accepts_host("[::1]:8000"));
        assert!(policy.accepts_host("127.0.0.1:8000."));
    }

    #[test]
    fn a_dns_rebinding_host_is_refused_even_on_a_loopback_listener() {
        let policy = OriginPolicy::loopback_only(bind(8000));
        // The attacker-controlled name resolves to 127.0.0.1, and the listener
        // really is loopback. Neither fact says who is asking.
        for host in [
            "evil.example.com",
            "evil.example.com:8000",
            "127.0.0.1.evil.example.com",
            "localhost",
            "127.0.0.2:8000",
            "vpn.example.com",
            "",
        ] {
            assert!(!policy.accepts_host(host), "{host:?} must be refused");
        }
    }

    #[test]
    fn origin_matching_is_exact_including_scheme_and_port() {
        let policy = OriginPolicy::loopback_only(bind(8000));
        assert!(policy.accepts_origin("http://127.0.0.1:8000"));
        for origin in [
            "http://127.0.0.1:8001",
            "https://127.0.0.1:8000",
            "http://evil.example.com",
            "http://127.0.0.1.evil.example.com",
            "null",
            "",
            "   ",
        ] {
            assert!(!policy.accepts_origin(origin), "{origin:?} must be refused");
        }
    }

    #[test]
    fn a_proxy_deployment_gets_a_secure_cookie_and_hsts_eligibility() {
        let policy =
            OriginPolicy::behind_https_proxy(bind(8000), "https://vpn.example.com").unwrap();
        assert_eq!(
            policy.canonical.as_header_value(),
            "https://vpn.example.com"
        );
        assert!(policy.is_secure());
        assert_eq!(policy.session_cookie_name(), SESSION_COOKIE_SECURE_NAME);
        assert!(policy.accepts_host("vpn.example.com"));
        assert!(policy.accepts_origin("https://vpn.example.com"));
        // The internal port is not part of the external origin, so a browser
        // using it is not the canonical origin.
        assert!(!policy.accepts_origin("https://vpn.example.com:8000"));
        assert!(!policy.accepts_host("127.0.0.1:8000"));
    }

    #[test]
    fn a_proxy_deployment_must_actually_be_https() {
        assert!(
            OriginPolicy::behind_https_proxy(bind(8000), "http://vpn.example.com").is_err(),
            "an external origin over plain HTTP would claim a stable public name insecurely"
        );
    }

    #[test]
    fn a_routable_listener_needs_acknowledgement_and_cannot_claim_https() {
        let routable: SocketAddr = "0.0.0.0:8000".parse().unwrap();

        // Claiming HTTPS on a socket that speaks no TLS would put a `Secure`
        // cookie and an HSTS header on a plaintext connection.
        assert_eq!(
            OriginPolicy::acknowledged_off_host(routable, "https://vpn.example.com").unwrap_err(),
            OriginConfigError::HttpsClaimWithoutProxy
        );

        // An acknowledged plaintext origin is the operator saying "I know", and
        // is the only off-host profile Phase 7 permits.
        let ok =
            OriginPolicy::acknowledged_off_host(routable, "http://vpn.example.com:8000").unwrap();
        assert!(ok.exposure.is_off_host());
        assert!(ok.describe().contains("ROUTABLE"));
        // Acknowledging a routable listener still does not make loopback a
        // legitimate Host for it.
        assert!(!ok.accepts_host("127.0.0.1:8000"));
    }

    #[test]
    fn a_loopback_cookie_makes_no_false_secure_claim() {
        // A `Secure` cookie over plain loopback HTTP is never stored by a
        // browser, which would be a silent login failure rather than a safe
        // default.
        let policy = OriginPolicy::loopback_only(bind(8000));
        assert_eq!(policy.session_cookie_name(), SESSION_COOKIE_NAME);
        assert!(!policy.session_cookie_name().starts_with("__Host-"));
    }

    #[test]
    fn host_normalization_strips_a_trailing_dot_but_nothing_else() {
        assert_eq!(normalize_host("VPN.Example.COM."), "vpn.example.com");
        assert_eq!(normalize_host(" vpn.example.com "), "vpn.example.com");
        // A port is part of which origin is addressed and must survive.
        assert_eq!(
            normalize_host("vpn.example.com:8443"),
            "vpn.example.com:8443"
        );
    }
}
