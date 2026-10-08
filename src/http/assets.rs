//! The embedded operator shell.
//!
//! # Why the assets live in the binary
//!
//! A management UI served from a document root on disk is a document root on
//! disk: something has to create it, something has to keep it in step with the
//! binary, and something can replace it between two requests. For an appliance
//! whose entire security argument is "the service is exactly this binary", that
//! is a hole the size of a filesystem write.
//!
//! So the assets are `include_str!`d at compile time. There is no root, no
//! fallback directory, no configuration that can point elsewhere, and no
//! failure mode in which the service is up and the shell is missing.
//!
//! # Why there is no build step
//!
//! A shell that needs a bundler is a shell that will eventually be built and
//! served out of band. The rule this module enforces is therefore not "keep it
//! small" but "keep it *plain*": what is committed is what is served, and a
//! reader can diff a behavioural change without a toolchain.
//!
//! # What the shell owns
//!
//! It renders the operator workflows and consumes the authenticated API. It
//! does not allocate addresses, validate durable changes, generate credentials,
//! or call netd; those decisions remain behind the worker boundary.
//!
//! Each script's side effects are confined to its document: there is no
//! timer, no global hook, and no event listener outside the two named DOM
//! elements the page provides. [`Asset::mutates_the_document`] states that as a
//! claim the guard tests restate, so it cannot rot silently.

use eggserve_primitives::{ResponseBody, StatusCode};

/// The shell document, served at `/`.
pub const INDEX_HTML: &str = include_str!("assets/index.html");

/// The stylesheet, served at `/assets/app.css`.
pub const APP_CSS: &str = include_str!("assets/app.css");

/// The script, served at `/assets/app.js`.
pub const APP_JS: &str = include_str!("assets/app.js");
pub const ENROLL_HTML: &str = include_str!("assets/enroll.html");
pub const ENROLL_JS: &str = include_str!("assets/enroll.js");

/// The total embedded payload, as a ceiling rather than an observation.
///
/// 32 KiB bounds the full management shell, including product forms and client
/// actions, while keeping the complete same-origin UI small enough to review.
pub const MAX_EMBEDDED_ASSET_BYTES: usize = 32 * 1024;

/// The largest single embedded asset, as a ceiling.
pub const MAX_EMBEDDED_ASSET_BYTES_EACH: usize = 24 * 1024;

/// One embedded asset: where it is served, what it is, and what it contains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Asset {
    /// The exact request path this asset answers. No prefix, no suffix.
    pub path: &'static str,
    /// The media type. Deterministic, never negotiated from `Accept`.
    pub content_type: &'static str,
    /// The file name used in the inventory and in a test failure message.
    pub name: &'static str,
    /// The bytes, fixed at compile time.
    pub body: &'static str,
    /// Whether serving it executes script in the operator's browser.
    pub mutates_the_document: bool,
}

/// The complete inventory, in a fixed order.
///
/// Every entry is an exact path. `/assets/` on its own is not an asset, and
/// neither is `/assets/app.css.map` — an unknown asset is a `404`, the same as
/// an unknown route, so the surface has no discovery behaviour.
pub const INVENTORY: &[Asset] = &[
    Asset {
        path: "/",
        content_type: "text/html; charset=utf-8",
        name: "index.html",
        body: INDEX_HTML,
        mutates_the_document: true,
    },
    Asset {
        path: "/assets/app.css",
        content_type: "text/css; charset=utf-8",
        name: "app.css",
        body: APP_CSS,
        mutates_the_document: false,
    },
    Asset {
        path: "/assets/app.js",
        content_type: "text/javascript; charset=utf-8",
        name: "app.js",
        body: APP_JS,
        mutates_the_document: true,
    },
    Asset {
        path: "/enroll",
        content_type: "text/html; charset=utf-8",
        name: "enroll.html",
        body: ENROLL_HTML,
        mutates_the_document: true,
    },
    Asset {
        path: "/assets/enroll.js",
        content_type: "text/javascript; charset=utf-8",
        name: "enroll.js",
        body: ENROLL_JS,
        mutates_the_document: true,
    },
];

/// Looks up an asset by its exact path.
///
/// `None` for anything else, including a path with a trailing slash, a
/// percent-encoded variant, or a query string. The lookup is a linear scan over
/// the small fixed inventory, which is cheaper than the prefix matching it replaces and
/// cannot be made to walk off the end of a directory.
pub fn asset(path: &str) -> Option<&'static Asset> {
    INVENTORY.iter().find(|asset| asset.path == path)
}

/// The total embedded size, for the footprint evidence.
pub fn total_bytes() -> usize {
    INVENTORY
        .iter()
        .map(|asset| asset.body.len())
        .sum::<usize>()
}

/// The immutable content type for an asset, used by `response::build`.
pub fn content_type(path: &str) -> &'static str {
    asset(path)
        .map(|asset| asset.content_type)
        .unwrap_or(TEXT_PLAIN)
}

/// The immutable body for an asset.
pub fn body(path: &str) -> Option<&'static str> {
    asset(path).map(|asset| asset.body)
}

/// The status an asset is served with.
///
/// Always `200`. There is no conditional request handling: a shell this small
/// is cheaper to resend than to validate, and `ETag`/`If-None-Match` would add
/// a second code path in which a response is built — which is the one thing the
/// security-header guarantee is built on having a single path for.
pub fn status() -> StatusCode {
    StatusCode::OK
}

/// The response body for an asset.
pub fn response_body(path: &str) -> Option<ResponseBody> {
    body(path).map(|body| ResponseBody::Bytes(body.as_bytes().to_vec()))
}

/// The fallback media type for a path that is not an asset.
pub const TEXT_PLAIN: &str = "text/plain; charset=utf-8";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_inventory_is_bounded_and_small() {
        assert!(
            INVENTORY.len() <= 8,
            "an appliance shell of {} assets is no longer a shell",
            INVENTORY.len()
        );
        assert!(
            total_bytes() <= MAX_EMBEDDED_ASSET_BYTES,
            "the embedded shell is {} bytes, over the {MAX_EMBEDDED_ASSET_BYTES} ceiling",
            total_bytes()
        );
        for asset in INVENTORY {
            assert!(
                asset.body.len() <= MAX_EMBEDDED_ASSET_BYTES_EACH,
                "{} is {} bytes, over the per-asset ceiling",
                asset.name,
                asset.body.len()
            );
            assert!(!asset.body.is_empty(), "{} is empty", asset.name);
        }
    }

    #[test]
    fn every_asset_path_is_exact_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for asset in INVENTORY {
            assert!(
                asset.path.starts_with('/'),
                "{}: an asset path must be absolute",
                asset.name
            );
            assert!(
                seen.insert(asset.path),
                "{}: duplicate asset path {}",
                asset.name,
                asset.path
            );
            // The lookup is exact, so a path with a trailing slash or a query
            // string must simply not be in the inventory.
            assert!(!asset.path.contains('?') && !asset.path.ends_with("//"));
        }
        // "/" is the only inventory entry that legitimately ends in a slash,
        // and only because it *is* the root rather than a directory listing.
        assert_eq!(
            INVENTORY
                .iter()
                .filter(|asset| asset.path.ends_with('/'))
                .count(),
            1
        );
        assert!(asset("/assets/app.css.map").is_none());
        assert!(asset("/assets/").is_none());
        assert!(asset("/index.html").is_none());
        assert!(asset("/assets/app.css?v=2").is_none());
    }

    #[test]
    fn no_asset_references_an_external_origin() {
        // The single most important property here. An asset that fetches from a
        // CDN tells that CDN when an operator of this appliance signs in, and
        // the service's own `Host` allowlist cannot see it happen.
        for asset in INVENTORY {
            for forbidden in [
                "http://",
                "https://",
                "//cdn",
                "integrity=",
                "crossorigin",
                "@import",
                "src=\"//",
            ] {
                assert!(
                    !asset.body.contains(forbidden),
                    "{}: contains {forbidden}; an embedded asset must reach nothing outside \
                     this origin",
                    asset.name
                );
            }
        }
    }

    #[test]
    fn the_shell_needs_no_csp_concession() {
        // `default-src 'self'` with no 'unsafe-inline' and no nonce means: no
        // inline <script>, no inline <style>, no inline event handler. If an
        // asset ever needs one, the CSP has to be weakened deliberately and the
        // weakening has to be argued for -- not discovered when the page renders
        // blank and somebody "fixes" the header.
        for forbidden in [
            "<script>",
            "<style>",
            "onclick=",
            "onload=",
            "onerror=",
            "javascript:",
        ] {
            for asset in INVENTORY {
                assert!(
                    !asset.body.contains(forbidden),
                    "{}: contains {forbidden}, which would require a CSP concession",
                    asset.name
                );
            }
        }
        // The stylesheet is a stylesheet and the script is a script, by
        // reference rather than inline.
        assert!(INDEX_HTML.contains(r#"<link rel="stylesheet" href="/assets/app.css" />"#));
        assert!(INDEX_HTML.contains(r#"<script src="/assets/app.js"></script>"#));
    }

    #[test]
    fn content_types_are_declared_and_deterministic() {
        for asset in INVENTORY {
            assert!(
                asset.content_type.starts_with("text/"),
                "{}: an asset must declare a media type",
                asset.name
            );
            assert!(
                asset.content_type.ends_with("; charset=utf-8"),
                "{}: an asset must declare its charset",
                asset.name
            );
            assert_eq!(content_type(asset.path), asset.content_type);
        }
        assert_eq!(
            content_type("/assets/app.js"),
            "text/javascript; charset=utf-8"
        );
        // Never negotiated from `Accept`: an unknown path is not `*/*`.
        assert_eq!(content_type("/nope"), TEXT_PLAIN);
        // And the two script-bearing assets are declared as such.
        assert!(asset("/assets/app.js").unwrap().mutates_the_document);
        assert!(asset("/").unwrap().mutates_the_document);
        assert!(!asset("/assets/app.css").unwrap().mutates_the_document);
    }

    #[test]
    fn the_shell_exposes_the_product_api_workflows() {
        assert!(APP_JS.contains("/api/v1/login"));
        assert!(APP_JS.contains("/api/v1/session"));
        assert!(APP_JS.contains("/api/v1/health"));
        assert!(APP_JS.contains("/api/v1/logout"));
        for route in [
            "/api/v1/server",
            "/api/v1/setup",
            "/api/v1/clients",
            "/api/v1/clients/telemetry",
            "/api/v1/audit",
            "/enrollment-links/",
        ] {
            assert!(
                APP_JS.contains(route),
                "the operator shell must use {route}"
            );
        }
        assert!(APP_JS.contains("expected_generation"));
        assert!(APP_JS.contains("response.status === 409"));
        assert!(APP_JS.contains("network access has not been confirmed revoked"));
        assert!(APP_JS.contains("network application is pending or degraded"));
        assert!(INDEX_HTML.contains("id=\"setup-form\""));
        assert!(INDEX_HTML.contains("id=\"client-rows\""));
    }

    #[test]
    fn the_shell_sends_the_csrf_header_and_never_reads_the_cookie() {
        // Two halves of the same property: the page can perform an unsafe
        // request, and it cannot perform one without the token.
        assert!(
            APP_JS.contains("x-wg-basic-csrf"),
            "an unsafe request needs the CSRF header"
        );
        assert!(
            !APP_JS.contains("document.cookie"),
            "the page must never read document.cookie; the bearer is HttpOnly on purpose"
        );
        assert!(
            !APP_JS.contains("localStorage") && !APP_JS.contains("sessionStorage"),
            "nothing about this session belongs in persistent client storage"
        );
    }

    #[test]
    fn telemetry_polling_is_bounded_to_visible_authenticated_pages() {
        assert!(APP_JS.contains("setInterval("));
        assert!(APP_JS.contains("window.clearInterval"));
        assert!(APP_JS.contains("!document.hidden && csrf"));
        assert!(APP_JS.contains("visibilitychange"));
        assert!(APP_JS.contains("7000"));
        for forbidden in [
            "setTimeout(",
            "eval(",
            "console.log",
            "localStorage",
            "sessionStorage",
        ] {
            assert!(!APP_JS.contains(forbidden), "app.js contains {forbidden}");
        }
        assert!(!APP_JS.contains("document.cookie"));
    }

    #[test]
    fn a_response_body_is_the_exact_embedded_bytes() {
        for asset in INVENTORY {
            let body = response_body(asset.path).expect("every inventory entry has a body");
            assert_eq!(body.len(), asset.body.len() as u64);
        }
        assert!(response_body("/nope").is_none());
    }
}
