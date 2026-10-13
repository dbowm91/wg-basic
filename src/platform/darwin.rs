//! Darwin (macOS) platform facts for the headless server target (M001).
//!
//! Owner: headless Darwin WireGuard *server*, not a macOS client app.
//! Linux remains the canonical qualified deployment.
//!
//! Support floor: macOS 13.0 (Ventura) or newer, on both
//! `aarch64-apple-darwin` (Apple Silicon) and `x86_64-apple-darwin` (Intel).
//! The floor is chosen because both target triples, `utun`/`wireguard-go`,
//! launchd system daemons, and the PF anchor model M005 evaluates are all
//! available and supportable there; older releases are not qualified and must
//! fail closed rather than degrade silently.
//!
//! M001 status: no Darwin network mutation is implemented. Every Darwin host
//! backend reports [`crate::platform::BackendCapability::Unsupported`] (when
//! the lack of support is known) or `Unknown` (when qualification is pending
//! in M002–M005). A Darwin compile and a loopback management smoke test are
//! not a working VPN server.

/// Minimum supported macOS release for the headless server target.
pub const MIN_MACOS_VERSION: &str = "13.0";
/// Minimum supported Darwin major version number.
pub const MIN_MACOS_MAJOR: u32 = 13;
/// The two native server target triples. Apple Silicon qualification and
/// Intel native evidence are distinct; Rosetta translation never counts as
/// native Intel support.
pub const SUPPORTED_TARGETS: &[&str] = &["aarch64-apple-darwin", "x86_64-apple-darwin"];
/// SDK used to establish the M001 floor (macOS 26 SDK, native arm64 host).
pub const M001_SDK_VERSION: &str = "26.5";
/// Host that produced the M001 native evidence.
pub const M001_QUALIFIED_HOST: &str = "macos-26.6.2-arm64";

/// Why the Darwin network backends are unavailable in M001.
pub const DARWIN_NETWORK_UNSUPPORTED: &str =
    "darwin host network backends are not implemented in M001; Linux remains canonical";

/// True on a macOS build.
pub fn is_darwin() -> bool {
    cfg!(target_os = "macos")
}
