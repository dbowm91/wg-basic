//! Darwin (macOS) platform facts for the headless server target.
//!
//! Owner: headless Darwin WireGuard *server*, not a macOS client app.
//! Linux remains the canonical qualified deployment.
//!
//! Support floor: macOS 13.0 (Ventura) or newer, on `aarch64-apple-darwin`
//! (Apple Silicon). Controlled-host evidence exists on macOS 15.x hosted and
//! macOS 26.6.2 arm64 guests. Older releases are not qualified and must fail
//! closed rather than degrade silently.
//!
//! Apple silicon is the only Darwin target (ADR-009). Intel Macs are refused
//! at install time. Rosetta never counts as native support.
//!
//! Release authority: ADR-014 amends M007 MUST-NOT-release for Apple silicon
//! under checksums-only policy. Operator “supported” claims wait on C015
//! teardown evidence and C005 packaging closure. Darwin self-update is not
//! authorized.

/// Minimum supported macOS release for the headless server target.
pub const MIN_MACOS_VERSION: &str = "13.0";
/// Minimum supported Darwin major version number.
pub const MIN_MACOS_MAJOR: u32 = 13;
/// The native server target triple. Apple silicon is the only Darwin target
/// (ADR-009): the managed server's supported target set is closed, and an
/// Intel Mac is refused at install time instead of running an unqualified
/// build.
pub const SUPPORTED_TARGETS: &[&str] = &["aarch64-apple-darwin"];
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
