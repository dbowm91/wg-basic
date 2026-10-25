use serde::{Deserialize, Serialize};
use std::{fs, os::unix::fs::MetadataExt};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Available,
    Unavailable,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCapabilitySnapshot {
    pub os: String,
    pub architecture: String,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub cap_net_admin: Option<bool>,
    pub kernel_release: Option<String>,
    pub runtime_directory_safe: bool,
    pub network_namespaces: CapabilityState,
    pub wireguard_control: CapabilityState,
    pub nftables: CapabilityState,
}

impl NetworkCapabilitySnapshot {
    #[cfg(target_os = "linux")]
    pub fn observe(runtime_directory: &std::path::Path) -> Self {
        Self {
            os: "linux".into(),
            architecture: std::env::consts::ARCH.into(),
            effective_uid: nix::unistd::geteuid().as_raw(),
            effective_gid: nix::unistd::getegid().as_raw(),
            cap_net_admin: effective_capability(12),
            kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")
                .ok()
                .map(|value| value.trim().to_owned()),
            runtime_directory_safe: safe_runtime_directory(runtime_directory),
            // These probes are intentionally deferred to their owning backends.
            network_namespaces: CapabilityState::Unknown,
            wireguard_control: CapabilityState::Unknown,
            nftables: CapabilityState::Unknown,
        }
    }

    /// Darwin observation: honest unsupported/unknown, never Linux values.
    ///
    /// `cap_net_admin` is `None` (no Linux capabilities on Darwin),
    /// `network_namespaces` is unavailable (no netns on macOS), and the
    /// nftables slot is unavailable (Darwin has no nftables; the PF backend
    /// lands with C003). The WireGuard slot reports the real Darwin control
    /// surface: the pinned userspace helper, and only when the installed
    /// helper still matches the digest the install receipt recorded. No
    /// mutation is performed.
    #[cfg(not(target_os = "linux"))]
    pub fn observe(runtime_directory: &std::path::Path) -> Self {
        Self {
            os: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            effective_uid: nix::unistd::geteuid().as_raw(),
            effective_gid: nix::unistd::getegid().as_raw(),
            cap_net_admin: None,
            kernel_release: darwin_kernel_release(),
            runtime_directory_safe: safe_runtime_directory(runtime_directory),
            network_namespaces: CapabilityState::Unavailable,
            wireguard_control: darwin_wireguard_control_state(),
            nftables: CapabilityState::Unavailable,
        }
    }
}

#[cfg(target_os = "linux")]
fn effective_capability(capability: u8) -> Option<bool> {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("CapEff:")
                    .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
            })
        })
        .map(|effective| effective & (1_u64 << capability) != 0)
}

/// The Darwin WireGuard control surface.
///
/// Darwin has no kernel WireGuard interface: the managed tunnel is a pinned
/// `wireguard-go` helper. The surface is available only when the installed
/// helper is present and still hashes to the digest the install receipt
/// recorded, so a replaced helper is reported as unavailable instead of
/// trusted.
#[cfg(not(target_os = "linux"))]
fn darwin_wireguard_control_state() -> CapabilityState {
    let Some(digest) = crate::launchd::installed_helper_digest(std::path::Path::new("/")) else {
        return CapabilityState::Unavailable;
    };
    match crate::wireguard::darwin::verify_helper_sha256(
        std::path::Path::new(crate::launchd::HELPER_PATH),
        &digest,
    ) {
        Ok(()) => CapabilityState::Available,
        Err(_) => CapabilityState::Unavailable,
    }
}

/// Darwin kernel release via the audited `nix` `uname` wrapper (no new unsafe,
/// no subprocess, no `/proc`). Returns `None` when the release string is
/// empty rather than inventing a version.
#[cfg(not(target_os = "linux"))]
fn darwin_kernel_release() -> Option<String> {
    let uts = nix::sys::utsname::uname().ok()?;
    let release = uts.release().to_str()?.trim().to_owned();
    if release.is_empty() {
        None
    } else {
        Some(release)
    }
}

fn safe_runtime_directory(path: &std::path::Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    let uid = nix::unistd::geteuid().as_raw();
    metadata.file_type().is_dir() && metadata.uid() == uid && metadata.mode() & 0o022 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn snapshot_is_read_only_and_leaves_backend_owned_probes_unknown() {
        let snapshot = NetworkCapabilitySnapshot::observe(std::path::Path::new(
            "/definitely/not/a/runtime/path",
        ));
        assert_eq!(snapshot.os, "linux");
        assert!(!snapshot.runtime_directory_safe);
        assert_eq!(snapshot.network_namespaces, CapabilityState::Unknown);
        assert_eq!(snapshot.wireguard_control, CapabilityState::Unknown);
        assert_eq!(snapshot.nftables, CapabilityState::Unknown);
        assert!(snapshot.kernel_release.is_some());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn darwin_snapshot_reports_unsupported_never_linux_values() {
        let snapshot = NetworkCapabilitySnapshot::observe(std::path::Path::new(
            "/definitely/not/a/runtime/path",
        ));
        assert_eq!(snapshot.os, std::env::consts::OS);
        assert!(!snapshot.runtime_directory_safe);
        // No Linux capability, namespace, or backend is ever reported as
        // available on Darwin in M001.
        assert_eq!(snapshot.cap_net_admin, None);
        assert_eq!(snapshot.network_namespaces, CapabilityState::Unavailable);
        // The Darwin WireGuard slot reports the real helper, never a Linux
        // value and never an optimistic "available".
        assert_ne!(snapshot.wireguard_control, CapabilityState::Unknown);
        assert_eq!(snapshot.nftables, CapabilityState::Unavailable);
        // uname-backed release, never a /proc read.
        assert!(snapshot.kernel_release.is_some());
    }
}
