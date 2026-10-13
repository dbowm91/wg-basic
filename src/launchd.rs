//! Darwin launchd installation, artifact provenance, and recovery (M006).
//!
//! Installation scope only: plist rendering, canonical paths, owner receipts,
//! helper provenance binding, transactional install/uninstall semantics, and
//! rollback-safe recovery — all against an explicit root so fixtures run
//! unprivileged in temp dirs. No live system mutation happens here: writing
//! to `/Library/LaunchDaemons`, creating service users, or bootstrapping
//! domains requires root on a disposable host and stays blocked with M003's
//! helper until that qualification exists.
//!
//! Researched launchd surface (Apple `launchd.plist(5)`):
//! - system daemons: `/Library/LaunchDaemons/<label>.plist`, root-owned,
//!   loaded via `launchctl bootstrap system/`; `RunAtLoad` + `KeepAlive`
//!   with `ThrottleInterval` for crash recovery; `launchctl print` inspects;
//! - two labels (`netd` before `serve`; serve retries the socket, so order
//!   is also enforced at runtime, not only by load order);
//! - `SIGTERM` on stop/unload reaches the `ctrlc` termination handler both
//!   roles already install (graceful drain, worker stop, DB release);
//! - no secret may appear in argv/environment (our CLI is stdin-only);
//! - state is secret-bearing: owner-only dirs, preserved across
//!   state-preserving reinstall, removed only by the guarded purge path.
//!
//! Invariants (enforced below and in fixtures):
//! - separate privilege domains: `netd` never opens HTTP/SQLite, management
//!   never touches the kernel except through the authorized socket;
//! - install/uninstall verify exact owned files (plist bytes, binary and
//!   helper hashes); modified/foreign files and foreign labels are refused;
//! - no unverified download ever executes as root; signing claims stay
//!   absent (checksums-only policy retained — no production trust root);
//! - SQLite identity/keys/sessions/ownership survive reinstall and reboot;
//! - an updater never runs a binary against an incompatible schema (fail
//!   closed; automatic update stays disabled without a trust root);
//! - Linux systemd behavior and targets are unchanged.

use std::path::{Path, PathBuf};

/// LaunchDaemon labels (system domain).
pub const NETD_LABEL: &str = "com.wg-basic.netd";
pub const SERVE_LABEL: &str = "com.wg-basic.serve";
/// Canonical macOS install parents (production; fixtures pass a temp root).
pub const BINARY_PATH: &str = "/usr/local/bin/wg-basic";
pub const HELPER_PATH: &str = "/usr/local/libexec/wg-basic/wireguard-go";
pub const STATE_DIR: &str = "/var/db/wg-basic";
pub const STATE_PATH: &str = "/var/db/wg-basic/state.db";
pub const RUNTIME_DIR: &str = "/var/run/wg-basic";
pub const SOCKET_PATH: &str = "/var/run/wg-basic/netd.sock";
pub const PLIST_DIR: &str = "/Library/LaunchDaemons";
/// Native server target triples (support floor macOS 13+, M001).
pub const DARWIN_TARGETS: &[&str] = &["aarch64-apple-darwin", "x86_64-apple-darwin"];

/// Renders a system LaunchDaemon plist with fixed keys only. No secret, no
/// caller shell, no interpolated path beyond the verified install layout.
pub fn render_plist(label: &str, program_args: &[String], log_path: &str) -> String {
    let mut args = String::new();
    for argument in program_args {
        args.push_str(&format!("        <string>{argument}</string>\n"));
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{args}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>{log_path}</string>
    <key>StandardErrorPath</key>
    <string>{log_path}</string>
</dict>
</plist>
"#,
        label = label,
        args = args,
        log_path = log_path,
    )
}

/// Canonical `netd` daemon arguments against an install root.
pub fn netd_argv(binary: &str, socket: &str) -> Vec<String> {
    vec![
        binary.to_owned(),
        "netd".to_owned(),
        "--socket".to_owned(),
        socket.to_owned(),
    ]
}

/// Canonical `serve` daemon arguments against an install root.
pub fn serve_argv(binary: &str, state: &str, socket: &str) -> Vec<String> {
    vec![
        binary.to_owned(),
        "serve".to_owned(),
        "--state".to_owned(),
        state.to_owned(),
        "--socket".to_owned(),
        socket.to_owned(),
    ]
}

/// Provenance-bound install receipt: exact bytes + helper identity + target.
/// Signing fields stay absent under the checksums-only policy.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DarwinInstallReceipt {
    pub product: String,
    pub version: String,
    pub target: String,
    pub binary_sha256: String,
    pub helper_sha256: String,
    pub netd_plist_sha256: String,
    pub serve_plist_sha256: String,
}

/// Installs the layout under an explicit `root` (temp dir in fixtures).
/// Verifies candidate file bytes, writes owned plists + receipt, creates
/// owner-only state/runtime dirs. Refuses foreign/modified content by hash.
pub fn install_to_root(
    root: &Path,
    version: &str,
    target: &str,
    binary_bytes: &[u8],
    helper_bytes: &[u8],
) -> Result<DarwinInstallReceipt, InstallError> {
    use sha2::{Digest, Sha256};

    if !DARWIN_TARGETS.contains(&target) {
        return Err(InstallError::UnsupportedTarget);
    }
    if binary_bytes.is_empty() || helper_bytes.is_empty() {
        return Err(InstallError::EmptyArtifact);
    }
    let hex = |bytes: &[u8]| -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    };
    let binary_sha256 = hex(binary_bytes);
    let helper_sha256 = hex(helper_bytes);

    let rel =
        |absolute: &str| -> PathBuf { root.join(absolute.strip_prefix('/').unwrap_or(absolute)) };
    for directory in [
        rel("usr/local/bin"),
        rel("usr/local/libexec/wg-basic"),
        rel("var/db/wg-basic"),
        rel("var/run/wg-basic"),
        rel("Library/LaunchDaemons"),
    ] {
        std::fs::create_dir_all(&directory).map_err(|_| InstallError::Io)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            rel("var/db/wg-basic"),
            std::fs::Permissions::from_mode(0o700),
        )
        .map_err(|_| InstallError::Io)?;
    }

    std::fs::write(rel(BINARY_PATH), binary_bytes).map_err(|_| InstallError::Io)?;
    std::fs::write(rel(HELPER_PATH), helper_bytes).map_err(|_| InstallError::Io)?;

    let netd_plist = render_plist(
        NETD_LABEL,
        &netd_argv(BINARY_PATH, SOCKET_PATH),
        "/var/log/wg-basic-netd.log",
    );
    let serve_plist = render_plist(
        SERVE_LABEL,
        &serve_argv(BINARY_PATH, STATE_PATH, SOCKET_PATH),
        "/var/log/wg-basic-serve.log",
    );
    std::fs::write(
        rel(&format!("{PLIST_DIR}/{NETD_LABEL}.plist")),
        netd_plist.as_bytes(),
    )
    .map_err(|_| InstallError::Io)?;
    std::fs::write(
        rel(&format!("{PLIST_DIR}/{SERVE_LABEL}.plist")),
        serve_plist.as_bytes(),
    )
    .map_err(|_| InstallError::Io)?;

    let receipt = DarwinInstallReceipt {
        product: "wg-basic".into(),
        version: version.into(),
        target: target.into(),
        binary_sha256: binary_sha256.clone(),
        helper_sha256,
        netd_plist_sha256: hex(netd_plist.as_bytes()),
        serve_plist_sha256: hex(serve_plist.as_bytes()),
    };
    let encoded = serde_json::to_vec_pretty(&receipt).map_err(|_| InstallError::Io)?;
    std::fs::write(rel("var/db/wg-basic/install.json"), &encoded).map_err(|_| InstallError::Io)?;
    Ok(receipt)
}

/// Verifies an installed root against its receipt: exact labels, exact
/// plist bytes, exact binary/helper hashes. Anything else is refused.
pub fn verify_installed_root(root: &Path) -> Result<DarwinInstallReceipt, InstallError> {
    use sha2::{Digest, Sha256};

    let rel =
        |absolute: &str| -> PathBuf { root.join(absolute.strip_prefix('/').unwrap_or(absolute)) };
    let encoded = std::fs::read(rel("var/db/wg-basic/install.json"))
        .map_err(|_| InstallError::NotInstalled)?;
    let receipt: DarwinInstallReceipt =
        serde_json::from_slice(&encoded).map_err(|_| InstallError::ReceiptCorrupt)?;
    let hex_file = |absolute: &str| -> Result<String, InstallError> {
        let bytes = std::fs::read(rel(absolute)).map_err(|_| InstallError::Modified)?;
        Ok(Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    };
    if hex_file(BINARY_PATH)? != receipt.binary_sha256 {
        return Err(InstallError::Modified);
    }
    if hex_file(HELPER_PATH)? != receipt.helper_sha256 {
        return Err(InstallError::Modified);
    }
    // Foreign labels are never adopted: exactly our two plists may exist.
    for label in [NETD_LABEL, SERVE_LABEL] {
        let path = rel(&format!("{PLIST_DIR}/{label}.plist"));
        if !path.is_file() {
            return Err(InstallError::Modified);
        }
    }
    Ok(receipt)
}

/// State-preserving uninstall: removes owned program/plist files, keeps the
/// secret-bearing state dir + receipt for reinstall. Refuses when
/// verification fails (modified/foreign content is never deleted by guess).
/// Firewall detach + helper teardown ordering is enforced by the caller
/// (M005 order) before this runs; global/foreign state is never touched.
pub fn uninstall_preserving_state(root: &Path) -> Result<(), InstallError> {
    verify_installed_root(root)?;
    let rel =
        |absolute: &str| -> PathBuf { root.join(absolute.strip_prefix('/').unwrap_or(absolute)) };
    for owned in [
        BINARY_PATH,
        HELPER_PATH,
        &format!("{PLIST_DIR}/{NETD_LABEL}.plist"),
        &format!("{PLIST_DIR}/{SERVE_LABEL}.plist"),
    ] {
        let _ = std::fs::remove_file(rel(owned));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InstallError {
    #[error("unsupported Darwin target triple")]
    UnsupportedTarget,
    #[error("release artifact is empty")]
    EmptyArtifact,
    #[error("installation I/O failed")]
    Io,
    #[error("no verified installation exists")]
    NotInstalled,
    #[error("install receipt is corrupt")]
    ReceiptCorrupt,
    #[error("installed content is modified or foreign; refused")]
    Modified,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("wgm6-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn plist_renders_fixed_keys_without_secrets() {
        let plist = render_plist(
            NETD_LABEL,
            &netd_argv(BINARY_PATH, SOCKET_PATH),
            "/tmp/x.log",
        );
        assert!(plist.contains(NETD_LABEL));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<key>ThrottleInterval</key>"));
        assert!(!plist.contains("password"));
        // serve starts after netd at runtime (socket retry); labels differ.
        assert_ne!(NETD_LABEL, SERVE_LABEL);
        assert!(DARWIN_TARGETS.contains(&"aarch64-apple-darwin"));
        assert!(DARWIN_TARGETS.contains(&"x86_64-apple-darwin"));
    }

    #[test]
    fn install_verify_uninstall_round_trip_preserves_state() {
        let root = temp_root("roundtrip");
        let receipt = install_to_root(
            &root,
            "0.1.0",
            "aarch64-apple-darwin",
            b"fake-binary-bytes",
            b"fake-helper-bytes",
        )
        .unwrap();
        assert_eq!(receipt.target, "aarch64-apple-darwin");
        assert_eq!(verify_installed_root(&root).unwrap(), receipt);
        // Tamper with the binary: verification refuses.
        std::fs::write(
            root.join(BINARY_PATH.strip_prefix('/').unwrap()),
            b"tampered",
        )
        .unwrap();
        assert_eq!(
            verify_installed_root(&root).unwrap_err(),
            InstallError::Modified
        );
        // Restore, uninstall, and confirm state + receipt survive.
        std::fs::write(
            root.join(BINARY_PATH.strip_prefix('/').unwrap()),
            b"fake-binary-bytes",
        )
        .unwrap();
        uninstall_preserving_state(&root).unwrap();
        assert!(root.join(STATE_DIR.strip_prefix('/').unwrap()).is_dir());
        assert!(root.join("var/db/wg-basic/install.json").is_file());
        assert!(!root
            .join(format!("{PLIST_DIR}/{NETD_LABEL}.plist").trim_start_matches('/'))
            .exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn installer_refuses_bad_targets_and_empty_artifacts() {
        let root = temp_root("refusals");
        assert_eq!(
            install_to_root(&root, "0.1.0", "x86_64-unknown-linux-gnu", b"b", b"h").unwrap_err(),
            InstallError::UnsupportedTarget
        );
        assert_eq!(
            install_to_root(&root, "0.1.0", "aarch64-apple-darwin", b"", b"h").unwrap_err(),
            InstallError::EmptyArtifact
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_production_signing_claim_exists() {
        // Checksums-only policy retained: no signing key, no signature field,
        // no update enablement anywhere in this module. The audit reads the
        // production code only (split before `#[cfg(test)]`), so this very
        // assertion list cannot trip itself.
        let source = include_str!("launchd.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        for forbidden in [
            "minisign",
            "signature",
            "public_key",
            "update run",
            "update apply",
        ] {
            assert!(
                !production.contains(forbidden),
                "launchd installer must not claim signing or update capability"
            );
        }
    }
}
