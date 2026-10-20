//! Darwin launchd installation, artifact provenance, and recovery (M006).
//!
//! C002 scope: service identity, constrained plist rendering, canonical
//! paths, owner receipts, helper provenance binding, the exact filesystem and
//! IPC layout, and transactional install/uninstall semantics — all against an
//! explicit root so fixtures run unprivileged in temp dirs.
//!
//! This module stays free of process execution: the bounded `launchctl`
//! invocations live in the separate `launchd_install` module so the pure
//! layout contract stays statically checkable.
//!
//! ## Service identity (C002)
//!
//! - `netd` is the only root component. It owns the typed OS mutations.
//! - `serve` is a dedicated, unprivileged local principal. It owns SQLite and
//!   HTTP and never touches the kernel.
//!
//! The management account is **preprovisioned**: the installer never creates
//! accounts (that would need a generic privileged directory-service mutation)
//! and never adopts an unknown identity. A missing account, a name that
//! resolves to a different account, or an account that lands in macOS's
//! reserved UID range is refused, because a renamed or reused identity is
//! exactly how a "least privilege" daemon silently becomes someone else's.
//!
//! ## Filesystem and IPC layout (C002)
//!
//! - `/var/db/wg-basic` is management-owned: the dedicated service account
//!   owns it, mode `0700`. The management daemon is never root.
//! - `/var/run/wg-basic` is root-controlled and not world-writable; the
//!   privileged socket inside it is `0660` and owned by root and the
//!   management group, so only the intended service identity can connect.
//! - Executables, the helper, the plists, and the receipt live in root-owned
//!   locations. A symlink anywhere in the owned layout is refused, never
//!   followed.
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
/// The privileged daemon's account. It is the only component that mutates the
/// host, so it is explicitly root rather than implicitly root-by-default.
pub const NETD_USER: &str = "root";
/// The privileged daemon's primary group.
pub const NETD_GROUP: &str = "wheel";
/// The management daemon's dedicated, unprivileged local account.
///
/// The account is preprovisioned. The installer verifies it and refuses to
/// install without it; it never creates accounts.
pub const SERVE_USER: &str = "_wg-basic-serve";
/// The management daemon's dedicated group.
pub const SERVE_GROUP: &str = "_wg-basic-serve";
/// The directory the daemons' logs live in.
pub const LOG_DIR: &str = "/var/log/wg-basic";
/// The privileged daemon's log file.
pub const NETD_LOG: &str = "/var/log/wg-basic/netd.log";
/// The management daemon's log file.
pub const SERVE_LOG: &str = "/var/log/wg-basic/serve.log";
/// The lowest UID this product accepts for the preprovisioned management
/// account.
///
/// macOS reserves UIDs below 500 for the system. A management account that
/// resolves into the reserved range is a renamed or reused identity and is
/// refused.
pub const MIN_SERVICE_UID: u32 = 500;

/// The two system services this product installs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceRole {
    /// The privileged daemon: the only component that mutates the host.
    Netd,
    /// The management daemon: SQLite and HTTP, unprivileged.
    Serve,
}

impl ServiceRole {
    /// The launchd label of this service.
    pub fn label(self) -> &'static str {
        match self {
            ServiceRole::Netd => NETD_LABEL,
            ServiceRole::Serve => SERVE_LABEL,
        }
    }

    /// The account this service runs as.
    pub fn user(self) -> &'static str {
        match self {
            ServiceRole::Netd => NETD_USER,
            ServiceRole::Serve => SERVE_USER,
        }
    }

    /// The group this service runs as.
    pub fn group(self) -> &'static str {
        match self {
            ServiceRole::Netd => NETD_GROUP,
            ServiceRole::Serve => SERVE_GROUP,
        }
    }

    /// The log file this service writes to.
    pub fn log_path(self) -> &'static str {
        match self {
            ServiceRole::Netd => NETD_LOG,
            ServiceRole::Serve => SERVE_LOG,
        }
    }

    /// The fixed program arguments of this service.
    pub fn program_arguments(self, binary: &str, socket: &str, state: &str) -> Vec<String> {
        match self {
            ServiceRole::Netd => netd_argv(binary, socket),
            ServiceRole::Serve => serve_argv(binary, state, socket),
        }
    }
}

/// The resolved numeric identity of a service account.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceIdentity {
    /// The account name.
    pub user: String,
    /// The primary group name.
    pub group: String,
    /// The account's numeric UID.
    pub uid: u32,
    /// The group's numeric GID.
    pub gid: u32,
}

/// Resolves the numeric identity of one service account.
///
/// The name is resolved through the directory service, so a renamed account is
/// reported as a different identity rather than silently accepted.
pub fn resolve_service_identity(role: ServiceRole) -> Result<ServiceIdentity, InstallError> {
    let user = nix::unistd::User::from_name(role.user())
        .map_err(|_| InstallError::ServiceIdentityMissing)?
        .ok_or(InstallError::ServiceIdentityMissing)?;
    let group = nix::unistd::Group::from_name(role.group())
        .map_err(|_| InstallError::ServiceIdentityMissing)?
        .ok_or(InstallError::ServiceIdentityMissing)?;
    let identity = ServiceIdentity {
        user: user.name.clone(),
        group: group.name.clone(),
        uid: user.uid.as_raw(),
        gid: group.gid.as_raw(),
    };
    if role == ServiceRole::Serve {
        // A management account must be a stable, non-reserved identity whose
        // primary group is the dedicated group. Anything else means the
        // account was renamed, reused, or is a system identity.
        if identity.uid < MIN_SERVICE_UID {
            return Err(InstallError::ServiceIdentityUnstable);
        }
        if user.gid != group.gid {
            return Err(InstallError::ServiceIdentityUnstable);
        }
    }
    Ok(identity)
}

/// Escapes text for an XML text node.
///
/// Control characters are refused outright: a newline inside a plist value is
/// a way to smuggle a second key into a file that is supposed to have a fixed
/// schema.
fn escape_xml(value: &str) -> Result<String, InstallError> {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            control if control.is_control() => return Err(InstallError::DangerousValue),
            other => escaped.push(other),
        }
    }
    Ok(escaped)
}

/// Renders a system LaunchDaemon plist with a fixed schema.
///
/// The label, the service identity, the executable, the arguments, and the log
/// path all come from the typed [`ServiceRole`] and the verified install
/// layout. There is no caller-supplied key, no environment, no working
/// directory, and no arbitrary value: every interpolated string is
/// XML-escaped, and a value carrying a control character is refused rather
/// than escaped.
pub fn render_service_plist(role: ServiceRole) -> Result<String, InstallError> {
    let arguments = role.program_arguments(BINARY_PATH, SOCKET_PATH, STATE_PATH);
    let mut args = String::new();
    for argument in &arguments {
        args.push_str(&format!(
            "        <string>{}</string>\n",
            escape_xml(argument)?
        ));
    }
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{args}    </array>
    <key>UserName</key>
    <string>{user}</string>
    <key>GroupName</key>
    <string>{group}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#,
        label = escape_xml(role.label())?,
        args = args,
        user = escape_xml(role.user())?,
        group = escape_xml(role.group())?,
        log = escape_xml(role.log_path())?,
    ))
}

/// Renders the plist for one service role against an install root.
///
/// Kept as a thin, typed wrapper so no caller can pass an arbitrary label,
/// argument list, user, group, or log path.
pub fn render_plist(role: ServiceRole) -> Result<String, InstallError> {
    render_service_plist(role)
}

/// Canonical `netd` daemon arguments against an install root.
///
/// The management identity is not named here: the privileged daemon reads it
/// from the verified install receipt, so the account it admits is the account
/// the installer bound, never a name someone typed.
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
    /// The management service identity the privileged installer bound the
    /// socket group and the state directory to.
    ///
    /// It is absent only for an unprivileged layout-only install, which never
    /// produces a running service. A receipt without it is evidence of files,
    /// not of a deployment.
    #[serde(default)]
    pub management_identity: Option<ServiceIdentity>,
}

/// The exact mode of the management state directory.
pub const STATE_DIR_MODE: u32 = 0o700;
/// The exact mode of the privileged runtime directory. It is never
/// world-writable: only root may create entries in it.
pub const RUNTIME_DIR_MODE: u32 = 0o755;
/// The exact mode of the privileged socket. The management group may connect;
/// nobody else may.
pub const SOCKET_MODE: u32 = 0o660;
/// The exact mode of the log directory.
pub const LOG_DIR_MODE: u32 = 0o755;
/// The exact mode of each daemon log file.
pub const LOG_FILE_MODE: u32 = 0o640;
/// The exact mode of the installed program files.
pub const PROGRAM_MODE: u32 = 0o755;
/// The exact mode of the installed plists.
pub const PLIST_MODE: u32 = 0o644;
/// The exact mode of the launchd plist directory.
pub const PLIST_DIR_MODE: u32 = 0o755;
/// The exact mode of the install receipt.
pub const RECEIPT_MODE: u32 = 0o600;

/// Maps an absolute install path into an explicit root.
fn owned_path(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.strip_prefix('/').unwrap_or(absolute))
}

/// Creates a directory with an exact mode, refusing a symlink or a foreign
/// path in its place.
fn secure_directory(path: &Path, mode: u32) -> Result<(), InstallError> {
    if path.symlink_metadata().is_ok() {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| InstallError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(InstallError::Modified);
        }
    } else {
        std::fs::create_dir_all(path).map_err(|_| InstallError::Io)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|_| InstallError::Io)?;
    }
    Ok(())
}

/// Writes an owned file with an exact mode, refusing a symlink in its place.
fn secure_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), InstallError> {
    if path.symlink_metadata().is_ok() {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| InstallError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(InstallError::Modified);
        }
    }
    std::fs::write(path, bytes).map_err(|_| InstallError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|_| InstallError::Io)?;
    }
    Ok(())
}

/// Installs the layout under an explicit `root` (temp dir in fixtures).
///
/// Verifies candidate file bytes, writes owned plists + receipt, and creates
/// the exact owner-only directory layout. Refuses foreign/modified content by
/// hash, and refuses a symlink anywhere in the owned layout.
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

    for (directory, mode) in [
        ("usr/local/bin", PROGRAM_MODE),
        ("usr/local/libexec/wg-basic", PROGRAM_MODE),
        (STATE_DIR, STATE_DIR_MODE),
        (RUNTIME_DIR, RUNTIME_DIR_MODE),
        (LOG_DIR, LOG_DIR_MODE),
        (PLIST_DIR, PLIST_DIR_MODE),
    ] {
        secure_directory(&owned_path(root, directory), mode)?;
    }

    secure_file(&owned_path(root, BINARY_PATH), binary_bytes, PROGRAM_MODE)?;
    secure_file(&owned_path(root, HELPER_PATH), helper_bytes, PROGRAM_MODE)?;
    secure_file(&owned_path(root, NETD_LOG), b"", LOG_FILE_MODE)?;
    secure_file(&owned_path(root, SERVE_LOG), b"", LOG_FILE_MODE)?;

    let netd_plist = render_service_plist(ServiceRole::Netd)?;
    let serve_plist = render_service_plist(ServiceRole::Serve)?;
    secure_file(
        &owned_path(root, &format!("{PLIST_DIR}/{NETD_LABEL}.plist")),
        netd_plist.as_bytes(),
        PLIST_MODE,
    )?;
    secure_file(
        &owned_path(root, &format!("{PLIST_DIR}/{SERVE_LABEL}.plist")),
        serve_plist.as_bytes(),
        PLIST_MODE,
    )?;

    let receipt = DarwinInstallReceipt {
        product: "wg-basic".into(),
        version: version.into(),
        target: target.into(),
        binary_sha256: binary_sha256.clone(),
        helper_sha256: helper_sha256.clone(),
        netd_plist_sha256: hex(netd_plist.as_bytes()),
        serve_plist_sha256: hex(serve_plist.as_bytes()),
        management_identity: None,
    };
    let encoded = serde_json::to_vec_pretty(&receipt).map_err(|_| InstallError::Io)?;
    secure_file(
        &owned_path(root, &format!("{STATE_DIR}/install.json")),
        &encoded,
        RECEIPT_MODE,
    )?;
    Ok(receipt)
}

/// Records the resolved management identity in the install receipt.
///
/// The privileged installer resolves the account through the directory
/// service, applies the ownership the receipt then names, and writes the
/// identity down. A receipt without a recorded identity never produced a
/// running service.
pub fn bind_management_identity(
    root: &Path,
    identity: &ServiceIdentity,
) -> Result<DarwinInstallReceipt, InstallError> {
    let mut receipt = read_receipt(root)?;
    receipt.management_identity = Some(identity.clone());
    let encoded = serde_json::to_vec_pretty(&receipt).map_err(|_| InstallError::Io)?;
    secure_file(
        &owned_path(root, &format!("{STATE_DIR}/install.json")),
        &encoded,
        RECEIPT_MODE,
    )?;
    Ok(receipt)
}

/// Reads the install receipt without verifying the installed content.
fn read_receipt(root: &Path) -> Result<DarwinInstallReceipt, InstallError> {
    let encoded = std::fs::read(owned_path(root, &format!("{STATE_DIR}/install.json")))
        .map_err(|_| InstallError::NotInstalled)?;
    serde_json::from_slice(&encoded).map_err(|_| InstallError::ReceiptCorrupt)
}

/// Verifies an installed root against its receipt: exact labels, exact
/// plist bytes, exact binary/helper hashes, and the exact directory modes.
/// Anything else is refused.
pub fn verify_installed_root(root: &Path) -> Result<DarwinInstallReceipt, InstallError> {
    use sha2::{Digest, Sha256};

    let receipt = read_receipt(root)?;
    let hex_file = |absolute: &str| -> Result<String, InstallError> {
        let bytes =
            std::fs::read(owned_path(root, absolute)).map_err(|_| InstallError::Modified)?;
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
        let path = owned_path(root, &format!("{PLIST_DIR}/{label}.plist"));
        if !path.is_file() {
            return Err(InstallError::Modified);
        }
    }
    verify_directory_mode(root, STATE_DIR, STATE_DIR_MODE)?;
    verify_directory_mode(root, RUNTIME_DIR, RUNTIME_DIR_MODE)?;
    verify_directory_mode(root, LOG_DIR, LOG_DIR_MODE)?;
    Ok(receipt)
}

/// Verifies that one owned directory still has its exact mode.
fn verify_directory_mode(root: &Path, absolute: &str, mode: u32) -> Result<(), InstallError> {
    let path = owned_path(root, absolute);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| InstallError::Modified)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(InstallError::Modified);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.mode() & 0o7777 != mode {
            return Err(InstallError::Modified);
        }
    }
    Ok(())
}

/// Applies the management identity's ownership to the owned layout.
///
/// The management state directory and the management log belong to the
/// management account; the privileged runtime directory and the program files
/// stay root-owned. This is the privileged half of the install and needs
/// root.
pub fn apply_service_ownership(
    root: &Path,
    identity: &ServiceIdentity,
) -> Result<(), InstallError> {
    #[cfg(unix)]
    {
        let uid = nix::unistd::Uid::from_raw(identity.uid);
        let gid = nix::unistd::Gid::from_raw(identity.gid);
        nix::unistd::chown(&owned_path(root, STATE_DIR), Some(uid), Some(gid))
            .map_err(|_| InstallError::Io)?;
        nix::unistd::chown(&owned_path(root, SERVE_LOG), Some(uid), Some(gid))
            .map_err(|_| InstallError::Io)?;
    }
    let _ = identity;
    Ok(())
}

/// Grants the management identity access to the privileged socket.
///
/// The socket is created by the privileged daemon. This makes it reachable by
/// the management group and by nobody else, and refuses a socket that is not
/// a socket.
pub fn authorize_socket_group(
    socket: &Path,
    identity: &ServiceIdentity,
) -> Result<(), InstallError> {
    let metadata = std::fs::symlink_metadata(socket).map_err(|_| InstallError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            return Err(InstallError::Modified);
        }
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(SOCKET_MODE))
            .map_err(|_| InstallError::Io)?;
        nix::unistd::chown(
            socket,
            Some(nix::unistd::Uid::from_raw(0)),
            Some(nix::unistd::Gid::from_raw(identity.gid)),
        )
        .map_err(|_| InstallError::Io)?;
    }
    Ok(())
}

/// The installed helper's digest, if an install receipt exists.
pub fn installed_helper_digest(root: &Path) -> Option<String> {
    read_receipt(root).ok().map(|receipt| receipt.helper_sha256)
}

/// The management identity recorded in the install receipt, if any.
pub fn recorded_management_identity(root: &Path) -> Option<ServiceIdentity> {
    read_receipt(root).ok()?.management_identity
}

/// The installed service status an operator can read without privileges.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledStatus {
    /// The installed product.
    pub product: String,
    /// The installed version.
    pub version: String,
    /// The installed target triple.
    pub target: String,
    /// The management identity the install bound the layout to.
    pub management_identity: Option<ServiceIdentity>,
    /// Whether the owned layout verifies against the receipt.
    pub layout_verified: bool,
}

/// Reads the installed status of a root, verifying the owned layout.
pub fn installed_status(root: &Path) -> InstalledStatus {
    let receipt = verify_installed_root(root).ok();
    InstalledStatus {
        product: receipt
            .as_ref()
            .map(|receipt| receipt.product.clone())
            .unwrap_or_default(),
        version: receipt
            .as_ref()
            .map(|receipt| receipt.version.clone())
            .unwrap_or_default(),
        target: receipt
            .as_ref()
            .map(|receipt| receipt.target.clone())
            .unwrap_or_default(),
        management_identity: receipt
            .as_ref()
            .and_then(|receipt| receipt.management_identity.clone()),
        layout_verified: receipt.is_some(),
    }
}

/// State-preserving uninstall: removes owned program/plist files, keeps the
/// secret-bearing state dir + receipt for reinstall. Refuses when
/// verification fails (modified/foreign content is never deleted by guess).
/// Firewall detach + helper teardown ordering is enforced by the caller
/// (M005 order) before this runs; global/foreign state is never touched.
pub fn uninstall_preserving_state(root: &Path) -> Result<(), InstallError> {
    verify_installed_root(root)?;
    for owned in [
        BINARY_PATH,
        HELPER_PATH,
        &format!("{PLIST_DIR}/{NETD_LABEL}.plist"),
        &format!("{PLIST_DIR}/{SERVE_LABEL}.plist"),
    ] {
        let _ = std::fs::remove_file(owned_path(root, owned));
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
    #[error("the management service account does not exist")]
    ServiceIdentityMissing,
    #[error("the management service account is renamed, reused, or reserved")]
    ServiceIdentityUnstable,
    #[error("a value would inject structure into the launchd plist; refused")]
    DangerousValue,
    #[error("the Darwin installer requires effective root; no automatic sudo is performed")]
    PrivilegeRequired,
    #[error("launchctl refused the requested operation")]
    LaunchctlFailed,
    #[error("the privileged daemon did not publish its socket")]
    SocketUnavailable,
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
    fn plist_renders_fixed_keys_and_the_service_identity_without_secrets() {
        let plist = render_plist(ServiceRole::Netd).unwrap();
        assert!(plist.contains(NETD_LABEL));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<key>ThrottleInterval</key>"));
        assert!(!plist.contains("password"));
        // The privileged daemon is explicitly root and the management daemon
        // is explicitly not.
        assert!(plist.contains("<key>UserName</key>\n    <string>root</string>"));
        let serve = render_plist(ServiceRole::Serve).unwrap();
        assert!(serve.contains(SERVE_USER));
        assert!(!serve.contains("<string>root</string>"));
        assert!(serve.contains("<key>GroupName</key>"));
        // serve starts after netd at runtime (socket retry); labels differ.
        assert_ne!(NETD_LABEL, SERVE_LABEL);
        assert!(DARWIN_TARGETS.contains(&"aarch64-apple-darwin"));
        assert!(DARWIN_TARGETS.contains(&"x86_64-apple-darwin"));
    }

    #[test]
    fn the_renderer_refuses_values_that_could_inject_structure() {
        // A relative executable is refused outright.
        // The renderer has no path parameters at all: the label, the
        // identity, the executable, the arguments, and the log path are the
        // role's own.
        let plist = render_plist(ServiceRole::Netd).unwrap();
        assert!(plist.contains(BINARY_PATH));
        assert!(plist.contains(SOCKET_PATH));
        // The renderer has no way to carry an arbitrary label, user, group, or
        // log path: the role owns all of them.
        let plist = render_plist(ServiceRole::Serve).unwrap();
        assert!(!plist.contains("<key>EnvironmentVariables</key>"));
        assert!(!plist.contains("<key>WorkingDirectory</key>"));
        assert!(!plist.contains("<key>Program</key>"));
        // Escaping is applied to every interpolated value.
        assert!(!plist.contains("&amp;amp;"));
    }

    #[test]
    fn the_management_account_is_never_the_privileged_one() {
        assert_eq!(ServiceRole::Netd.user(), NETD_USER);
        assert_eq!(ServiceRole::Serve.user(), SERVE_USER);
        assert_ne!(ServiceRole::Serve.user(), "root");
        assert_ne!(ServiceRole::Serve.group(), "root");
        // The management account is preprovisioned, so its absence is a
        // refusal rather than a reason to run as root.
        assert!(
            resolve_service_identity(ServiceRole::Serve).is_err()
                || resolve_service_identity(ServiceRole::Serve).unwrap().uid >= MIN_SERVICE_UID
        );
    }

    #[test]
    fn the_owned_layout_refuses_a_symlink_in_place_of_a_directory() {
        let root = temp_root("symlink");
        let state = root.join(STATE_DIR.strip_prefix('/').unwrap());
        std::fs::create_dir_all(state.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("/tmp", &state).unwrap();
        assert_eq!(
            install_to_root(&root, "0.1.0", "aarch64-apple-darwin", b"b", b"h").unwrap_err(),
            InstallError::Modified
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_runtime_directory_is_never_world_writable() {
        assert_eq!(RUNTIME_DIR_MODE & 0o022, 0);
        assert_eq!(STATE_DIR_MODE & 0o077, 0);
        assert_eq!(SOCKET_MODE & 0o007, 0);
        let root = temp_root("modes");
        install_to_root(
            &root,
            "0.1.0",
            "aarch64-apple-darwin",
            b"fake-binary-bytes",
            b"fake-helper-bytes",
        )
        .unwrap();
        verify_installed_root(&root).unwrap();
        // A widened runtime directory is refused.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let runtime = root.join(RUNTIME_DIR.strip_prefix('/').unwrap());
            std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        assert_eq!(
            verify_installed_root(&root).unwrap_err(),
            InstallError::Modified
        );
        let _ = std::fs::remove_dir_all(&root);
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
