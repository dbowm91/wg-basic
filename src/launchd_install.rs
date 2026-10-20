//! Bounded launchd control and the Darwin installer (C002).
//!
//! This is the only module in the product that executes a process on Darwin,
//! and the only process it executes is `launchctl`:
//!
//! - the executable is an absolute path, so there is no `PATH` lookup;
//! - the verb set is closed (`bootstrap`, `bootout`, `print`);
//! - the target set is closed (this product's two labels, in the system
//!   domain);
//! - there is no shell, and no argument is ever taken from a caller.
//!
//! Everything else the installer needs — layout, ownership, identity,
//! receipts — is pure logic in [`crate::launchd`].

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::launchd::{
    self, InstallError, InstalledStatus, ServiceRole, PLIST_DIR, RUNTIME_DIR, SOCKET_PATH,
};

/// The absolute path of `launchctl`. No `PATH` lookup is ever used.
pub const LAUNCHCTL_PATH: &str = "/bin/launchctl";

/// How long the installer waits for the privileged daemon to publish its
/// socket before giving up.
const SOCKET_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// A launchctl operation this product performs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchctlOperation {
    /// Registers a service in the system domain.
    Bootstrap,
    /// Removes a service from the system domain.
    Bootout,
    /// Prints the state of a service in the system domain.
    Print,
}

impl LaunchctlOperation {
    /// The fixed verb this operation uses.
    fn verb(self) -> &'static str {
        match self {
            LaunchctlOperation::Bootstrap => "bootstrap",
            LaunchctlOperation::Bootout => "bootout",
            LaunchctlOperation::Print => "print",
        }
    }
}

/// Runs one launchctl operation against one of this product's services.
///
/// The verb and the target are closed sets. There is no shell, no `PATH`
/// lookup, and no way to address a foreign job.
pub fn run(operation: LaunchctlOperation, role: ServiceRole) -> Result<String, InstallError> {
    let arguments: Vec<String> = match operation {
        LaunchctlOperation::Bootstrap => vec![
            operation.verb().to_owned(),
            "system".to_owned(),
            format!("{PLIST_DIR}/{}.plist", role.label()),
        ],
        LaunchctlOperation::Bootout | LaunchctlOperation::Print => vec![
            operation.verb().to_owned(),
            format!("system/{}", role.label()),
        ],
    };
    let output = Command::new(LAUNCHCTL_PATH)
        .args(&arguments)
        .output()
        .map_err(|_| InstallError::Io)?;
    if !output.status.success() {
        return Err(InstallError::LaunchctlFailed);
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Whether a service is currently registered in the system domain.
pub fn is_registered(role: ServiceRole) -> bool {
    run(LaunchctlOperation::Print, role).is_ok()
}

/// The host's own Darwin target triple.
pub fn host_target() -> String {
    format!("{}-apple-darwin", std::env::consts::ARCH)
}

/// Reads an owned executable, refusing a symlink and a non-regular file.
fn read_owned_binary(path: &Path) -> Result<Vec<u8>, InstallError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| InstallError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InstallError::Modified);
    }
    std::fs::read(path).map_err(|_| InstallError::Io)
}

/// Installs the Darwin deployment under an explicit root.
///
/// The order is deliberate: the owned layout is written and verified first,
/// the management identity is resolved and bound second, and only then are
/// the services registered. A failure after the first registration rolls the
/// first one back, so an interrupted install never leaves a half-registered
/// deployment behind.
pub fn install(root: &Path, binary: &Path, helper: &Path) -> Result<InstalledStatus, InstallError> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(InstallError::PrivilegeRequired);
    }
    let binary_bytes = read_owned_binary(binary)?;
    let helper_bytes = read_owned_binary(helper)?;
    let target = host_target();
    launchd::install_to_root(
        root,
        env!("CARGO_PKG_VERSION"),
        &target,
        &binary_bytes,
        &helper_bytes,
    )?;
    let identity = launchd::resolve_service_identity(ServiceRole::Serve)?;
    launchd::apply_service_ownership(root, &identity)?;
    launchd::bind_management_identity(root, &identity)?;

    // The privileged daemon comes first: the management daemon retries the
    // socket at runtime, so load order is not the only ordering guarantee.
    run(LaunchctlOperation::Bootstrap, ServiceRole::Netd)?;
    if let Err(error) = run(LaunchctlOperation::Bootstrap, ServiceRole::Serve) {
        // Transactional: a half-registered deployment is rolled back rather
        // than left with one live service.
        let _ = run(LaunchctlOperation::Bootout, ServiceRole::Netd);
        return Err(error);
    }
    wait_for_socket(root, &identity)?;
    Ok(launchd::installed_status(root))
}

/// Waits for the privileged daemon to publish its socket, then binds the
/// socket to the management identity.
///
/// The socket is the only path from the management daemon to the privileged
/// one, so its owner and mode are part of the privilege boundary rather than
/// a convenience.
fn wait_for_socket(root: &Path, identity: &launchd::ServiceIdentity) -> Result<(), InstallError> {
    let socket = owned_socket(root);
    let deadline = std::time::Instant::now() + SOCKET_WAIT;
    while std::time::Instant::now() < deadline {
        if socket.exists() {
            return launchd::authorize_socket_group(&socket, identity);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(InstallError::SocketUnavailable)
}

/// The privileged socket path under an explicit root.
fn owned_socket(root: &Path) -> PathBuf {
    root.join(SOCKET_PATH.strip_prefix('/').unwrap_or(SOCKET_PATH))
}

/// Removes the Darwin deployment, preserving the secret-bearing state.
///
/// The management daemon is stopped first so it is never talking to a socket
/// whose daemon is going away. Foreign launchd jobs are never touched.
pub fn uninstall(root: &Path) -> Result<(), InstallError> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(InstallError::PrivilegeRequired);
    }
    let _ = run(LaunchctlOperation::Bootout, ServiceRole::Serve);
    let _ = run(LaunchctlOperation::Bootout, ServiceRole::Netd);
    launchd::uninstall_preserving_state(root)
}

/// The installed deployment status an operator can read.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DarwinSystemStatus {
    /// The owned layout status.
    pub layout: InstalledStatus,
    /// Whether the privileged daemon is registered.
    pub netd_registered: bool,
    /// Whether the management daemon is registered.
    pub serve_registered: bool,
}

/// Reads the installed deployment status.
pub fn status(root: &Path) -> DarwinSystemStatus {
    DarwinSystemStatus {
        layout: launchd::installed_status(root),
        netd_registered: is_registered(ServiceRole::Netd),
        serve_registered: is_registered(ServiceRole::Serve),
    }
}

/// The runtime directory the privileged daemon owns.
pub fn runtime_directory() -> &'static str {
    RUNTIME_DIR
}
