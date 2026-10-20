//! The production Darwin WireGuard backend (C001).
//!
//! Darwin has no kernel WireGuard interface. A managed tunnel is a supervised
//! `wireguard-go` helper that owns one kernel-assigned `utunN` device and
//! serves the WireGuard UAPI protocol on a Unix socket.
//!
//! That shape creates the ownership problem this module solves. On Linux the
//! durable owner tag lives in the kernel's interface alias. On Darwin there is
//! no such field, so the durable proof lives in a **protected receipt** that
//! netd writes into an owner-only managed-runtime directory, and the receipt is
//! only ever a *claim*:
//!
//! - [`RuntimeRegistry`] stores one receipt per managed tunnel, bound to the
//!   installation, the logical interface, the kernel-assigned `utunN`, the
//!   helper pid and executable hash, and the UAPI socket path;
//! - [`prove_ownership`] re-observes the helper process, the helper
//!   executable, the UAPI socket, and the kernel device *jointly* before any
//!   mutation or teardown;
//! - a receipt that cannot be re-proven is treated as **absent**, never as
//!   permission to act. A foreign `utun`, a reused pid, or a replaced socket
//!   fails closed.
//!
//! The observation contract matches the Linux backend exactly: the same
//! [`ObservedWireGuardDevice`] shape, the same `set`/`get` UAPI protocol, and
//! the same apply-then-re-observe receipt.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::domain::{
    derive_public_key, InstallationId, InterfaceId, InterfaceName, NetworkPrefix, OwnerTag,
    PrivateKey, PublicKey,
};
use crate::wireguard::{
    ApplyDisposition, DesiredWireGuardPeer, FieldUpdate, ObservedWireGuardDevice,
    ObservedWireGuardPeer, PeerMutation, WireGuardApplyReceipt, WireGuardDevicePatch,
    WireGuardPeerPatch, WireGuardValidationError,
};

pub use super::darwin::SupervisedHelper;

use super::darwin::{
    base64_key_to_hex, is_utun_name, parse_uapi_get, uapi_round_trip, HelperArgv, HelperError,
    UapiDevice,
};

/// The managed-runtime directory holds the protected ownership receipts.
///
/// It is a subdirectory of the protected runtime directory, so it inherits the
/// same owner-only rules (see [`crate::launchd`]).
pub const MANAGED_RUNTIME_SUBDIR: &str = "managed";

/// The suffix of a managed-runtime receipt file.
pub const RECEIPT_SUFFIX: &str = "receipt";

/// How long the backend waits for the helper to publish its `utunN` device.
const HELPER_DEVICE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the backend waits for the helper to publish its UAPI socket once
/// the device is up.
const HELPER_SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

/// The durable receipt for one managed tunnel.
///
/// The receipt is the durable ownership claim. It is never sufficient on its
/// own: [`prove_ownership`] re-observes the live host before anything is
/// changed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntime {
    /// The installation that owns this tunnel.
    pub installation_id: InstallationId,
    /// The logical interface that owns this tunnel.
    pub interface_id: InterfaceId,
    /// The logical managed interface name.
    pub interface: String,
    /// The kernel-assigned `utunN` device backing this tunnel.
    pub utun_name: String,
    /// The helper process that created the device.
    pub helper_pid: u32,
    /// The absolute path of the helper executable.
    pub helper_path: String,
    /// The SHA-256 of the helper executable.
    pub helper_sha256: String,
    /// The UAPI socket the helper serves.
    pub uapi_socket: String,
    /// When the receipt was written (milliseconds since the Unix epoch).
    pub created_unix_ms: u128,
}

impl ManagedRuntime {
    /// The owner tag this receipt claims.
    pub fn owner_tag(&self) -> OwnerTag {
        OwnerTag::new(self.installation_id, self.interface_id)
    }

    /// The logical managed interface this receipt belongs to.
    pub fn interface_name(&self) -> Option<InterfaceName> {
        InterfaceName::new(self.interface.clone()).ok()
    }
}

/// Why a managed-runtime receipt could not be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RegistryError {
    /// The managed-runtime directory is not an owner-only directory.
    #[error("the managed runtime directory is not a safe owner-only directory")]
    UnsafeRuntimeDirectory,
    /// A receipt was missing, foreign, or modified.
    #[error("a managed runtime receipt was rejected")]
    ReceiptRejected,
    /// Managed-runtime storage failed.
    #[error("managed runtime storage failed")]
    Io,
}

/// netd's durable registry of managed tunnels.
///
/// The registry is the single owner of the mapping from a logical managed
/// interface to the kernel device that backs it. It survives a netd restart
/// so a restarted netd re-proves ownership instead of adopting a device by
/// name.
pub struct RuntimeRegistry {
    root: PathBuf,
    entries: Mutex<BTreeMap<String, ManagedRuntime>>,
}

impl RuntimeRegistry {
    /// Opens the protected managed-runtime directory and loads every receipt.
    ///
    /// The directory is created owner-only when missing. An existing directory
    /// that is not an owner-only directory is refused: a receipt is only a
    /// durable ownership proof when nobody else can rewrite it.
    pub fn open(root: &Path) -> Result<Self, RegistryError> {
        ensure_protected_directory(root)?;
        let mut entries = BTreeMap::new();
        let directory = std::fs::read_dir(root).map_err(|_| RegistryError::Io)?;
        for entry in directory {
            let entry = entry.map_err(|_| RegistryError::Io)?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some(RECEIPT_SUFFIX) {
                continue;
            }
            let runtime = read_protected_receipt(&path)?;
            entries.insert(runtime.interface.clone(), runtime);
        }
        Ok(Self {
            root: root.to_path_buf(),
            entries: Mutex::new(entries),
        })
    }

    /// The directory the receipts live in.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The receipt for one logical managed interface, if it has one.
    pub fn get(&self, interface: &InterfaceName) -> Option<ManagedRuntime> {
        self.entries.lock().ok()?.get(interface.as_str()).cloned()
    }

    /// The receipt that claims one owner tag, if any.
    pub fn find_by_owner_tag(&self, owner_tag: &OwnerTag) -> Option<ManagedRuntime> {
        let entries = self.entries.lock().ok()?;
        entries
            .values()
            .find(|runtime| {
                runtime.installation_id == owner_tag.installation_id()
                    && runtime.interface_id == owner_tag.interface_id()
            })
            .cloned()
    }

    /// Every receipt, for operator-facing reporting.
    pub fn entries(&self) -> Vec<ManagedRuntime> {
        self.entries
            .lock()
            .map(|entries| entries.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Writes (or replaces) the receipt for one managed tunnel.
    pub fn insert(&self, runtime: ManagedRuntime) -> Result<(), RegistryError> {
        let name = receipt_name(&runtime.installation_id, &runtime.interface_id);
        let encoded = serde_json::to_vec_pretty(&runtime).map_err(|_| RegistryError::Io)?;
        let temporary = self.root.join(format!(".{name}.tmp"));
        std::fs::write(&temporary, &encoded).map_err(|_| RegistryError::Io)?;
        set_owner_only_permissions(&temporary)?;
        std::fs::rename(&temporary, self.root.join(&name)).map_err(|_| RegistryError::Io)?;
        let mut entries = self.entries.lock().map_err(|_| RegistryError::Io)?;
        entries.insert(runtime.interface.clone(), runtime);
        Ok(())
    }

    /// Removes the receipt for one managed tunnel.
    pub fn remove(&self, interface: &InterfaceName) -> Result<(), RegistryError> {
        let runtime = self
            .entries
            .lock()
            .map_err(|_| RegistryError::Io)?
            .remove(interface.as_str());
        if let Some(runtime) = runtime {
            let path = self.root.join(receipt_name(
                &runtime.installation_id,
                &runtime.interface_id,
            ));
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }
}

/// The file name of one receipt.
fn receipt_name(installation_id: &InstallationId, interface_id: &InterfaceId) -> String {
    format!("{installation_id}.{interface_id}.{RECEIPT_SUFFIX}")
}

/// Creates or verifies the owner-only managed-runtime directory.
fn ensure_protected_directory(root: &Path) -> Result<(), RegistryError> {
    if !root.exists() {
        std::fs::create_dir_all(root).map_err(|_| RegistryError::Io)?;
        set_owner_only_permissions(root)?;
    }
    let metadata = std::fs::symlink_metadata(root).map_err(|_| RegistryError::Io)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(RegistryError::UnsafeRuntimeDirectory);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let euid = nix::unistd::geteuid().as_raw();
        if metadata.uid() != euid || metadata.mode() & 0o077 != 0 {
            return Err(RegistryError::UnsafeRuntimeDirectory);
        }
    }
    Ok(())
}

/// Reads one receipt, refusing anything that is not an owner-only regular file.
fn read_protected_receipt(path: &Path) -> Result<ManagedRuntime, RegistryError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| RegistryError::Io)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(RegistryError::ReceiptRejected);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let euid = nix::unistd::geteuid().as_raw();
        if metadata.uid() != euid || metadata.mode() & 0o077 != 0 {
            return Err(RegistryError::ReceiptRejected);
        }
    }
    let bytes = std::fs::read(path).map_err(|_| RegistryError::Io)?;
    serde_json::from_slice(&bytes).map_err(|_| RegistryError::ReceiptRejected)
}

/// Restricts a path to owner-only permissions.
fn set_owner_only_permissions(path: &Path) -> Result<(), RegistryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| RegistryError::Io)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// The pinned helper identity netd is allowed to execute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelperIdentity {
    /// The absolute path of the helper executable.
    pub path: PathBuf,
    /// The SHA-256 the installed helper must have.
    pub sha256: String,
}

/// The outcome of proving ownership of a recorded tunnel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipOutcome {
    /// The receipt is proven by the live host.
    Proven,
    /// The helper process is gone or is no longer the pinned executable.
    HelperMismatch,
    /// The UAPI socket is gone, foreign, or does not answer.
    SocketMismatch,
    /// The kernel no longer exposes the recorded device.
    InterfaceAbsent,
}

impl OwnershipOutcome {
    /// Whether the outcome proves ownership.
    pub fn is_proven(self) -> bool {
        matches!(self, OwnershipOutcome::Proven)
    }
}

/// Proves that a recorded tunnel still exists and is still ours.
///
/// The proof is joint: the recorded helper pid must still be alive *and* still
/// be running the recorded executable, the recorded executable must still
/// hash to the recorded digest, the UAPI socket must still be an owner-only
/// socket that answers, and the caller must have observed the recorded
/// `utunN` device in the kernel.
pub fn prove_ownership(runtime: &ManagedRuntime, device_present: bool) -> OwnershipOutcome {
    if !device_present {
        return OwnershipOutcome::InterfaceAbsent;
    }
    let executable = match wg_basic_darwin_sys::process_executable_path(runtime.helper_pid) {
        Some(path) => path,
        None => return OwnershipOutcome::HelperMismatch,
    };
    if executable != Path::new(&runtime.helper_path) {
        return OwnershipOutcome::HelperMismatch;
    }
    if super::darwin::verify_helper_sha256(Path::new(&runtime.helper_path), &runtime.helper_sha256)
        .is_err()
    {
        return OwnershipOutcome::HelperMismatch;
    }
    if owned_uapi_socket(&runtime.uapi_socket).is_err() {
        return OwnershipOutcome::SocketMismatch;
    }
    let mut stream = match std::os::unix::net::UnixStream::connect(&runtime.uapi_socket) {
        Ok(stream) => stream,
        Err(_) => return OwnershipOutcome::SocketMismatch,
    };
    match uapi_round_trip(&mut stream, "get=1\n\n") {
        Ok(response) if response.errno == 0 => OwnershipOutcome::Proven,
        _ => OwnershipOutcome::SocketMismatch,
    }
}

/// Verifies that a UAPI socket path is an owner-only socket of this user.
fn owned_uapi_socket(path: &str) -> Result<PathBuf, OwnershipOutcome> {
    let path = PathBuf::from(path);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(_) => return Err(OwnershipOutcome::SocketMismatch),
    };
    {
        use std::os::unix::fs::FileTypeExt as _;
        if !metadata.file_type().is_socket() {
            return Err(OwnershipOutcome::SocketMismatch);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let euid = nix::unistd::geteuid().as_raw();
        if metadata.uid() != euid {
            return Err(OwnershipOutcome::SocketMismatch);
        }
    }
    Ok(path)
}

/// Spawns the pinned helper and returns the supervised child with the
/// kernel-assigned device it created.
///
/// Exactly one new `utunN` must appear: zero or several is a fail-closed
/// conflict, never an adoption by numeric guess.
pub fn spawn_managed_tunnel(
    helper: &HelperIdentity,
) -> Result<(SupervisedHelper, String), HelperError> {
    super::darwin::validate_helper_path(&helper.path)?;
    super::darwin::verify_helper_sha256(&helper.path, &helper.sha256)?;
    let before = utun_interface_names();
    let argv = HelperArgv::new(helper.path.clone())?;
    let child = SupervisedHelper::spawn(&argv)?;
    let deadline = std::time::Instant::now() + HELPER_DEVICE_TIMEOUT;
    let name = loop {
        if let Ok(name) = super::darwin::interface_delta(&before, &utun_interface_names()) {
            break name;
        }
        if std::time::Instant::now() >= deadline {
            return Err(HelperError::StartupFailed);
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    // The helper publishes its UAPI socket a moment after the kernel hands it
    // the device. A tunnel is not usable until that control socket exists, so
    // the spawn does not return before it does: an ownership proof taken in
    // that window would fail closed on a socket that is merely late, and a
    // receipt written in that window would claim a tunnel nobody can configure
    // yet.
    let socket = super::darwin::uapi_socket_path(&name);
    let socket_deadline = std::time::Instant::now() + HELPER_SOCKET_TIMEOUT;
    while !socket.exists() {
        if std::time::Instant::now() >= socket_deadline {
            return Err(HelperError::StartupFailed);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok((child, name))
}

/// Every `utunN` interface currently present in the kernel.
pub fn utun_interface_names() -> Vec<String> {
    wg_basic_darwin_sys::interfaces()
        .map(|interfaces| {
            interfaces
                .into_iter()
                .map(|interface| interface.name)
                .filter(|name| is_utun_name(name))
                .collect()
        })
        .unwrap_or_default()
}

/// The production Darwin WireGuard backend.
///
/// It owns no helper process itself: the reconciliation backend supervises the
/// helper and records the receipt, and this backend configures and observes
/// the device through the UAPI socket that receipt names.
#[derive(Clone)]
pub struct DarwinWireGuardBackend {
    registry: Result<Arc<RuntimeRegistry>, RegistryError>,
}

impl DarwinWireGuardBackend {
    /// Builds the backend over a managed-runtime registry.
    pub fn new(registry: Arc<RuntimeRegistry>) -> Self {
        Self {
            registry: Ok(registry),
        }
    }

    /// Builds a backend that can never act, because the managed-runtime
    /// directory could not be opened safely.
    pub fn unavailable(reason: RegistryError) -> Self {
        Self {
            registry: Err(reason),
        }
    }

    /// The registry this backend reads its ownership claims from.
    pub fn registry(&self) -> Option<&Arc<RuntimeRegistry>> {
        self.registry.as_ref().ok()
    }

    /// The managed-runtime registry netd shares between the protocol dispatch
    /// and the aggregate coordinator.
    ///
    /// One process owns one registry: two registries would disagree about which
    /// `utunN` device belongs to which managed interface.
    pub fn shared_registry() -> Result<Arc<RuntimeRegistry>, RegistryError> {
        static SHARED: std::sync::OnceLock<Result<Arc<RuntimeRegistry>, RegistryError>> =
            std::sync::OnceLock::new();
        SHARED
            .get_or_init(|| {
                RuntimeRegistry::open(&crate::wireguard::production_runtime_root()).map(Arc::new)
            })
            .clone()
    }

    /// Observes the managed device for one logical interface.
    ///
    /// Fails closed when there is no proven managed tunnel: an unrecorded or
    /// unprovable device is never observed as ours.
    pub fn observe_device(
        &self,
        interface: &InterfaceName,
    ) -> Result<ObservedWireGuardDevice, WireGuardValidationError> {
        let registry = self
            .registry
            .as_ref()
            .map_err(|_| WireGuardValidationError::BackendFailure)?;
        let runtime = registry
            .get(interface)
            .ok_or(WireGuardValidationError::InterfaceUnavailable)?;
        read_managed_device(&runtime, interface).map_err(classify_helper_error)
    }

    /// Applies one device patch to the managed device.
    pub fn apply_patch(
        &self,
        interface: &InterfaceName,
        patch: WireGuardDevicePatch,
    ) -> Result<WireGuardApplyReceipt, WireGuardValidationError> {
        crate::wireguard::validate_device_patch(&patch)?;
        let registry = self
            .registry
            .as_ref()
            .map_err(|_| WireGuardValidationError::BackendFailure)?;
        let runtime = registry
            .get(interface)
            .ok_or(WireGuardValidationError::InterfaceUnavailable)?;
        let before = read_managed_device(&runtime, interface).map_err(classify_helper_error)?;
        let command = render_uapi_patch(&patch).map_err(classify_helper_error)?;
        let mut stream = std::os::unix::net::UnixStream::connect(&runtime.uapi_socket)
            .map_err(|_| WireGuardValidationError::InterfaceUnavailable)?;
        let response = uapi_round_trip(&mut stream, &command).map_err(classify_helper_error)?;
        if response.errno != 0 {
            return Err(WireGuardValidationError::KernelRejected);
        }
        let after = read_managed_device(&runtime, interface).map_err(classify_helper_error)?;
        Ok(WireGuardApplyReceipt {
            interface: interface.clone(),
            disposition: if after == before {
                ApplyDisposition::NoChange
            } else {
                ApplyDisposition::Applied
            },
        })
    }
}

/// Reads and maps the device behind one receipt.
fn read_managed_device(
    runtime: &ManagedRuntime,
    interface: &InterfaceName,
) -> Result<ObservedWireGuardDevice, HelperError> {
    let mut stream = std::os::unix::net::UnixStream::connect(&runtime.uapi_socket)
        .map_err(|_| HelperError::UapiTransport)?;
    let response = uapi_round_trip(&mut stream, "get=1\n\n")?;
    parse_uapi_device(interface, &response)
}

/// Maps a helper failure onto the portable backend failure vocabulary.
fn classify_helper_error(error: HelperError) -> WireGuardValidationError {
    match error {
        HelperError::UapiMalformed => WireGuardValidationError::InvalidBackendInput,
        HelperError::UapiRefused => WireGuardValidationError::KernelRejected,
        HelperError::UapiTransport => WireGuardValidationError::BackendFailure,
        _ => WireGuardValidationError::BackendFailure,
    }
}

/// Maps one helper `get=1` dump onto the portable observed device.
///
/// The helper reports the device private key; it is a secret. It is converted
/// to the device public key and dropped immediately. The per-peer preshared
/// key is never read at all.
pub fn parse_uapi_device(
    interface: &InterfaceName,
    device: &UapiDevice,
) -> Result<ObservedWireGuardDevice, HelperError> {
    if device.errno != 0 {
        return Err(HelperError::UapiRefused);
    }
    let mut public_key = None;
    let mut listen_port = None;
    let mut peers: Vec<ObservedWireGuardPeer> = Vec::new();
    let mut current: Option<PeerObservation> = None;
    for (key, value) in &device.pairs {
        match key.as_str() {
            "private_key" if public_key.is_none() && current.is_none() => {
                let secret = PrivateKey::new(hex_to_base64(value)?)
                    .map_err(|_| HelperError::UapiMalformed)?;
                public_key =
                    Some(derive_public_key(&secret).map_err(|_| HelperError::UapiMalformed)?);
            }
            "listen_port" => {
                let port: u16 = value.parse().map_err(|_| HelperError::UapiMalformed)?;
                match current.as_mut() {
                    Some(peer) => peer.listen_port = Some(port),
                    None => listen_port = Some(port),
                }
            }
            "public_key" => {
                if let Some(peer) = current.take() {
                    peers.push(peer.build());
                }
                current = Some(PeerObservation {
                    public_key: PublicKey::new(hex_to_base64(value)?)
                        .map_err(|_| HelperError::UapiMalformed)?,
                    allowed_ips: Vec::new(),
                    persistent_keepalive_seconds: None,
                    endpoint: None,
                    listen_port: None,
                    handshake_seconds: 0,
                    handshake_nanos: 0,
                    tx_bytes: None,
                    rx_bytes: None,
                });
            }
            "endpoint" => {
                if let Some(peer) = current.as_mut() {
                    peer.endpoint = normalize_endpoint(value);
                }
            }
            "allowed_ip" => {
                if let Some(peer) = current.as_mut() {
                    let network = value.parse().map_err(|_| HelperError::UapiMalformed)?;
                    peer.allowed_ips.push(NetworkPrefix::new(network));
                }
            }
            "persistent_keepalive_interval" => {
                if let Some(peer) = current.as_mut() {
                    let seconds: u16 = value.parse().map_err(|_| HelperError::UapiMalformed)?;
                    peer.persistent_keepalive_seconds = (seconds != 0).then_some(seconds);
                }
            }
            "last_handshake_time_sec" => {
                if let Some(peer) = current.as_mut() {
                    let seconds: u64 = value.parse().map_err(|_| HelperError::UapiMalformed)?;
                    peer.handshake_seconds = seconds;
                }
            }
            "last_handshake_time_nsec" => {
                if let Some(peer) = current.as_mut() {
                    let nanos: u32 = value.parse().map_err(|_| HelperError::UapiMalformed)?;
                    peer.handshake_nanos = nanos;
                }
            }
            "tx_bytes" => {
                if let Some(peer) = current.as_mut() {
                    peer.tx_bytes = value.parse().ok();
                }
            }
            "rx_bytes" => {
                if let Some(peer) = current.as_mut() {
                    peer.rx_bytes = value.parse().ok();
                }
            }
            // The per-peer preshared key is a secret and is never read.
            "preshared_key" => {}
            _ => {}
        }
    }
    if let Some(peer) = current.take() {
        peers.push(peer.build());
    }
    Ok(ObservedWireGuardDevice {
        interface: interface.clone(),
        public_key,
        listen_port,
        peers,
    })
}

/// One peer's observation while the dump is being parsed.
#[derive(Debug)]
struct PeerObservation {
    public_key: PublicKey,
    allowed_ips: Vec<NetworkPrefix>,
    persistent_keepalive_seconds: Option<u16>,
    endpoint: Option<SocketAddr>,
    listen_port: Option<u16>,
    handshake_seconds: u64,
    handshake_nanos: u32,
    tx_bytes: Option<u64>,
    rx_bytes: Option<u64>,
}

impl PeerObservation {
    fn build(self) -> ObservedWireGuardPeer {
        let latest_handshake = (self.handshake_seconds != 0)
            .then(|| Duration::new(self.handshake_seconds, self.handshake_nanos));
        ObservedWireGuardPeer {
            public_key: self.public_key,
            allowed_ips: self.allowed_ips,
            persistent_keepalive_seconds: self.persistent_keepalive_seconds,
            endpoint: self.endpoint,
            latest_handshake,
            rx_bytes: self.rx_bytes,
            tx_bytes: self.tx_bytes,
        }
    }
}

/// Normalizes a reported endpoint: an unspecified address means "no endpoint".
fn normalize_endpoint(value: &str) -> Option<SocketAddr> {
    let endpoint: SocketAddr = value.parse().ok()?;
    let unspecified = match endpoint.ip() {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    };
    if unspecified && endpoint.port() == 0 {
        None
    } else {
        Some(endpoint)
    }
}

/// Decodes the helper's lowercase hex key form into the portable base64 form.
pub fn hex_to_base64(hex: &str) -> Result<String, HelperError> {
    if hex.is_empty() || hex.len() % 2 != 0 {
        return Err(HelperError::UapiMalformed);
    }
    let raw = hex.as_bytes();
    let mut bytes = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks(2) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or(HelperError::UapiMalformed)?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or(HelperError::UapiMalformed)?;
        bytes.push(((high << 4) | low) as u8);
    }
    Ok(STANDARD.encode(bytes))
}

/// Renders one portable device patch as a UAPI `set` command.
///
/// The wire form is the helper's own: `set=1`, then the device fields, then at
/// most one peer section. Every value is typed and rendered here; no raw
/// caller text reaches the socket.
pub fn render_uapi_patch(patch: &WireGuardDevicePatch) -> Result<String, HelperError> {
    let mut out = String::from("set=1\n");
    match &patch.private_key {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => out.push_str(&format!("private_key={}\n", "0".repeat(64))),
        FieldUpdate::Set(key) => {
            out.push_str(&format!(
                "private_key={}\n",
                base64_key_to_hex(key.expose_secret())?
            ));
        }
    }
    match patch.listen_port {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => out.push_str("listen_port=0\n"),
        FieldUpdate::Set(port) => out.push_str(&format!("listen_port={port}\n")),
    }
    if let Some(peer) = &patch.peer {
        render_peer_mutation(&mut out, peer)?;
    }
    out.push('\n');
    if out.len() > super::darwin::MAX_UAPI_REQUEST {
        return Err(HelperError::UapiMalformed);
    }
    Ok(out)
}

/// Renders one peer mutation into a UAPI peer section.
fn render_peer_mutation(out: &mut String, mutation: &PeerMutation) -> Result<(), HelperError> {
    match mutation {
        PeerMutation::Add(peer) => {
            out.push_str(&format!(
                "public_key={}\n",
                base64_key_to_hex(peer.public_key.expose())?
            ));
            if let Some(preshared) = &peer.preshared_key {
                out.push_str(&format!(
                    "preshared_key={}\n",
                    base64_key_to_hex(preshared.expose_secret())?
                ));
            }
            render_allowed_ips(out, &peer.allowed_ips);
            if let Some(keepalive) = peer.persistent_keepalive_seconds {
                out.push_str(&format!("persistent_keepalive_interval={keepalive}\n"));
            }
            if let Some(endpoint) = peer.endpoint {
                out.push_str(&format!("endpoint={endpoint}\n"));
            }
        }
        PeerMutation::Update(peer) => {
            render_peer_update(out, peer)?;
        }
        PeerMutation::Remove { public_key } => {
            out.push_str(&format!(
                "public_key={}\n",
                base64_key_to_hex(public_key.expose())?
            ));
            out.push_str("remove=true\n");
        }
    }
    Ok(())
}

/// Renders one partial peer update into a UAPI peer section.
fn render_peer_update(out: &mut String, peer: &WireGuardPeerPatch) -> Result<(), HelperError> {
    out.push_str(&format!(
        "public_key={}\n",
        base64_key_to_hex(peer.public_key.expose())?
    ));
    match &peer.preshared_key {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => out.push_str(&format!("preshared_key={}\n", "0".repeat(64))),
        FieldUpdate::Set(key) => {
            out.push_str(&format!(
                "preshared_key={}\n",
                base64_key_to_hex(key.expose_secret())?
            ));
        }
    }
    match &peer.allowed_ips {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => out.push_str("replace_allowed_ips=true\n"),
        FieldUpdate::Set(prefixes) => render_allowed_ips(out, prefixes),
    }
    match peer.persistent_keepalive_seconds {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => out.push_str("persistent_keepalive_interval=0\n"),
        FieldUpdate::Set(seconds) => {
            out.push_str(&format!("persistent_keepalive_interval={seconds}\n"))
        }
    }
    match peer.endpoint {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => out.push_str("endpoint=0.0.0.0:0\n"),
        FieldUpdate::Set(endpoint) => out.push_str(&format!("endpoint={endpoint}\n")),
    }
    Ok(())
}

/// Renders the allowed-IP section of a peer, replacing the peer's set.
fn render_allowed_ips(out: &mut String, prefixes: &[crate::domain::NetworkPrefix]) {
    out.push_str("replace_allowed_ips=true\n");
    for prefix in prefixes {
        out.push_str(&format!("allowed_ip={}\n", prefix.network()));
    }
}

/// Whether the desired peer set is already satisfied by the observation.
pub fn peer_matches(observed: &ObservedWireGuardPeer, desired: &DesiredWireGuardPeer) -> bool {
    observed.public_key == desired.public_key
        && observed.allowed_ips == desired.allowed_ips
        && observed.persistent_keepalive_seconds == desired.persistent_keepalive_seconds
        && observed.endpoint == desired.endpoint
}

/// Reads one UAPI `get` response into a typed device dump.
pub fn read_uapi_get(response: &str) -> Result<UapiDevice, HelperError> {
    parse_uapi_get(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface() -> InterfaceName {
        InterfaceName::new("wg-test").unwrap()
    }

    fn dump(pairs: &[(&str, &str)]) -> UapiDevice {
        UapiDevice {
            errno: 0,
            pairs: pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn a_device_dump_maps_onto_the_portable_observation() {
        let device = parse_uapi_device(
            &interface(),
            &dump(&[
                (
                    "private_key",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                ),
                ("listen_port", "51820"),
                (
                    "public_key",
                    "1111111111111111111111111111111111111111111111111111111111111111",
                ),
                (
                    "preshared_key",
                    "2222222222222222222222222222222222222222222222222222222222222222",
                ),
                ("protocol_version", "1"),
                ("endpoint", "192.0.2.10:51821"),
                ("last_handshake_time_sec", "12"),
                ("last_handshake_time_nsec", "500"),
                ("tx_bytes", "100"),
                ("rx_bytes", "200"),
                ("persistent_keepalive_interval", "25"),
                ("allowed_ip", "10.0.0.2/32"),
            ]),
        )
        .unwrap();
        assert_eq!(device.listen_port, Some(51820));
        assert_eq!(device.peers.len(), 1);
        let peer = &device.peers[0];
        assert_eq!(peer.allowed_ips.len(), 1);
        assert_eq!(peer.persistent_keepalive_seconds, Some(25));
        assert_eq!(peer.endpoint, Some("192.0.2.10:51821".parse().unwrap()));
        assert_eq!(peer.latest_handshake, Some(Duration::new(12, 500)));
        assert_eq!(peer.tx_bytes, Some(100));
        assert_eq!(peer.rx_bytes, Some(200));
    }

    #[test]
    fn a_zero_endpoint_is_reported_as_no_endpoint() {
        let device = parse_uapi_device(
            &interface(),
            &dump(&[
                (
                    "public_key",
                    "1111111111111111111111111111111111111111111111111111111111111111",
                ),
                ("endpoint", "0.0.0.0:0"),
            ]),
        )
        .unwrap();
        assert_eq!(device.peers[0].endpoint, None);
    }

    #[test]
    fn a_refused_dump_is_not_an_observation() {
        let refused = UapiDevice {
            errno: 1,
            pairs: Vec::new(),
        };
        assert!(parse_uapi_device(&interface(), &refused).is_err());
    }

    #[test]
    fn a_peer_update_renders_only_the_changed_fields() {
        let patch = WireGuardDevicePatch {
            private_key: FieldUpdate::Keep,
            listen_port: FieldUpdate::Keep,
            peer: Some(PeerMutation::Update(WireGuardPeerPatch {
                public_key: PublicKey::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into())
                    .unwrap(),
                preshared_key: FieldUpdate::Keep,
                allowed_ips: FieldUpdate::Set(vec!["10.0.0.0/24".parse().unwrap()]),
                persistent_keepalive_seconds: FieldUpdate::Keep,
                endpoint: FieldUpdate::Keep,
            })),
        };
        let rendered = render_uapi_patch(&patch).unwrap();
        assert!(rendered.starts_with("set=1\n"));
        assert!(rendered.contains("replace_allowed_ips=true\n"));
        assert!(rendered.contains("allowed_ip=10.0.0.0/24\n"));
        assert!(!rendered.contains("endpoint="));
        assert!(!rendered.contains("persistent_keepalive_interval="));
        assert!(rendered.ends_with("\n\n"));
    }

    #[test]
    fn hex_keys_decode_into_the_portable_base64_form() {
        let encoded = hex_to_base64("00ff10").unwrap();
        assert_eq!(encoded, "AP8Q");
        assert!(hex_to_base64("0g").is_err());
        assert!(hex_to_base64("").is_err());
    }
}
