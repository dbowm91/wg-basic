//! wireguard-nt adapter lifecycle.
//!
//! A handle from `WireGuardCreateAdapter` is retained for the life of the
//! adapter. Closing that handle removes the adapter. A handle from
//! `WireGuardOpenAdapter` does not, so a foreign adapter can be inspected and
//! released without deleting it.

use super::{
    ApplyDisposition, DesiredWireGuardPeer, FieldUpdate, ObservedWireGuardDevice,
    ObservedWireGuardPeer, PeerMutation, WireGuardApplyReceipt, WireGuardDevicePatch,
    WireGuardPeerPatch, WireGuardValidationError,
};
use crate::domain::{InterfaceName, NetworkPrefix};
use crate::platform::windows::{self, RUNTIME_DIR};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

const FILETIME_TO_UNIX_SECONDS: u64 = 11_644_473_600;

struct Held {
    adapter: wg_basic_win32_sys::Adapter,
    /// True when this process called `WireGuardCreateAdapter`. Only that
    /// handle removes the adapter on close.
    created_here: bool,
}

fn held() -> &'static Mutex<HashMap<String, Held>> {
    static HELD: std::sync::OnceLock<Mutex<HashMap<String, Held>>> = std::sync::OnceLock::new();
    HELD.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn observe_device(
    interface: &InterfaceName,
) -> Result<ObservedWireGuardDevice, WireGuardValidationError> {
    ensure_loaded()?;
    let guard = held()
        .lock()
        .map_err(|_| WireGuardValidationError::BackendFailure)?;
    let held = guard
        .get(interface.as_str())
        .ok_or(WireGuardValidationError::InterfaceUnavailable)?;
    device_from(interface, &held.adapter)
}

pub fn apply_patch(
    interface: &InterfaceName,
    patch: WireGuardDevicePatch,
) -> Result<WireGuardApplyReceipt, WireGuardValidationError> {
    super::validate_device_patch(&patch)?;
    ensure_loaded()?;
    let guard = held()
        .lock()
        .map_err(|_| WireGuardValidationError::BackendFailure)?;
    let held = guard
        .get(interface.as_str())
        .ok_or(WireGuardValidationError::InterfaceUnavailable)?;
    let mut config = held
        .adapter
        .get_config()
        .map_err(|_| WireGuardValidationError::BackendFailure)?;
    let changed = merge_patch(&mut config, &patch)?;
    if changed {
        held.adapter
            .set_config(&config)
            .map_err(|_| WireGuardValidationError::KernelRejected)?;
    }
    Ok(WireGuardApplyReceipt {
        interface: interface.clone(),
        disposition: if changed {
            ApplyDisposition::Applied
        } else {
            ApplyDisposition::NoChange
        },
    })
}

/// Creates the adapter when this installation's GUID is free, or adopts one
/// this process already holds. A different GUID on the same name is left in
/// place.
pub fn create_adapter(
    interface: &InterfaceName,
    guid: [u8; 16],
) -> Result<(), WireGuardValidationError> {
    ensure_loaded()?;
    let mut guard = held()
        .lock()
        .map_err(|_| WireGuardValidationError::BackendFailure)?;
    if let Some(existing) = guard.get(interface.as_str()) {
        if existing.adapter.guid == guid {
            return Ok(());
        }
        return Err(WireGuardValidationError::InterfaceUnavailable);
    }
    match wg_basic_win32_sys::Adapter::open(interface.as_str()) {
        Ok(opened) => {
            let matches = opened.guid == guid && receipt_matches(interface, guid);
            drop(opened);
            if !matches {
                return Err(WireGuardValidationError::InterfaceUnavailable);
            }
            let adopted = wg_basic_win32_sys::Adapter::open(interface.as_str())
                .map_err(|_| WireGuardValidationError::BackendFailure)?;
            guard.insert(
                interface.as_str().to_owned(),
                Held {
                    adapter: adopted,
                    created_here: false,
                },
            );
            Ok(())
        }
        Err(_) => {
            let created = wg_basic_win32_sys::Adapter::create(interface.as_str(), &guid)
                .map_err(|_| WireGuardValidationError::BackendFailure)?;
            write_receipt(interface, &created)?;
            guard.insert(
                interface.as_str().to_owned(),
                Held {
                    adapter: created,
                    created_here: true,
                },
            );
            Ok(())
        }
    }
}

pub fn delete_adapter(interface: &InterfaceName) -> Result<(), WireGuardValidationError> {
    let mut guard = held()
        .lock()
        .map_err(|_| WireGuardValidationError::BackendFailure)?;
    match guard.remove(interface.as_str()) {
        Some(held) if held.created_here => {
            drop(held);
            let _ = std::fs::remove_file(receipt_path(interface));
            Ok(())
        }
        Some(held) => {
            guard.insert(interface.as_str().to_owned(), held);
            Err(WireGuardValidationError::InterfaceUnavailable)
        }
        None => Err(WireGuardValidationError::InterfaceUnavailable),
    }
}

pub fn set_up(interface: &InterfaceName, up: bool) -> Result<(), WireGuardValidationError> {
    let guard = held()
        .lock()
        .map_err(|_| WireGuardValidationError::BackendFailure)?;
    let held = guard
        .get(interface.as_str())
        .ok_or(WireGuardValidationError::InterfaceUnavailable)?;
    held.adapter
        .set_up(up)
        .map_err(|_| WireGuardValidationError::BackendFailure)
}

pub enum Presence {
    Absent,
    Owned,
    Foreign,
}

/// Opens an existing adapter without creating one. An owned adapter is retained
/// so later mutations use the same handle. A foreign adapter is closed without
/// being removed.
pub fn probe(
    interface: &InterfaceName,
    guid: [u8; 16],
) -> Result<Presence, WireGuardValidationError> {
    ensure_loaded()?;
    if guid_matches(interface, &guid) {
        return Ok(Presence::Owned);
    }
    match wg_basic_win32_sys::Adapter::open(interface.as_str()) {
        Err(_) => Ok(Presence::Absent),
        Ok(opened) => {
            let owned = opened.guid == guid && receipt_matches(interface, guid);
            drop(opened);
            if !owned {
                return Ok(Presence::Foreign);
            }
            let adopted = wg_basic_win32_sys::Adapter::open(interface.as_str())
                .map_err(|_| WireGuardValidationError::BackendFailure)?;
            held()
                .lock()
                .map_err(|_| WireGuardValidationError::BackendFailure)?
                .insert(
                    interface.as_str().to_owned(),
                    Held {
                        adapter: adopted,
                        created_here: false,
                    },
                );
            Ok(Presence::Owned)
        }
    }
}

pub fn is_up(interface: &InterfaceName) -> Result<bool, WireGuardValidationError> {
    let guard = held()
        .lock()
        .map_err(|_| WireGuardValidationError::BackendFailure)?;
    let held = guard
        .get(interface.as_str())
        .ok_or(WireGuardValidationError::InterfaceUnavailable)?;
    held.adapter
        .is_up()
        .map_err(|_| WireGuardValidationError::BackendFailure)
}

pub fn luid(interface: &InterfaceName) -> Result<u64, WireGuardValidationError> {
    let guard = held()
        .lock()
        .map_err(|_| WireGuardValidationError::BackendFailure)?;
    guard
        .get(interface.as_str())
        .map(|held| held.adapter.luid)
        .ok_or(WireGuardValidationError::InterfaceUnavailable)
}

pub fn guid_matches(interface: &InterfaceName, guid: &[u8; 16]) -> bool {
    held()
        .lock()
        .ok()
        .and_then(|guard| {
            guard
                .get(interface.as_str())
                .map(|held| held.adapter.guid == *guid)
        })
        .unwrap_or(false)
}

fn ensure_loaded() -> Result<(), WireGuardValidationError> {
    let dll = dll_path().ok_or(WireGuardValidationError::UnsupportedBackend)?;
    if !windows::dll_matches_pin(&dll) {
        return Err(WireGuardValidationError::UnsupportedBackend);
    }
    match wg_basic_win32_sys::load_wireguard(&dll) {
        Ok(()) => Ok(()),
        Err(error) if error.to_string().contains("already loaded") => Ok(()),
        Err(_) => Err(WireGuardValidationError::BackendFailure),
    }
}

fn dll_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.join("wireguard.dll"))
}

fn device_from(
    interface: &InterfaceName,
    adapter: &wg_basic_win32_sys::Adapter,
) -> Result<ObservedWireGuardDevice, WireGuardValidationError> {
    let config = adapter
        .get_config()
        .map_err(|_| WireGuardValidationError::BackendFailure)?;
    let mut peers = Vec::new();
    for peer in config.peers {
        let public_key = crate::domain::PublicKey::new(STANDARD.encode(peer.public_key))
            .map_err(|_| WireGuardValidationError::InvalidKey)?;
        let allowed_ips = peer
            .allowed_ips
            .into_iter()
            .filter_map(|(addr, prefix)| {
                let net = ipnet::IpNet::new(addr, prefix).ok()?;
                Some(NetworkPrefix::new(net))
            })
            .collect();
        peers.push(ObservedWireGuardPeer {
            public_key,
            allowed_ips,
            persistent_keepalive_seconds: (peer.persistent_keepalive != 0)
                .then_some(peer.persistent_keepalive),
            endpoint: peer.endpoint.filter(|endpoint| endpoint.port() != 0),
            latest_handshake: handshake_unix(peer.last_handshake),
            rx_bytes: Some(peer.rx_bytes),
            tx_bytes: Some(peer.tx_bytes),
            preshared_key_configured: peer.preshared_key.is_some(),
        });
    }
    Ok(ObservedWireGuardDevice {
        interface: interface.clone(),
        public_key: config
            .public_key
            .and_then(|key| crate::domain::PublicKey::new(STANDARD.encode(key)).ok()),
        listen_port: (config.listen_port != 0).then_some(config.listen_port),
        peers,
    })
}

fn handshake_unix(filetime: u64) -> Option<Duration> {
    if filetime == 0 {
        return None;
    }
    let seconds = filetime / 10_000_000;
    seconds
        .checked_sub(FILETIME_TO_UNIX_SECONDS)
        .map(Duration::from_secs)
}

fn merge_patch(
    config: &mut wg_basic_win32_sys::DeviceConfig,
    patch: &WireGuardDevicePatch,
) -> Result<bool, WireGuardValidationError> {
    let mut changed = false;
    match &patch.private_key {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => {
            if config.private_key.is_some() || config.public_key.is_some() {
                config.private_key = None;
                config.public_key = None;
                changed = true;
            }
        }
        FieldUpdate::Set(key) => {
            let bytes = key_bytes(key.expose_secret())?;
            let public = crate::domain::derive_public_key(key)
                .map_err(|_| WireGuardValidationError::InvalidKey)?;
            let public_bytes = key_bytes(public.expose())?;
            if config.private_key != Some(bytes) {
                config.private_key = Some(bytes);
                config.public_key = Some(public_bytes);
                changed = true;
            }
        }
    }
    match patch.listen_port {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => {
            if config.listen_port != 0 {
                config.listen_port = 0;
                changed = true;
            }
        }
        FieldUpdate::Set(port) => {
            if config.listen_port != port {
                config.listen_port = port;
                changed = true;
            }
        }
    }
    if let Some(peer) = &patch.peer {
        changed |= merge_peer(config, peer)?;
    }
    Ok(changed)
}

fn merge_peer(
    config: &mut wg_basic_win32_sys::DeviceConfig,
    peer: &PeerMutation,
) -> Result<bool, WireGuardValidationError> {
    match peer {
        PeerMutation::Remove { public_key } => {
            let bytes = key_bytes(public_key.expose())?;
            let before = config.peers.len();
            config.peers.retain(|peer| peer.public_key != bytes);
            if config.peers.len() == before {
                return Err(WireGuardValidationError::PeerNotFound);
            }
            Ok(true)
        }
        PeerMutation::Add(peer) => {
            let bytes = key_bytes(peer.public_key.expose())?;
            if config
                .peers
                .iter()
                .any(|current| current.public_key == bytes)
            {
                return Err(WireGuardValidationError::PeerAlreadyExists);
            }
            reject_overlap(config, &bytes, &peer.allowed_ips)?;
            config.peers.push(peer_config(peer)?);
            Ok(true)
        }
        PeerMutation::Update(patch) => update_peer(config, patch),
    }
}

fn update_peer(
    config: &mut wg_basic_win32_sys::DeviceConfig,
    patch: &WireGuardPeerPatch,
) -> Result<bool, WireGuardValidationError> {
    let bytes = key_bytes(patch.public_key.expose())?;
    let peer = config
        .peers
        .iter_mut()
        .find(|peer| peer.public_key == bytes)
        .ok_or(WireGuardValidationError::PeerNotFound)?;
    let mut changed = false;
    match &patch.preshared_key {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => {
            if peer.preshared_key.is_some() {
                peer.preshared_key = None;
                changed = true;
            }
        }
        FieldUpdate::Set(key) => {
            let next = key_bytes(key.expose_secret())?;
            if peer.preshared_key != Some(next) {
                peer.preshared_key = Some(next);
                changed = true;
            }
        }
    }
    if let FieldUpdate::Set(prefixes) = &patch.allowed_ips {
        reject_overlap_except(config, &bytes, prefixes)?;
        let next = allowed(prefixes)?;
        let peer = config
            .peers
            .iter_mut()
            .find(|peer| peer.public_key == bytes)
            .ok_or(WireGuardValidationError::PeerNotFound)?;
        if peer.allowed_ips != next {
            peer.allowed_ips = next;
            changed = true;
        }
    }
    if let FieldUpdate::Set(seconds) = patch.persistent_keepalive_seconds {
        let peer = config
            .peers
            .iter_mut()
            .find(|peer| peer.public_key == bytes)
            .ok_or(WireGuardValidationError::PeerNotFound)?;
        if peer.persistent_keepalive != seconds {
            peer.persistent_keepalive = seconds;
            changed = true;
        }
    } else if matches!(patch.persistent_keepalive_seconds, FieldUpdate::Clear) {
        let peer = config
            .peers
            .iter_mut()
            .find(|peer| peer.public_key == bytes)
            .ok_or(WireGuardValidationError::PeerNotFound)?;
        if peer.persistent_keepalive != 0 {
            peer.persistent_keepalive = 0;
            changed = true;
        }
    }
    match patch.endpoint {
        FieldUpdate::Keep => {}
        FieldUpdate::Clear => {
            let peer = config
                .peers
                .iter_mut()
                .find(|peer| peer.public_key == bytes)
                .ok_or(WireGuardValidationError::PeerNotFound)?;
            if peer.endpoint.is_some() {
                peer.endpoint = None;
                changed = true;
            }
        }
        FieldUpdate::Set(endpoint) => {
            let peer = config
                .peers
                .iter_mut()
                .find(|peer| peer.public_key == bytes)
                .ok_or(WireGuardValidationError::PeerNotFound)?;
            if peer.endpoint != Some(endpoint) {
                peer.endpoint = Some(endpoint);
                changed = true;
            }
        }
    }
    Ok(changed)
}

fn reject_overlap(
    config: &wg_basic_win32_sys::DeviceConfig,
    _self_key: &[u8; 32],
    prefixes: &[NetworkPrefix],
) -> Result<(), WireGuardValidationError> {
    reject_overlap_except(config, &[0u8; 32], prefixes)
}

fn reject_overlap_except(
    config: &wg_basic_win32_sys::DeviceConfig,
    self_key: &[u8; 32],
    prefixes: &[NetworkPrefix],
) -> Result<(), WireGuardValidationError> {
    for peer in &config.peers {
        if &peer.public_key == self_key {
            continue;
        }
        for (addr, cidr) in &peer.allowed_ips {
            let Some(existing) = ipnet::IpNet::new(*addr, *cidr).ok().map(NetworkPrefix::new)
            else {
                continue;
            };
            if prefixes
                .iter()
                .any(|prefix| super::prefixes_overlap(prefix, &existing))
            {
                return Err(WireGuardValidationError::ConflictingAllowedIps);
            }
        }
    }
    Ok(())
}

fn peer_config(
    peer: &DesiredWireGuardPeer,
) -> Result<wg_basic_win32_sys::PeerConfig, WireGuardValidationError> {
    Ok(wg_basic_win32_sys::PeerConfig {
        public_key: key_bytes(peer.public_key.expose())?,
        preshared_key: peer
            .preshared_key
            .as_ref()
            .map(|key| key_bytes(key.expose_secret()))
            .transpose()?,
        persistent_keepalive: peer.persistent_keepalive_seconds.unwrap_or(0),
        endpoint: peer.endpoint,
        allowed_ips: allowed(&peer.allowed_ips)?,
        tx_bytes: 0,
        rx_bytes: 0,
        last_handshake: 0,
    })
}

fn allowed(prefixes: &[NetworkPrefix]) -> Result<Vec<(IpAddr, u8)>, WireGuardValidationError> {
    Ok(prefixes
        .iter()
        .map(|prefix| {
            let net = prefix.network();
            (net.addr(), net.prefix_len())
        })
        .collect())
}

fn key_bytes(text: &str) -> Result<[u8; 32], WireGuardValidationError> {
    let bytes = STANDARD
        .decode(text)
        .map_err(|_| WireGuardValidationError::InvalidKey)?;
    bytes
        .try_into()
        .map_err(|_| WireGuardValidationError::InvalidKey)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AdapterReceipt {
    guid: String,
    luid: u64,
    dll_sha256: String,
}

fn receipt_path(interface: &InterfaceName) -> PathBuf {
    Path::new(RUNTIME_DIR).join(format!("{}.adapter.json", interface.as_str()))
}

fn write_receipt(
    interface: &InterfaceName,
    adapter: &wg_basic_win32_sys::Adapter,
) -> Result<(), WireGuardValidationError> {
    let directory = Path::new(RUNTIME_DIR);
    std::fs::create_dir_all(directory).map_err(|_| WireGuardValidationError::BackendFailure)?;
    let _ = wg_basic_win32_sys::restrict_to_current_user(directory);
    let receipt = AdapterReceipt {
        guid: hex(&adapter.guid),
        luid: adapter.luid,
        dll_sha256: windows::WIREGUARD_NT_DLL_SHA256.to_owned(),
    };
    let path = receipt_path(interface);
    let encoded =
        serde_json::to_vec(&receipt).map_err(|_| WireGuardValidationError::BackendFailure)?;
    std::fs::write(&path, encoded).map_err(|_| WireGuardValidationError::BackendFailure)?;
    wg_basic_win32_sys::restrict_to_current_user(&path)
        .map_err(|_| WireGuardValidationError::BackendFailure)?;
    Ok(())
}

fn receipt_matches(interface: &InterfaceName, guid: [u8; 16]) -> bool {
    let Ok(bytes) = std::fs::read(receipt_path(interface)) else {
        return false;
    };
    let Ok(receipt) = serde_json::from_slice::<AdapterReceipt>(&bytes) else {
        return false;
    };
    receipt.guid.eq_ignore_ascii_case(&hex(&guid))
        && receipt
            .dll_sha256
            .eq_ignore_ascii_case(windows::WIREGUARD_NT_DLL_SHA256)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
