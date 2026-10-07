use crate::domain::{InterfaceName, NetworkPrefix, PresharedKey, PrivateKey, PublicKey};
mod backend;
mod keys;

pub use backend::WireGuardBackend;
pub use keys::{derive_public_key, generate_keypair, WireGuardKeyPair};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "update", content = "value", rename_all = "snake_case")]
pub enum FieldUpdate<T> {
    Keep,
    Clear,
    Set(T),
}

impl<T> Default for FieldUpdate<T> {
    fn default() -> Self {
        Self::Keep
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardDevicePatch {
    #[serde(default)]
    pub private_key: FieldUpdate<PrivateKey>,
    #[serde(default)]
    pub listen_port: FieldUpdate<u16>,
    /// At most one peer operation per request keeps each netlink change bounded and attributable.
    pub peer: Option<PeerMutation>,
}

impl WireGuardDevicePatch {
    pub fn is_empty(&self) -> bool {
        matches!(self.private_key, FieldUpdate::Keep)
            && matches!(self.listen_port, FieldUpdate::Keep)
            && self.peer.is_none()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "action", content = "peer", rename_all = "snake_case")]
pub enum PeerMutation {
    Add(DesiredWireGuardPeer),
    Update(WireGuardPeerPatch),
    Remove { public_key: PublicKey },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredWireGuardPeer {
    pub public_key: PublicKey,
    pub preshared_key: Option<PresharedKey>,
    pub allowed_ips: Vec<NetworkPrefix>,
    pub persistent_keepalive_seconds: Option<u16>,
    pub endpoint: Option<SocketAddr>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardPeerPatch {
    pub public_key: PublicKey,
    #[serde(default)]
    pub preshared_key: FieldUpdate<PresharedKey>,
    #[serde(default)]
    pub allowed_ips: FieldUpdate<Vec<NetworkPrefix>>,
    #[serde(default)]
    pub persistent_keepalive_seconds: FieldUpdate<u16>,
    #[serde(default)]
    pub endpoint: FieldUpdate<SocketAddr>,
}

impl WireGuardPeerPatch {
    pub fn is_empty(&self) -> bool {
        matches!(self.preshared_key, FieldUpdate::Keep)
            && matches!(self.allowed_ips, FieldUpdate::Keep)
            && matches!(self.persistent_keepalive_seconds, FieldUpdate::Keep)
            && matches!(self.endpoint, FieldUpdate::Keep)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedWireGuardDevice {
    pub interface: InterfaceName,
    pub public_key: Option<PublicKey>,
    pub listen_port: Option<u16>,
    pub peers: Vec<ObservedWireGuardPeer>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedWireGuardPeer {
    pub public_key: PublicKey,
    pub allowed_ips: Vec<NetworkPrefix>,
    pub persistent_keepalive_seconds: Option<u16>,
    pub endpoint: Option<SocketAddr>,
    pub latest_handshake: Option<std::time::Duration>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardApplyReceipt {
    pub interface: InterfaceName,
    pub disposition: ApplyDisposition,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyDisposition {
    Applied,
    NoChange,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WireGuardValidationError {
    #[error("device patch contains no change")]
    EmptyPatch,
    #[error("listen port must be nonzero when set")]
    InvalidListenPort,
    #[error("persistent keepalive must be nonzero when set")]
    InvalidKeepalive,
    #[error("peer operation contains no change")]
    EmptyPeerPatch,
    #[error("peer operation contains too many AllowedIPs")]
    TooManyAllowedIps,
    #[error("peer operation contains a duplicate AllowedIP")]
    DuplicateAllowedIp,
    #[error("AllowedIPs overlap a different peer's cryptokey route")]
    ConflictingAllowedIps,
    #[error("peer endpoint port must be nonzero when set")]
    InvalidEndpoint,
    #[error("peer public key already exists")]
    PeerAlreadyExists,
    #[error("peer public key does not exist")]
    PeerNotFound,
    #[error("interface does not exist or is not a WireGuard device")]
    InterfaceUnavailable,
    #[error("WireGuard key was rejected by the backend")]
    InvalidKey,
    #[error("WireGuard backend rejected the requested configuration")]
    InvalidBackendInput,
    #[error("insufficient privilege to control the WireGuard device")]
    PermissionDenied,
    #[error("kernel or backend does not support this WireGuard operation")]
    UnsupportedBackend,
    #[error("WireGuard kernel rejected the request")]
    KernelRejected,
    #[error("WireGuard backend failed")]
    BackendFailure,
}

pub fn validate_device_patch(patch: &WireGuardDevicePatch) -> Result<(), WireGuardValidationError> {
    if patch.is_empty() {
        return Err(WireGuardValidationError::EmptyPatch);
    }
    if matches!(patch.listen_port, FieldUpdate::Set(0)) {
        return Err(WireGuardValidationError::InvalidListenPort);
    }
    if let Some(peer) = &patch.peer {
        match peer {
            PeerMutation::Add(peer) => {
                validate_allowed_ips(&peer.allowed_ips)?;
                if peer.persistent_keepalive_seconds == Some(0) {
                    return Err(WireGuardValidationError::InvalidKeepalive);
                }
                if peer.endpoint.is_some_and(|endpoint| endpoint.port() == 0) {
                    return Err(WireGuardValidationError::InvalidEndpoint);
                }
            }
            PeerMutation::Update(peer) => {
                if peer.is_empty() {
                    return Err(WireGuardValidationError::EmptyPeerPatch);
                }
                if let FieldUpdate::Set(prefixes) = &peer.allowed_ips {
                    validate_allowed_ips(prefixes)?;
                }
                if matches!(peer.persistent_keepalive_seconds, FieldUpdate::Set(0)) {
                    return Err(WireGuardValidationError::InvalidKeepalive);
                }
                if matches!(peer.endpoint, FieldUpdate::Set(endpoint) if endpoint.port() == 0) {
                    return Err(WireGuardValidationError::InvalidEndpoint);
                }
            }
            PeerMutation::Remove { .. } => {}
        }
    }
    Ok(())
}

pub fn validate_allowed_ips(prefixes: &[NetworkPrefix]) -> Result<(), WireGuardValidationError> {
    const MAX_ALLOWED_IPS: usize = 256;
    if prefixes.len() > MAX_ALLOWED_IPS {
        return Err(WireGuardValidationError::TooManyAllowedIps);
    }
    for (index, prefix) in prefixes.iter().enumerate() {
        if prefixes[index + 1..]
            .iter()
            .any(|other| prefix.network() == other.network())
        {
            return Err(WireGuardValidationError::DuplicateAllowedIp);
        }
    }
    Ok(())
}

pub fn prefixes_overlap(first: &NetworkPrefix, second: &NetworkPrefix) -> bool {
    let first_net = first.network();
    let second_net = second.network();
    first_net.addr().is_ipv4() == second_net.addr().is_ipv4()
        && (first_net.contains(&second_net.addr()) || second_net.contains(&first_net.addr()))
}

pub fn cleared_endpoint() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> PublicKey {
        PublicKey::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()).unwrap()
    }

    #[test]
    fn update_semantics_distinguish_keep_clear_and_set() {
        let keep = WireGuardDevicePatch {
            private_key: FieldUpdate::Keep,
            listen_port: FieldUpdate::Keep,
            peer: None,
        };
        assert_eq!(
            validate_device_patch(&keep),
            Err(WireGuardValidationError::EmptyPatch)
        );
        let clear = WireGuardDevicePatch {
            private_key: FieldUpdate::Clear,
            listen_port: FieldUpdate::Keep,
            peer: None,
        };
        assert!(validate_device_patch(&clear).is_ok());
        let invalid = WireGuardDevicePatch {
            private_key: FieldUpdate::Keep,
            listen_port: FieldUpdate::Set(0),
            peer: None,
        };
        assert_eq!(
            validate_device_patch(&invalid),
            Err(WireGuardValidationError::InvalidListenPort)
        );
        assert_eq!(
            key().expose(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }

    #[test]
    fn allowed_ip_validation_rejects_duplicates_and_detects_cross_peer_overlap() {
        let prefix: NetworkPrefix = "10.8.0.0/24".parse().unwrap();
        let host: NetworkPrefix = "10.8.0.2/32".parse().unwrap();
        assert_eq!(
            validate_allowed_ips(&[prefix.clone(), prefix.clone()]),
            Err(WireGuardValidationError::DuplicateAllowedIp)
        );
        assert!(prefixes_overlap(&prefix, &host));
        let other_family: NetworkPrefix = "2001:db8::/64".parse().unwrap();
        assert!(!prefixes_overlap(&prefix, &other_family));
    }

    #[test]
    fn secret_debug_is_redacted_inside_protocol_operation() {
        let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned();
        let patch = WireGuardDevicePatch {
            private_key: FieldUpdate::Set(PrivateKey::new(secret.clone()).unwrap()),
            listen_port: FieldUpdate::Keep,
            peer: None,
        };
        assert!(!format!("{patch:?}").contains(&secret));
        let encoded = serde_json::to_string(&patch).unwrap();
        let decoded: WireGuardDevicePatch = serde_json::from_str(&encoded).unwrap();
        assert!(!format!("{decoded:?}").contains(&secret));
    }
}
