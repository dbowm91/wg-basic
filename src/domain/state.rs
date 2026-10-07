use super::{ClientRoutePolicy, InterfaceId, InterfaceName, NetworkPrefix, PeerId, PublicKey};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesiredPeer {
    pub id: PeerId,
    pub public_key: PublicKey,
    /// Server-side WireGuard cryptokey-routing prefixes.
    pub allowed_ips: Vec<NetworkPrefix>,
    pub persistent_keepalive_seconds: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesiredClient {
    pub id: super::ClientId,
    pub peer_id: PeerId,
    /// Address assigned to this client inside this interface's managed tunnel prefixes.
    pub assigned_address: IpNet,
    /// Client-side routes; these are not server-side peer AllowedIPs.
    pub route_policy: ClientRoutePolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesiredInterface {
    pub id: InterfaceId,
    pub name: InterfaceName,
    pub tunnel_prefixes: Vec<NetworkPrefix>,
    pub listen_port: Option<u16>,
    pub peers: Vec<DesiredPeer>,
    pub clients: Vec<DesiredClient>,
}

impl DesiredInterface {
    pub fn validate(&self) -> Result<(), StateValidationError> {
        if self.listen_port == Some(0) {
            return Err(StateValidationError::InvalidListenPort);
        }
        let mut keys = std::collections::HashSet::new();
        for peer in &self.peers {
            if !keys.insert(peer.public_key.expose()) {
                return Err(StateValidationError::DuplicatePeerKey);
            }
        }
        let peer_ids = self
            .peers
            .iter()
            .map(|peer| peer.id)
            .collect::<std::collections::HashSet<_>>();
        let mut assigned = std::collections::HashSet::new();
        for client in &self.clients {
            let address = client.assigned_address.addr();
            let host_prefix = if address.is_ipv4() { 32 } else { 128 };
            if client.assigned_address.prefix_len() != host_prefix {
                return Err(StateValidationError::ClientAddressMustBeHostPrefix);
            }
            if !self
                .tunnel_prefixes
                .iter()
                .any(|prefix| prefix.contains(address))
            {
                return Err(StateValidationError::ClientAddressOutsideTunnel(address));
            }
            if !peer_ids.contains(&client.peer_id) {
                return Err(StateValidationError::ClientPeerMissing);
            }
            let peer = self
                .peers
                .iter()
                .find(|peer| peer.id == client.peer_id)
                .expect("peer id checked above");
            if !peer
                .allowed_ips
                .iter()
                .any(|prefix| prefix.contains(address))
            {
                return Err(StateValidationError::ClientAddressNotAllowedForPeer);
            }
            if !assigned.insert(address) {
                return Err(StateValidationError::DuplicateClientAddress(address));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesiredState {
    pub interfaces: Vec<DesiredInterface>,
    pub client_routes: ClientRoutePolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservedInterface {
    pub name: InterfaceName,
    pub addresses: Vec<IpNet>,
    pub listen_port: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StateValidationError {
    #[error("listen port must be between 1 and 65535")]
    InvalidListenPort,
    #[error("peer public key appears more than once")]
    DuplicatePeerKey,
    #[error("client address {0} is assigned more than once")]
    DuplicateClientAddress(IpAddr),
    #[error("client address {0} is outside the managed tunnel prefixes")]
    ClientAddressOutsideTunnel(IpAddr),
    #[error("client assigned address must use a host prefix (/32 or /128)")]
    ClientAddressMustBeHostPrefix,
    #[error("client references a peer that is not part of this interface")]
    ClientPeerMissing,
    #[error("client assigned address is not covered by its peer's server-side AllowedIPs")]
    ClientAddressNotAllowedForPeer,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ClientId, InterfaceId};

    fn interface() -> DesiredInterface {
        let address: IpNet = "10.8.0.2/32".parse().unwrap();
        let peer_id = PeerId::new();
        DesiredInterface {
            id: InterfaceId::new(),
            name: "wg0".parse().unwrap(),
            tunnel_prefixes: vec!["10.8.0.0/24".parse().unwrap()],
            listen_port: Some(51820),
            peers: vec![DesiredPeer {
                id: peer_id,
                public_key: PublicKey::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into())
                    .unwrap(),
                allowed_ips: vec![NetworkPrefix::new(address)],
                persistent_keepalive_seconds: None,
            }],
            clients: vec![DesiredClient {
                id: ClientId::new(),
                peer_id,
                assigned_address: address,
                route_policy: ClientRoutePolicy::default(),
            }],
        }
    }

    #[test]
    fn validates_client_assignment_relationships_and_unique_addresses() {
        let desired = interface();
        assert!(desired.validate().is_ok());

        let mut duplicate = desired.clone();
        duplicate.clients.push(DesiredClient {
            id: ClientId::new(),
            ..duplicate.clients[0].clone()
        });
        assert!(matches!(
            duplicate.validate(),
            Err(StateValidationError::DuplicateClientAddress(_))
        ));

        let mut outside = desired.clone();
        outside.clients[0].assigned_address = "192.0.2.1/32".parse().unwrap();
        assert!(matches!(
            outside.validate(),
            Err(StateValidationError::ClientAddressOutsideTunnel(_))
        ));
    }
}
