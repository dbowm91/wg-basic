use super::{
    ClientRoutePolicy, DesiredAddress, InterfaceId, InterfaceName, LinkLifecycle, ManagedRoute,
    NetworkPrefix, OwnershipDeclaration, PeerId, PresharedKey, PrivateKey, PublicKey,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesiredPeer {
    pub id: PeerId,
    pub public_key: PublicKey,
    /// Retained only when wg-basic generated or was given the client private key.
    /// This is secret-bearing and is never rendered by `Debug`/`Display`.
    pub private_key: Option<PrivateKey>,
    pub preshared_key: Option<PresharedKey>,
    /// Server-side WireGuard cryptokey-routing prefixes.
    pub allowed_ips: Vec<NetworkPrefix>,
    pub persistent_keepalive_seconds: Option<u16>,
    pub endpoint: Option<SocketAddr>,
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
    /// Whether wg-basic claims this link. Destructive reconciliation requires
    /// `Managed` plus a durable owner tag supplied by a later milestone.
    pub ownership: OwnershipDeclaration,
    pub lifecycle: LinkLifecycle,
    /// Required for a present link and omitted for an absent link.
    pub admin_up: Option<bool>,
    /// Server private key. Secret-bearing.
    pub private_key: PrivateKey,
    pub listen_port: Option<u16>,
    /// Authorizes removal of peers absent from this desired collection.
    pub manage_all_peers: bool,
    pub tunnel_prefixes: Vec<NetworkPrefix>,
    /// Exactly these addresses are managed; unlisted addresses survive.
    pub addresses: Vec<DesiredAddress>,
    /// Exactly these main-table routes are managed; unlisted routes survive.
    pub routes: Vec<ManagedRoute>,
    pub peers: Vec<DesiredPeer>,
    pub clients: Vec<DesiredClient>,
}

impl DesiredInterface {
    pub fn validate(&self) -> Result<(), StateValidationError> {
        if self.listen_port == Some(0) {
            return Err(StateValidationError::InvalidListenPort);
        }
        if self.lifecycle == LinkLifecycle::Present && self.admin_up.is_none() {
            return Err(StateValidationError::AdminUpRequiredForPresentLink);
        }
        if self.lifecycle == LinkLifecycle::Absent && self.admin_up.is_some() {
            return Err(StateValidationError::AdminUpNotAllowedForAbsentLink);
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

/// Desired IPv4 forwarding/NAT policy for one managed interface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredNetworkPolicy {
    /// The managed interface this policy protects. It must reference an
    /// interface present in the same snapshot.
    pub wireguard_interface: InterfaceName,
    /// Whether host IPv4 forwarding is required.
    pub ipv4_forwarding_required: bool,
    pub egress_interface: InterfaceName,
    pub source_prefixes: Vec<NetworkPrefix>,
    pub masquerade: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesiredState {
    pub interfaces: Vec<DesiredInterface>,
    pub client_routes: ClientRoutePolicy,
    /// At most one policy applies; it is owned by exactly one managed interface.
    pub network_policy: Option<DesiredNetworkPolicy>,
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
    #[error("a present link must declare its admin-up state")]
    AdminUpRequiredForPresentLink,
    #[error("an absent link must not declare an admin-up state")]
    AdminUpNotAllowedForAbsentLink,
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
    #[error("two managed interfaces share the name {0}")]
    DuplicateInterfaceName(InterfaceName),
    #[error("network policy references {0}, which is not a managed interface")]
    NetworkPolicyUnknownInterface(InterfaceName),
    #[error("network policy source prefixes must be IPv4")]
    NetworkPolicyNonIpv4Prefix,
    #[error("network policy requires at least one source prefix")]
    NetworkPolicyEmptySourcePrefixes,
    #[error("peer identifier {0} is declared more than once")]
    DuplicatePeerId(String),
    #[error("client identifier {0} is declared more than once")]
    DuplicateClientId(String),
}

/// Validates a whole desired snapshot, including cross-interface relationships.
pub fn validate_desired_state(state: &DesiredState) -> Result<(), StateValidationError> {
    let mut names = std::collections::HashSet::new();
    let mut peer_ids = std::collections::HashSet::new();
    let mut client_ids = std::collections::HashSet::new();
    for interface in &state.interfaces {
        if !names.insert(interface.name.clone()) {
            return Err(StateValidationError::DuplicateInterfaceName(
                interface.name.clone(),
            ));
        }
        interface.validate()?;
        for peer in &interface.peers {
            if !peer_ids.insert(peer.id) {
                return Err(StateValidationError::DuplicatePeerId(peer.id.to_string()));
            }
        }
        for client in &interface.clients {
            if !client_ids.insert(client.id) {
                return Err(StateValidationError::DuplicateClientId(
                    client.id.to_string(),
                ));
            }
        }
    }
    if let Some(policy) = &state.network_policy {
        if !state
            .interfaces
            .iter()
            .any(|interface| interface.name == policy.wireguard_interface)
        {
            return Err(StateValidationError::NetworkPolicyUnknownInterface(
                policy.wireguard_interface.clone(),
            ));
        }
        if policy.source_prefixes.is_empty() {
            return Err(StateValidationError::NetworkPolicyEmptySourcePrefixes);
        }
        if policy
            .source_prefixes
            .iter()
            .any(|prefix| !prefix.network().addr().is_ipv4())
        {
            return Err(StateValidationError::NetworkPolicyNonIpv4Prefix);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ClientId, InterfaceId};

    fn private_key() -> PrivateKey {
        PrivateKey::new("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".into()).unwrap()
    }

    fn interface() -> DesiredInterface {
        let address: IpNet = "10.8.0.2/32".parse().unwrap();
        let peer_id = PeerId::new();
        DesiredInterface {
            id: InterfaceId::new(),
            name: "wg0".parse().unwrap(),
            ownership: OwnershipDeclaration::Managed,
            lifecycle: LinkLifecycle::Present,
            admin_up: Some(true),
            private_key: private_key(),
            manage_all_peers: true,
            tunnel_prefixes: vec!["10.8.0.0/24".parse().unwrap()],
            addresses: Vec::new(),
            routes: Vec::new(),
            listen_port: Some(51820),
            peers: vec![DesiredPeer {
                id: peer_id,
                public_key: PublicKey::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into())
                    .unwrap(),
                private_key: None,
                preshared_key: None,
                allowed_ips: vec![NetworkPrefix::new(address)],
                persistent_keepalive_seconds: None,
                endpoint: None,
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
