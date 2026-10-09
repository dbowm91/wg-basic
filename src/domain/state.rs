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
    /// Optional IPv6 address assigned to the same client. IPv4 remains
    /// required for compatibility with the current product contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_ipv6_address: Option<IpNet>,
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
            client
                .route_policy
                .validate()
                .map_err(|_| StateValidationError::ClientRoutePolicyInvalid)?;
            if client
                .route_policy
                .prefixes
                .iter()
                .any(|prefix| prefix.network().addr().is_ipv6())
                && client.assigned_ipv6_address.is_none()
            {
                return Err(StateValidationError::ClientIpv6RouteRequiresIpv6Assignment);
            }
            if !client.assigned_address.addr().is_ipv4() {
                return Err(StateValidationError::ClientPrimaryAddressNotIpv4);
            }
            if !peer_ids.contains(&client.peer_id) {
                return Err(StateValidationError::ClientPeerMissing);
            }
            let peer = self
                .peers
                .iter()
                .find(|peer| peer.id == client.peer_id)
                .expect("peer id checked above");
            let mut client_addresses = vec![&client.assigned_address];
            if let Some(address) = &client.assigned_ipv6_address {
                if !address.addr().is_ipv6() {
                    return Err(StateValidationError::ClientSecondaryAddressNotIpv6);
                }
                client_addresses.push(address);
            }
            for address in client_addresses {
                let ip = address.addr();
                let host_prefix = if ip.is_ipv4() { 32 } else { 128 };
                if address.prefix_len() != host_prefix {
                    return Err(StateValidationError::ClientAddressMustBeHostPrefix);
                }
                if !self
                    .tunnel_prefixes
                    .iter()
                    .any(|prefix| prefix.family_matches(ip) && prefix.contains(ip))
                {
                    return Err(StateValidationError::ClientAddressOutsideTunnel(ip));
                }
                if !peer
                    .allowed_ips
                    .iter()
                    .any(|prefix| prefix.network().eq(address))
                {
                    return Err(StateValidationError::ClientAddressNotAllowedForPeer);
                }
                if !assigned.insert(ip) {
                    return Err(StateValidationError::DuplicateClientAddress(ip));
                }
            }
        }
        Ok(())
    }
}

/// Desired IPv4/IPv6 forwarding and IPv4 NAT policy for one managed interface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredNetworkPolicy {
    /// The managed interface this policy protects. It must reference an
    /// interface present in the same snapshot.
    pub wireguard_interface: InterfaceName,
    /// Whether host IPv4 forwarding is required.
    pub ipv4_forwarding_required: bool,
    /// Whether host IPv6 forwarding is required. This is independent of merely
    /// assigning IPv6 tunnel addresses.
    #[serde(default)]
    pub ipv6_forwarding_required: bool,
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
    #[error("client's required primary address must be IPv4")]
    ClientPrimaryAddressNotIpv4,
    #[error("client's optional secondary address must be IPv6")]
    ClientSecondaryAddressNotIpv6,
    #[error("client route policy is invalid (maximum 64 unique unicast prefixes)")]
    ClientRoutePolicyInvalid,
    #[error("IPv6 client routes require a managed server IPv6 tunnel pool")]
    ClientIpv6RouteRequiresServerIpv6Pool,
    #[error("IPv6 client routes require an IPv6 address assigned to that client")]
    ClientIpv6RouteRequiresIpv6Assignment,
    #[error("two managed interfaces share the name {0}")]
    DuplicateInterfaceName(InterfaceName),
    #[error("network policy references {0}, which is not a managed interface")]
    NetworkPolicyUnknownInterface(InterfaceName),
    #[error("network policy source prefixes must be valid unicast prefixes")]
    NetworkPolicyInvalidPrefix,
    #[error("IPv6 forwarding requires an IPv6 source prefix")]
    NetworkPolicyIpv6PrefixRequired,
    #[error("IPv6 network policy source prefix is outside its managed tunnel prefix")]
    NetworkPolicyIpv6PrefixNotManaged,
    #[error("network policy requires at least one source prefix")]
    NetworkPolicyEmptySourcePrefixes,
    #[error("peer identifier {0} is declared more than once")]
    DuplicatePeerId(String),
    #[error("client identifier {0} is declared more than once")]
    DuplicateClientId(String),
}

/// Validates a whole desired snapshot, including cross-interface relationships.
pub fn validate_desired_state(state: &DesiredState) -> Result<(), StateValidationError> {
    state
        .client_routes
        .validate()
        .map_err(|_| StateValidationError::ClientRoutePolicyInvalid)?;
    if state
        .client_routes
        .prefixes
        .iter()
        .any(|prefix| prefix.network().addr().is_ipv6())
        && !state.interfaces.iter().any(|interface| {
            interface
                .tunnel_prefixes
                .iter()
                .any(|prefix| prefix.network().addr().is_ipv6())
        })
    {
        return Err(StateValidationError::ClientIpv6RouteRequiresServerIpv6Pool);
    }
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
        let Some(interface) = state
            .interfaces
            .iter()
            .find(|interface| interface.name == policy.wireguard_interface)
        else {
            return Err(StateValidationError::NetworkPolicyUnknownInterface(
                policy.wireguard_interface.clone(),
            ));
        };
        if policy.source_prefixes.is_empty() {
            return Err(StateValidationError::NetworkPolicyEmptySourcePrefixes);
        }
        if policy.source_prefixes.iter().any(|prefix| {
            prefix.network().addr().is_unspecified() || prefix.network().addr().is_multicast()
        }) {
            return Err(StateValidationError::NetworkPolicyInvalidPrefix);
        }
        if policy.ipv6_forwarding_required
            && !policy
                .source_prefixes
                .iter()
                .any(|prefix| prefix.network().addr().is_ipv6())
        {
            return Err(StateValidationError::NetworkPolicyIpv6PrefixRequired);
        }
        if policy
            .source_prefixes
            .iter()
            .filter(|prefix| prefix.network().addr().is_ipv6())
            .any(|prefix| !interface.tunnel_prefixes.contains(prefix))
        {
            return Err(StateValidationError::NetworkPolicyIpv6PrefixNotManaged);
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
                assigned_ipv6_address: None,
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

    #[test]
    fn global_ipv6_routes_require_a_managed_server_ipv6_pool() {
        let mut desired = DesiredState {
            interfaces: vec![interface()],
            client_routes: ClientRoutePolicy {
                prefixes: vec!["::/0".parse().unwrap()],
            },
            network_policy: None,
        };
        assert_eq!(
            validate_desired_state(&desired),
            Err(StateValidationError::ClientIpv6RouteRequiresServerIpv6Pool)
        );
        desired.interfaces[0]
            .tunnel_prefixes
            .push(NetworkPrefix::new("fd77::/64".parse().unwrap()));
        assert_eq!(validate_desired_state(&desired), Ok(()));
    }
}
