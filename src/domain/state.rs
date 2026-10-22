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

/// The routing intent a managed network policy declares.
///
/// The mode is part of the persisted contract, not an implementation detail.
/// A policy that declares a routed LAN is held to a different security
/// contract than one that declares a host-only endpoint, and that difference
/// is visible in the persisted state, on the wire, and in the diagnostics.
///
/// The variants are deliberately exhaustive. `HostOnly` and `Gateway` describe
/// the two shapes that already existed; `RoutedLan` is the shape that forwards
/// authorized client traffic to an explicit allowlist of downstream LAN
/// prefixes without NAT.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicyMode {
    /// The managed tunnel carries only this host's own traffic.
    ///
    /// No forwarding is required, no NAT is performed, and no downstream
    /// destination is approved.
    #[default]
    HostOnly,
    /// The managed tunnel forwards authorized client traffic to an explicit
    /// allowlist of downstream LAN prefixes, without NAT.
    RoutedLan,
    /// The managed tunnel forwards authorized client traffic to any
    /// destination, optionally with IPv4 masquerade.
    Gateway,
}

/// The largest number of downstream prefixes a routed-LAN policy may name.
///
/// The allowlist is rendered into one filter rule per source and destination
/// pair, so it is bounded rather than open-ended.
pub const MAX_ROUTED_LAN_DESTINATIONS: usize = 16;

/// Desired IPv4/IPv6 forwarding and IPv4 NAT policy for one managed interface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredNetworkPolicy {
    /// The managed interface this policy protects. It must reference an
    /// interface present in the same snapshot.
    pub wireguard_interface: InterfaceName,
    /// The routing intent this policy declares.
    #[serde(default)]
    pub mode: NetworkPolicyMode,
    /// Whether host IPv4 forwarding is required.
    pub ipv4_forwarding_required: bool,
    /// Whether host IPv6 forwarding is required. This is independent of merely
    /// assigning IPv6 tunnel addresses.
    #[serde(default)]
    pub ipv6_forwarding_required: bool,
    pub egress_interface: InterfaceName,
    pub source_prefixes: Vec<NetworkPrefix>,
    /// The approved downstream LAN prefixes.
    ///
    /// Only a `RoutedLan` policy may name any. A host-only or gateway policy
    /// carries none, so a stale allowlist cannot outlive the mode that
    /// justified it.
    #[serde(default)]
    pub destination_prefixes: Vec<NetworkPrefix>,
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
    #[error("a host-only network policy must not require forwarding")]
    NetworkPolicyHostOnlyForwarding,
    #[error("the network policy mode is not valid for the rest of the policy")]
    NetworkPolicyModeInvalid,
    #[error("a host-only network policy must not masquerade")]
    NetworkPolicyHostOnlyMasquerade,
    #[error("a gateway network policy must not name destination prefixes")]
    NetworkPolicyGatewayDestinations,
    #[error("a routed-LAN network policy must not masquerade")]
    NetworkPolicyRoutedLanMasquerade,
    #[error("a routed-LAN network policy must name at least one destination prefix")]
    NetworkPolicyRoutedLanEmptyDestinations,
    #[error("a routed-LAN network policy may name at most {MAX_ROUTED_LAN_DESTINATIONS} destination prefixes")]
    NetworkPolicyRoutedLanTooManyDestinations,
    #[error("a routed-LAN destination prefix must be a valid unicast prefix")]
    NetworkPolicyRoutedLanInvalidDestination,
    #[error("a routed-LAN destination prefix must not be a default route")]
    NetworkPolicyRoutedLanDefaultRoute,
    #[error("a routed-LAN destination prefix overlaps a source prefix")]
    NetworkPolicyRoutedLanDestinationOverlap,
    #[error("a routed-LAN destination prefix appears more than once")]
    NetworkPolicyRoutedLanDuplicateDestination,
    #[error("a routed-LAN policy with {family} destinations requires {family} forwarding")]
    NetworkPolicyRoutedLanForwardingRequired { family: &'static str },
    #[error("a routed-LAN policy has {family} destinations but its tunnel pool carries no {family} source")]
    NetworkPolicyRoutedLanDestinationFamilyUnreachable { family: &'static str },
    #[error("a routed-LAN network policy source prefix is outside its managed tunnel prefix")]
    NetworkPolicyRoutedLanSourceNotManaged,
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
        validate_policy_mode(policy, interface)?;
    }
    Ok(())
}

/// Validates the mode-specific contract of one network policy.
///
/// The mode is what makes the rest of the policy meaningful, so the mode's own
/// rules are checked together: a host-only policy carries no forwarding
/// obligation, a gateway policy carries no destination allowlist, and a
/// routed-LAN policy carries exactly one bounded allowlist and never
/// masquerades.
fn validate_policy_mode(
    policy: &DesiredNetworkPolicy,
    interface: &DesiredInterface,
) -> Result<(), StateValidationError> {
    match policy.mode {
        NetworkPolicyMode::HostOnly => {
            if policy.ipv4_forwarding_required || policy.ipv6_forwarding_required {
                return Err(StateValidationError::NetworkPolicyHostOnlyForwarding);
            }
            if policy.masquerade {
                return Err(StateValidationError::NetworkPolicyHostOnlyMasquerade);
            }
            if !policy.destination_prefixes.is_empty() {
                return Err(StateValidationError::NetworkPolicyGatewayDestinations);
            }
        }
        NetworkPolicyMode::Gateway => {
            if !policy.destination_prefixes.is_empty() {
                return Err(StateValidationError::NetworkPolicyGatewayDestinations);
            }
        }
        NetworkPolicyMode::RoutedLan => {
            if policy.masquerade {
                return Err(StateValidationError::NetworkPolicyRoutedLanMasquerade);
            }
            if policy.destination_prefixes.is_empty() {
                return Err(StateValidationError::NetworkPolicyRoutedLanEmptyDestinations);
            }
            if policy.destination_prefixes.len() > MAX_ROUTED_LAN_DESTINATIONS {
                return Err(StateValidationError::NetworkPolicyRoutedLanTooManyDestinations);
            }
            let mut seen = std::collections::HashSet::new();
            let mut has_v4 = false;
            let mut has_v6 = false;
            for destination in &policy.destination_prefixes {
                let network = destination.network();
                let addr = network.addr();
                if network.prefix_len() == 0 {
                    // The default route is the one destination a routed LAN
                    // must never be built on.
                    return Err(StateValidationError::NetworkPolicyRoutedLanDefaultRoute);
                }
                if addr.is_unspecified()
                    || addr.is_multicast()
                    || addr.is_loopback()
                    || is_link_local(addr)
                {
                    return Err(StateValidationError::NetworkPolicyRoutedLanInvalidDestination);
                }
                if !seen.insert(network) {
                    return Err(StateValidationError::NetworkPolicyRoutedLanDuplicateDestination);
                }
                if policy
                    .source_prefixes
                    .iter()
                    .any(|source| prefixes_overlap(source.network(), network))
                {
                    return Err(StateValidationError::NetworkPolicyRoutedLanDestinationOverlap);
                }
                if addr.is_ipv4() {
                    has_v4 = true;
                } else {
                    has_v6 = true;
                }
            }
            if has_v4 && !policy.ipv4_forwarding_required {
                return Err(
                    StateValidationError::NetworkPolicyRoutedLanForwardingRequired {
                        family: "IPv4",
                    },
                );
            }
            if has_v6 && !policy.ipv6_forwarding_required {
                return Err(
                    StateValidationError::NetworkPolicyRoutedLanForwardingRequired {
                        family: "IPv6",
                    },
                );
            }
            // A routed LAN forwards traffic that claims to come from the tunnel
            // pool, so every source prefix must stay inside that pool.
            if policy
                .source_prefixes
                .iter()
                .any(|source| !interface.tunnel_prefixes.contains(source))
            {
                return Err(StateValidationError::NetworkPolicyRoutedLanSourceNotManaged);
            }
            // A routed LAN forwards within one address family: carrying traffic
            // between the families would need a translation, and a routed LAN
            // never translates. An approved destination whose family the pool
            // does not carry could never be delivered, so it is refused rather
            // than approved and then silently unreachable.
            for (destination, family) in [(has_v4, "IPv4"), (has_v6, "IPv6")] {
                if !destination {
                    continue;
                }
                let carried = policy
                    .source_prefixes
                    .iter()
                    .any(|source| source.network().addr().is_ipv4() == (family == "IPv4"));
                if !carried {
                    return Err(
                        StateValidationError::NetworkPolicyRoutedLanDestinationFamilyUnreachable {
                            family,
                        },
                    );
                }
            }
        }
    }
    Ok(())
}

/// Whether an address is link-local in either family.
fn is_link_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
    }
}

/// Whether two prefixes overlap, in either direction.
fn prefixes_overlap(left: IpNet, right: IpNet) -> bool {
    left.contains(&right.addr()) || right.contains(&left.addr())
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

    /// A state with one managed interface and one policy in the given mode.
    fn policy_state(mode: NetworkPolicyMode) -> DesiredState {
        DesiredState {
            interfaces: vec![interface()],
            client_routes: ClientRoutePolicy::default(),
            network_policy: Some(DesiredNetworkPolicy {
                wireguard_interface: "wg0".parse().unwrap(),
                mode,
                ipv4_forwarding_required: false,
                ipv6_forwarding_required: false,
                egress_interface: "eth0".parse().unwrap(),
                source_prefixes: vec![NetworkPrefix::new("10.8.0.0/24".parse().unwrap())],
                destination_prefixes: Vec::new(),
                masquerade: false,
            }),
        }
    }

    #[test]
    fn a_host_only_policy_carries_no_forwarding_and_no_destinations() {
        let mut desired = policy_state(NetworkPolicyMode::HostOnly);
        assert_eq!(validate_desired_state(&desired), Ok(()));
        desired
            .network_policy
            .as_mut()
            .unwrap()
            .ipv4_forwarding_required = true;
        assert_eq!(
            validate_desired_state(&desired),
            Err(StateValidationError::NetworkPolicyHostOnlyForwarding)
        );
        let mut desired = policy_state(NetworkPolicyMode::HostOnly);
        desired.network_policy.as_mut().unwrap().masquerade = true;
        assert_eq!(
            validate_desired_state(&desired),
            Err(StateValidationError::NetworkPolicyHostOnlyMasquerade)
        );
        let mut desired = policy_state(NetworkPolicyMode::HostOnly);
        desired
            .network_policy
            .as_mut()
            .unwrap()
            .destination_prefixes
            .push(NetworkPrefix::new("192.168.9.0/24".parse().unwrap()));
        assert_eq!(
            validate_desired_state(&desired),
            Err(StateValidationError::NetworkPolicyGatewayDestinations)
        );
    }

    #[test]
    fn a_routed_lan_policy_needs_destinations_forwarding_and_a_managed_source() {
        let mut desired = policy_state(NetworkPolicyMode::RoutedLan);
        assert_eq!(
            validate_desired_state(&desired),
            Err(StateValidationError::NetworkPolicyRoutedLanEmptyDestinations)
        );

        let policy = desired.network_policy.as_mut().unwrap();
        policy.ipv4_forwarding_required = true;
        policy
            .destination_prefixes
            .push(NetworkPrefix::new("192.168.9.0/24".parse().unwrap()));
        assert_eq!(validate_desired_state(&desired), Ok(()));

        // A destination that needs a family the policy does not forward for.
        let mut ipv6 = desired.clone();
        ipv6.network_policy.as_mut().unwrap().destination_prefixes = vec![
            NetworkPrefix::new("192.168.9.0/24".parse().unwrap()),
            NetworkPrefix::new("2001:db8:9::/64".parse().unwrap()),
        ];
        assert_eq!(
            validate_desired_state(&ipv6),
            Err(StateValidationError::NetworkPolicyRoutedLanForwardingRequired { family: "IPv6" })
        );

        // A destination that is a default route.
        let mut default = desired.clone();
        default
            .network_policy
            .as_mut()
            .unwrap()
            .destination_prefixes = vec![NetworkPrefix::new("0.0.0.0/0".parse().unwrap())];
        assert_eq!(
            validate_desired_state(&default),
            Err(StateValidationError::NetworkPolicyRoutedLanDefaultRoute)
        );

        // A destination that overlaps the tunnel pool.
        let mut overlap = desired.clone();
        overlap
            .network_policy
            .as_mut()
            .unwrap()
            .destination_prefixes = vec![NetworkPrefix::new("10.8.0.0/16".parse().unwrap())];
        assert_eq!(
            validate_desired_state(&overlap),
            Err(StateValidationError::NetworkPolicyRoutedLanDestinationOverlap)
        );

        // A source prefix that is outside the managed tunnel pool.
        let mut unmanaged = desired.clone();
        unmanaged
            .network_policy
            .as_mut()
            .unwrap()
            .source_prefixes
            .push(NetworkPrefix::new("10.9.0.0/24".parse().unwrap()));
        assert_eq!(
            validate_desired_state(&unmanaged),
            Err(StateValidationError::NetworkPolicyRoutedLanSourceNotManaged)
        );

        // A routed LAN never masquerades.
        let mut masquerading = desired.clone();
        masquerading.network_policy.as_mut().unwrap().masquerade = true;
        assert_eq!(
            validate_desired_state(&masquerading),
            Err(StateValidationError::NetworkPolicyRoutedLanMasquerade)
        );
    }

    /// A routed LAN forwards within one address family, so a destination
    /// whose family the tunnel pool does not carry could never be delivered.
    #[test]
    fn a_routed_lan_destination_must_be_carried_by_the_tunnel_pool() {
        let mut desired = policy_state(NetworkPolicyMode::RoutedLan);
        let policy = desired.network_policy.as_mut().unwrap();
        policy.ipv4_forwarding_required = true;
        policy
            .destination_prefixes
            .push(NetworkPrefix::new("192.168.9.0/24".parse().unwrap()));
        // The pool carries IPv4 only, so the IPv4 destination is fine.
        assert_eq!(validate_desired_state(&desired), Ok(()));

        // An IPv6 destination with an IPv4-only pool is refused: IPv6
        // forwarding requires an IPv6 source prefix.
        let mut ipv6 = desired.clone();
        let policy = ipv6.network_policy.as_mut().unwrap();
        policy.ipv6_forwarding_required = true;
        policy.destination_prefixes = vec![
            NetworkPrefix::new("192.168.9.0/24".parse().unwrap()),
            NetworkPrefix::new("2001:db8:9::/64".parse().unwrap()),
        ];
        assert_eq!(
            validate_desired_state(&ipv6),
            Err(StateValidationError::NetworkPolicyIpv6PrefixRequired)
        );

        // An IPv4 destination with an IPv6-only pool is refused too.
        let mut ipv4 = desired.clone();
        ipv4.interfaces[0]
            .tunnel_prefixes
            .push(NetworkPrefix::new("2001:db8::/64".parse().unwrap()));
        let policy = ipv4.network_policy.as_mut().unwrap();
        policy.source_prefixes = vec![NetworkPrefix::new("2001:db8::/64".parse().unwrap())];
        policy.ipv6_forwarding_required = true;
        assert_eq!(
            validate_desired_state(&ipv4),
            Err(
                StateValidationError::NetworkPolicyRoutedLanDestinationFamilyUnreachable {
                    family: "IPv4",
                }
            )
        );

        // A pool that carries both families reaches both destinations.
        let mut both = desired.clone();
        both.interfaces[0]
            .tunnel_prefixes
            .push(NetworkPrefix::new("2001:db8::/64".parse().unwrap()));
        let policy = both.network_policy.as_mut().unwrap();
        policy.source_prefixes = vec![
            NetworkPrefix::new("10.8.0.0/24".parse().unwrap()),
            NetworkPrefix::new("2001:db8::/64".parse().unwrap()),
        ];
        policy.ipv6_forwarding_required = true;
        policy.destination_prefixes = vec![
            NetworkPrefix::new("192.168.9.0/24".parse().unwrap()),
            NetworkPrefix::new("2001:db8:9::/64".parse().unwrap()),
        ];
        assert_eq!(validate_desired_state(&both), Ok(()));
    }

    #[test]
    fn the_routed_lan_allowlist_is_bounded() {
        let mut desired = policy_state(NetworkPolicyMode::RoutedLan);
        let policy = desired.network_policy.as_mut().unwrap();
        policy.ipv4_forwarding_required = true;
        for index in 0..=MAX_ROUTED_LAN_DESTINATIONS {
            policy.destination_prefixes.push(NetworkPrefix::new(
                format!("192.168.{index}.0/24").parse::<IpNet>().unwrap(),
            ));
        }
        assert_eq!(
            validate_desired_state(&desired),
            Err(StateValidationError::NetworkPolicyRoutedLanTooManyDestinations)
        );
    }
}
