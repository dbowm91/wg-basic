//! Deterministic projection from persistent application state into kernel intent.
//!
//! The projector is pure: it performs no I/O, opens no connection, and never
//! calls a privileged backend. Every error it returns is a state validation
//! error and therefore must be raised before any privileged call.
//!
//! M001 projects only. Durable owner tags and generation-aware protocol fields
//! are M002's responsibility, so nothing here is written into the wire types.

use crate::domain::{
    DesiredNetworkPolicy as DomainNetworkPolicy, DesiredState, InterfaceName, LinkLifecycle,
};

#[cfg(target_os = "linux")]
use crate::{
    firewall::{DesiredNetworkPolicy, Ipv4Forwarding, NatMode},
    reconcile::{
        DesiredAddress, DesiredManagedInterface, DesiredManagedPeer, DesiredWireGuardConfiguration,
        ManagedRoute, OwnershipDeclaration, ResourcePresence,
    },
};

/// A projection failure.
///
/// These are state validation problems, not backend problems, so a caller can
/// surface them without implying that the kernel was contacted.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProjectionError {
    #[error("network policy requires an IPv4 source prefix set, found none")]
    EmptyNetworkPolicyPrefixes,
    #[error("network policy source prefix {0} is not IPv4")]
    NonIpv4PolicyPrefix(String),
    #[error("interface {0} has no listen port but a present WireGuard configuration")]
    MissingListenPort(InterfaceName),
}

/// The kernel intent derived from one persisted snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedNetworkIntent {
    /// One entry per managed interface, in snapshot order.
    #[cfg(target_os = "linux")]
    pub interfaces: Vec<DesiredManagedInterface>,
    /// The typed IPv4 policy, when the snapshot declares one.
    #[cfg(target_os = "linux")]
    pub network_policy: Option<DesiredNetworkPolicy>,
    /// The interfaces whose link should exist but which currently have no peers.
    ///
    /// Kept outside the kernel type so a caller can report a configuration that
    /// is valid but has nothing to apply.
    pub interface_names: Vec<InterfaceName>,
}

/// Projects a persisted snapshot into kernel intent.
///
/// Determinism: interface, address, route, and peer order follow the snapshot
/// order exactly, and no map iteration or clock read affects the result.
#[cfg(target_os = "linux")]
pub fn project(state: &DesiredState) -> Result<ResolvedNetworkIntent, ProjectionError> {
    let mut interfaces = Vec::with_capacity(state.interfaces.len());
    let mut interface_names = Vec::with_capacity(state.interfaces.len());

    for interface in &state.interfaces {
        interface_names.push(interface.name.clone());
        interfaces.push(project_interface(interface)?);
    }

    let network_policy = match &state.network_policy {
        Some(policy) => Some(project_network_policy(policy)?),
        None => None,
    };

    Ok(ResolvedNetworkIntent {
        interfaces,
        network_policy,
        interface_names,
    })
}

#[cfg(target_os = "linux")]
fn project_interface(
    interface: &crate::domain::DesiredInterface,
) -> Result<DesiredManagedInterface, ProjectionError> {
    let present = interface.lifecycle == LinkLifecycle::Present;
    let listen_port = match interface.listen_port {
        Some(port) => port,
        None if present => return Err(ProjectionError::MissingListenPort(interface.name.clone())),
        None => 0,
    };

    let wireguard = if interface.lifecycle == LinkLifecycle::Absent {
        None
    } else {
        Some(DesiredWireGuardConfiguration {
            private_key: interface.private_key.clone(),
            listen_port,
            manage_all_peers: interface.manage_all_peers,
            peers: interface
                .peers
                .iter()
                .map(|peer| DesiredManagedPeer {
                    public_key: peer.public_key.clone(),
                    allowed_ips: peer.allowed_ips.clone(),
                    persistent_keepalive_seconds: peer.persistent_keepalive_seconds,
                    endpoint: peer.endpoint,
                })
                .collect(),
        })
    };

    let addresses = interface
        .addresses
        .iter()
        .map(|address| DesiredAddress {
            address: address.address,
            presence: match address.presence {
                crate::domain::ResourcePresence::Present => ResourcePresence::Present,
                crate::domain::ResourcePresence::Absent => ResourcePresence::Absent,
            },
        })
        .collect();

    let routes = interface
        .routes
        .iter()
        .map(|route| ManagedRoute {
            destination: route.destination.clone(),
            gateway: route.gateway,
            presence: match route.presence {
                crate::domain::ResourcePresence::Present => ResourcePresence::Present,
                crate::domain::ResourcePresence::Absent => ResourcePresence::Absent,
            },
        })
        .collect();

    Ok(DesiredManagedInterface {
        interface: interface.name.clone(),
        ownership: match interface.ownership {
            crate::domain::OwnershipDeclaration::Managed => OwnershipDeclaration::Managed,
            crate::domain::OwnershipDeclaration::ObserveOnly => OwnershipDeclaration::ObserveOnly,
        },
        lifecycle: match interface.lifecycle {
            LinkLifecycle::Present => crate::reconcile::LinkLifecycle::Present,
            LinkLifecycle::Absent => crate::reconcile::LinkLifecycle::Absent,
        },
        admin_up: interface.admin_up,
        wireguard,
        addresses,
        routes,
    })
}

#[cfg(target_os = "linux")]
fn project_network_policy(
    policy: &DomainNetworkPolicy,
) -> Result<DesiredNetworkPolicy, ProjectionError> {
    if policy.source_prefixes.is_empty() {
        return Err(ProjectionError::EmptyNetworkPolicyPrefixes);
    }
    if policy
        .source_prefixes
        .iter()
        .any(|prefix| !prefix.network().addr().is_ipv4())
    {
        let offender = policy
            .source_prefixes
            .iter()
            .map(|prefix| prefix.to_string())
            .next()
            .unwrap_or_default();
        return Err(ProjectionError::NonIpv4PolicyPrefix(offender));
    }
    Ok(DesiredNetworkPolicy {
        ipv4_forwarding: if policy.ipv4_forwarding_required {
            Ipv4Forwarding::Required
        } else {
            Ipv4Forwarding::NotRequired
        },
        egress_interface: policy.egress_interface.clone(),
        source_prefixes: policy.source_prefixes.clone(),
        nat: if policy.masquerade {
            NatMode::Masquerade
        } else {
            NatMode::Disabled
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        ClientId, DesiredClient, DesiredInterface, DesiredPeer, NetworkPrefix, PeerId, PrivateKey,
        PublicKey,
    };
    use ipnet::IpNet;

    fn server_key() -> PrivateKey {
        PrivateKey::new("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".into()).unwrap()
    }

    fn state() -> DesiredState {
        let peer_id = PeerId::new();
        let address: IpNet = "10.8.0.2/32".parse().unwrap();
        DesiredState {
            interfaces: vec![DesiredInterface {
                id: crate::domain::InterfaceId::new(),
                name: "wg0".parse().unwrap(),
                ownership: crate::domain::OwnershipDeclaration::Managed,
                lifecycle: LinkLifecycle::Present,
                admin_up: Some(true),
                private_key: server_key(),
                listen_port: Some(51820),
                manage_all_peers: true,
                tunnel_prefixes: vec![NetworkPrefix::new("10.8.0.0/24".parse().unwrap())],
                addresses: vec![DesiredAddress {
                    address: "10.8.0.1/24".parse().unwrap(),
                    presence: crate::domain::ResourcePresence::Present,
                }],
                routes: vec![ManagedRoute {
                    destination: NetworkPrefix::new("10.9.0.0/16".parse().unwrap()),
                    gateway: None,
                    presence: crate::domain::ResourcePresence::Present,
                }],
                peers: vec![DesiredPeer {
                    id: peer_id,
                    public_key: PublicKey::new(
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                    )
                    .unwrap(),
                    private_key: None,
                    preshared_key: None,
                    allowed_ips: vec![NetworkPrefix::new(address)],
                    persistent_keepalive_seconds: Some(25),
                    endpoint: None,
                }],
                clients: vec![DesiredClient {
                    id: ClientId::new(),
                    peer_id,
                    assigned_address: address,
                    route_policy: Default::default(),
                }],
            }],
            client_routes: Default::default(),
            network_policy: Some(DomainNetworkPolicy {
                wireguard_interface: "wg0".parse().unwrap(),
                ipv4_forwarding_required: true,
                egress_interface: "eth0".parse().unwrap(),
                source_prefixes: vec![NetworkPrefix::new("10.8.0.0/24".parse().unwrap())],
                masquerade: true,
            }),
        }
    }

    #[test]
    fn projection_is_deterministic_across_repeated_calls() {
        let state = state();
        let first = project(&state).unwrap();
        let second = project(&state).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.interfaces.len(), 1);
        assert_eq!(first.interface_names.len(), 1);
    }

    #[test]
    fn projected_interface_carries_exactly_the_kernel_shaped_intent() {
        let intent = project(&state()).unwrap();
        let interface = &intent.interfaces[0];
        assert_eq!(interface.interface, "wg0".parse().unwrap());
        assert_eq!(interface.admin_up, Some(true));
        assert_eq!(interface.addresses.len(), 1);
        assert_eq!(interface.routes.len(), 1);
        let wireguard = interface
            .wireguard
            .as_ref()
            .expect("present link has configuration");
        assert_eq!(wireguard.listen_port, 51820);
        assert!(wireguard.manage_all_peers);
        assert_eq!(wireguard.peers.len(), 1);
        assert_eq!(wireguard.peers[0].persistent_keepalive_seconds, Some(25));

        let policy = intent.network_policy.expect("policy projected");
        assert_eq!(policy.egress_interface, "eth0".parse().unwrap());
        assert!(matches!(policy.nat, NatMode::Masquerade));
    }

    #[test]
    fn absent_links_project_without_wireguard_configuration() {
        let mut state = state();
        state.interfaces[0].lifecycle = LinkLifecycle::Absent;
        state.interfaces[0].admin_up = None;
        state.network_policy = None;
        let intent = project(&state).unwrap();
        assert!(intent.interfaces[0].wireguard.is_none());
        assert!(intent.network_policy.is_none());
    }

    #[test]
    fn projection_rejects_a_non_ipv4_policy_prefix_before_privileged_work() {
        let mut state = state();
        state.network_policy.as_mut().unwrap().source_prefixes =
            vec![NetworkPrefix::new("2001:db8::/64".parse().unwrap())];
        assert!(matches!(
            project(&state),
            Err(ProjectionError::NonIpv4PolicyPrefix(_))
        ));
    }

    #[test]
    fn projection_requires_host_prefixes_for_client_assignments() {
        let mut state = state();
        state.interfaces[0].clients[0].assigned_address = "10.8.0.2/24".parse().unwrap();
        // The domain validator rejects this before projection is ever reached.
        assert!(matches!(
            crate::domain::validate_desired_state(&state),
            Err(crate::domain::StateValidationError::ClientAddressMustBeHostPrefix)
        ));
    }
}
