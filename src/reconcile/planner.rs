//! Pure desired-versus-observed planning for one explicitly managed interface.
//!
//! Planning is deterministic and side-effect free: it never touches a backend and
//! never observes the kernel. The resulting mutation order is the contract the
//! application service executes.

use super::model::{
    DesiredManagedInterface, LinkLifecycle, MutationKind, ObservedLinkKind,
    ObservedManagedInterface, ObservedRoute, OwnershipDeclaration, PlannedAction, ReconcileError,
    ReconcilePlanSummary, ResourcePresence,
};
use crate::{
    domain::{AliasMatch, NetworkPrefix, OwnerTag, PrivateKey},
    wireguard::{
        derive_public_key, prefixes_overlap, DesiredWireGuardPeer, FieldUpdate, PeerMutation,
        WireGuardDevicePatch, WireGuardPeerPatch, WireGuardValidationError,
    },
};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug)]
pub(crate) enum Mutation {
    CreateWireGuardLink { owner_tag: OwnerTag },
    ConfigureWireGuard(WireGuardDevicePatch),
    AddAddress(IpNet),
    RemoveAddress(IpNet),
    AddRoute(ObservedRoute),
    RemoveRoute(ObservedRoute),
    SetLinkUp(bool),
    DeleteLink,
}

impl Mutation {
    fn summary(&self) -> PlannedAction {
        let (kind, target) = match self {
            Self::CreateWireGuardLink { .. } => {
                (MutationKind::CreateWireGuardLink, "wireguard".into())
            }
            Self::ConfigureWireGuard(_) => (MutationKind::ConfigureWireGuard, "wireguard".into()),
            Self::AddAddress(address) => (MutationKind::AddAddress, address.to_string()),
            Self::RemoveAddress(address) => (MutationKind::RemoveAddress, address.to_string()),
            Self::AddRoute(route) => (MutationKind::AddRoute, route_target(route)),
            Self::RemoveRoute(route) => (MutationKind::RemoveRoute, route_target(route)),
            Self::SetLinkUp(true) => (MutationKind::SetLinkUp, "link".into()),
            Self::SetLinkUp(false) => (MutationKind::SetLinkDown, "link".into()),
            Self::DeleteLink => (MutationKind::DeleteLink, "wireguard".into()),
        };
        PlannedAction { kind, target }
    }
}

/// Proves durable ownership of an existing link.
///
/// An existing link is eligible for authoritative mutation or destruction only
/// when its alias is exactly the expected owner tag. A missing tag, a tag from
/// another installation or interface, an unrelated alias, or a duplicate tag on
/// another link all fail closed: interface name and public key are not proof.
fn require_owned(
    observed: &ObservedManagedInterface,
    owner_tag: &OwnerTag,
) -> Result<(), ReconcileError> {
    if observed.duplicate_owner_tag {
        return Err(ReconcileError::OwnerTagDuplicated);
    }
    match owner_tag.classify(observed.interface_alias.as_deref()) {
        AliasMatch::Owned => Ok(()),
        AliasMatch::Absent => Err(ReconcileError::OwnerTagMissing),
        AliasMatch::ForeignInterface | AliasMatch::ForeignInstallation => {
            Err(ReconcileError::OwnerTagForeign)
        }
        AliasMatch::Unrelated => Err(ReconcileError::OwnerTagMissing),
    }
}

fn route_target(route: &ObservedRoute) -> String {
    match route.gateway {
        Some(gateway) => format!("{} via {gateway}", route.destination),
        None => route.destination.to_string(),
    }
}

#[derive(Debug)]
pub(crate) struct ExecutionPlan {
    pub(crate) mutations: Vec<Mutation>,
    pub(crate) summary: ReconcilePlanSummary,
}

pub fn plan_managed_interface(
    desired: &DesiredManagedInterface,
    observed: &ObservedManagedInterface,
) -> Result<ReconcilePlanSummary, ReconcileError> {
    Ok(plan_execution(desired, observed)?.summary)
}

pub(crate) fn plan_execution(
    desired: &DesiredManagedInterface,
    observed: &ObservedManagedInterface,
) -> Result<ExecutionPlan, ReconcileError> {
    desired.validate()?;
    let owner_tag = &desired.owner_tag;
    if desired.interface != observed.interface {
        return Err(ReconcileError::InvalidDesiredState);
    }
    let mut mutations = Vec::new();
    match desired.lifecycle {
        LinkLifecycle::Absent => {
            let Some(_) = observed.ifindex else {
                return Ok(execution_plan(desired, mutations));
            };
            if desired.ownership != OwnershipDeclaration::Managed {
                return Err(ReconcileError::OwnershipRequired);
            }
            if observed.link_kind != Some(ObservedLinkKind::WireGuard) {
                return Err(ReconcileError::WrongLinkKind);
            }
            require_owned(observed, owner_tag)?;
            let listed_addresses = desired
                .addresses
                .iter()
                .map(|entry| entry.address)
                .collect::<std::collections::HashSet<_>>();
            if observed
                .addresses
                .iter()
                .any(|address| !listed_addresses.contains(address))
            {
                return Err(ReconcileError::UnlistedResourceOnDelete);
            }
            if observed.unsupported_route_count > 0 {
                return Err(ReconcileError::UnlistedResourceOnDelete);
            }
            let listed_routes = desired
                .routes
                .iter()
                .map(|route| (&route.destination, route.gateway))
                .collect::<std::collections::HashSet<_>>();
            if observed.routes.iter().any(|route| {
                route.output_interface == observed.ifindex
                    && !listed_routes.contains(&(&route.destination, route.gateway))
            }) {
                return Err(ReconcileError::UnlistedResourceOnDelete);
            }
            let mut routes = desired.routes.iter().collect::<Vec<_>>();
            routes.sort_by_key(|route| (route.destination.to_string(), route.gateway));
            for route in routes {
                if observed.routes.iter().any(|current| {
                    current.output_interface == observed.ifindex
                        && current.destination == route.destination
                        && current.gateway == route.gateway
                }) {
                    mutations.push(Mutation::RemoveRoute(ObservedRoute {
                        destination: route.destination.clone(),
                        gateway: route.gateway,
                        output_interface: observed.ifindex,
                    }));
                }
            }
            let mut addresses = desired.addresses.iter().collect::<Vec<_>>();
            addresses.sort_by_key(|address| address.address.to_string());
            for address in addresses {
                if observed.addresses.contains(&address.address) {
                    mutations.push(Mutation::RemoveAddress(address.address));
                }
            }
            if observed.admin_up == Some(true) {
                mutations.push(Mutation::SetLinkUp(false));
            }
            mutations.push(Mutation::DeleteLink);
        }
        LinkLifecycle::Present => {
            let created = observed.ifindex.is_none();
            if created {
                if desired.ownership != OwnershipDeclaration::Managed {
                    return Err(ReconcileError::OwnershipRequired);
                }
                mutations.push(Mutation::CreateWireGuardLink {
                    owner_tag: owner_tag.clone(),
                });
            } else {
                if observed.link_kind != Some(ObservedLinkKind::WireGuard) {
                    return Err(ReconcileError::WrongLinkKind);
                }
                // Ownership is proven, so external drift in WireGuard config,
                // addresses, routes, or admin state is repaired back to desired.
                require_owned(observed, owner_tag)?;
            }
            plan_wireguard(desired, observed, created, &mut mutations)?;
            plan_addresses(desired, observed, &mut mutations)?;
            plan_routes(desired, observed, &mut mutations)?;
            if mutations
                .iter()
                .any(|mutation| matches!(mutation, Mutation::AddRoute(_)))
                && observed.admin_up != Some(true)
            {
                let route_index = mutations
                    .iter()
                    .position(|mutation| matches!(mutation, Mutation::AddRoute(_)))
                    .unwrap_or(mutations.len());
                mutations.insert(route_index, Mutation::SetLinkUp(true));
            }
            if let Some(admin_up) = desired.admin_up {
                let already_scheduled = mutations.iter().any(
                    |mutation| matches!(mutation, Mutation::SetLinkUp(state) if *state == admin_up),
                );
                if (admin_up || !created)
                    && observed.admin_up != Some(admin_up)
                    && !already_scheduled
                {
                    mutations.push(Mutation::SetLinkUp(admin_up));
                }
            }
        }
    }
    if desired.ownership == OwnershipDeclaration::ObserveOnly && !mutations.is_empty() {
        return Err(ReconcileError::OwnershipRequired);
    }
    Ok(execution_plan(desired, mutations))
}

fn plan_addresses(
    desired: &DesiredManagedInterface,
    observed: &ObservedManagedInterface,
    mutations: &mut Vec<Mutation>,
) -> Result<(), ReconcileError> {
    let mut addresses = desired.addresses.iter().collect::<Vec<_>>();
    addresses.sort_by_key(|address| address.address.to_string());
    for address in addresses {
        let exact = observed.addresses.contains(&address.address);
        let same_ip = observed
            .addresses
            .iter()
            .any(|current| current.addr() == address.address.addr() && current != &address.address);
        match address.presence {
            ResourcePresence::Present if exact => {}
            ResourcePresence::Present if same_ip => {
                return Err(ReconcileError::Conflict);
            }
            ResourcePresence::Present => mutations.push(Mutation::AddAddress(address.address)),
            ResourcePresence::Absent if exact => {
                mutations.push(Mutation::RemoveAddress(address.address))
            }
            ResourcePresence::Absent => {}
        }
    }
    Ok(())
}

fn plan_routes(
    desired: &DesiredManagedInterface,
    observed: &ObservedManagedInterface,
    mutations: &mut Vec<Mutation>,
) -> Result<(), ReconcileError> {
    let mut routes = desired.routes.iter().collect::<Vec<_>>();
    routes.sort_by_key(|route| (route.destination.to_string(), route.gateway));
    for route in routes {
        let same_destination = observed
            .routes
            .iter()
            .filter(|current| current.destination == route.destination)
            .collect::<Vec<_>>();
        let managed_destination = same_destination
            .iter()
            .filter(|current| current.output_interface == observed.ifindex)
            .collect::<Vec<_>>();
        let exact = managed_destination
            .iter()
            .any(|current| current.gateway == route.gateway);
        match route.presence {
            ResourcePresence::Present if exact => {}
            ResourcePresence::Present if !same_destination.is_empty() => {
                return Err(ReconcileError::Conflict);
            }
            ResourcePresence::Present => mutations.push(Mutation::AddRoute(ObservedRoute {
                destination: route.destination.clone(),
                gateway: route.gateway,
                output_interface: observed.ifindex,
            })),
            ResourcePresence::Absent if exact => {
                mutations.push(Mutation::RemoveRoute(ObservedRoute {
                    destination: route.destination.clone(),
                    gateway: route.gateway,
                    output_interface: observed.ifindex,
                }))
            }
            ResourcePresence::Absent => {}
        }
    }
    Ok(())
}

fn plan_wireguard(
    desired: &DesiredManagedInterface,
    observed: &ObservedManagedInterface,
    created: bool,
    mutations: &mut Vec<Mutation>,
) -> Result<(), ReconcileError> {
    let Some(desired_wg) = &desired.wireguard else {
        return Ok(());
    };
    let desired_public = derive_public_key(&desired_wg.private_key)
        .map_err(|_| ReconcileError::InvalidDesiredState)?;
    let current = if created {
        None
    } else {
        observed.wireguard.as_ref()
    };
    if !created && current.is_none() {
        return Err(ReconcileError::WrongLinkKind);
    }
    let mut private_key = FieldUpdate::Keep;
    let mut listen_port = FieldUpdate::Keep;
    if current.and_then(|device| device.public_key.as_ref()) != Some(&desired_public) {
        private_key = FieldUpdate::Set(
            PrivateKey::new(desired_wg.private_key.expose_secret().to_owned())
                .map_err(|_| ReconcileError::InvalidDesiredState)?,
        );
    }
    if current.and_then(|device| device.listen_port) != Some(desired_wg.listen_port) {
        listen_port = FieldUpdate::Set(desired_wg.listen_port);
    }
    if !matches!(private_key, FieldUpdate::Keep) || !matches!(listen_port, FieldUpdate::Keep) {
        mutations.push(Mutation::ConfigureWireGuard(WireGuardDevicePatch {
            private_key,
            listen_port,
            peer: None,
        }));
    }

    let current_peers = current
        .map(|device| device.peers.as_slice())
        .unwrap_or_default();
    let desired_keys = desired_wg
        .peers
        .iter()
        .map(|peer| peer.public_key.expose())
        .collect::<std::collections::HashSet<_>>();
    if !desired_wg.manage_all_peers {
        for current_peer in current_peers
            .iter()
            .filter(|peer| !desired_keys.contains(peer.public_key.expose()))
        {
            if desired_wg.peers.iter().any(|desired_peer| {
                desired_peer.allowed_ips.iter().any(|prefix| {
                    current_peer
                        .allowed_ips
                        .iter()
                        .any(|current| prefixes_overlap(prefix, current))
                })
            }) {
                return Err(ReconcileError::WireGuard(
                    WireGuardValidationError::ConflictingAllowedIps,
                ));
            }
        }
    }
    let mut peers = desired_wg.peers.iter().collect::<Vec<_>>();
    peers.sort_by(|left, right| left.public_key.expose().cmp(right.public_key.expose()));
    for peer in peers {
        let current_peer = current_peers
            .iter()
            .find(|current| current.public_key == peer.public_key);
        match current_peer {
            None => mutations.push(Mutation::ConfigureWireGuard(WireGuardDevicePatch {
                private_key: FieldUpdate::Keep,
                listen_port: FieldUpdate::Keep,
                peer: Some(PeerMutation::Add(DesiredWireGuardPeer {
                    public_key: peer.public_key.clone(),
                    preshared_key: None,
                    allowed_ips: peer.allowed_ips.clone(),
                    persistent_keepalive_seconds: peer.persistent_keepalive_seconds,
                    endpoint: peer.endpoint,
                })),
            })),
            Some(current) => {
                let allowed_ips = if same_prefix_set(&current.allowed_ips, &peer.allowed_ips) {
                    FieldUpdate::Keep
                } else {
                    FieldUpdate::Set(peer.allowed_ips.clone())
                };
                let keepalive =
                    if current.persistent_keepalive_seconds == peer.persistent_keepalive_seconds {
                        FieldUpdate::Keep
                    } else if peer.persistent_keepalive_seconds.is_none() {
                        FieldUpdate::Clear
                    } else {
                        FieldUpdate::Set(peer.persistent_keepalive_seconds.unwrap_or_default())
                    };
                let endpoint = if current.endpoint == peer.endpoint {
                    FieldUpdate::Keep
                } else if peer.endpoint.is_none() {
                    FieldUpdate::Clear
                } else {
                    FieldUpdate::Set(peer.endpoint.unwrap_or_else(cleared_endpoint))
                };
                if !matches!(allowed_ips, FieldUpdate::Keep)
                    || !matches!(keepalive, FieldUpdate::Keep)
                    || !matches!(endpoint, FieldUpdate::Keep)
                {
                    mutations.push(Mutation::ConfigureWireGuard(WireGuardDevicePatch {
                        private_key: FieldUpdate::Keep,
                        listen_port: FieldUpdate::Keep,
                        peer: Some(PeerMutation::Update(WireGuardPeerPatch {
                            public_key: peer.public_key.clone(),
                            preshared_key: FieldUpdate::Keep,
                            allowed_ips,
                            persistent_keepalive_seconds: keepalive,
                            endpoint,
                        })),
                    }));
                }
            }
        }
    }
    if desired_wg.manage_all_peers {
        let mut unknown = current_peers
            .iter()
            .filter(|peer| !desired_keys.contains(peer.public_key.expose()))
            .map(|peer| peer.public_key.clone())
            .collect::<Vec<_>>();
        unknown.sort_by(|left, right| left.expose().cmp(right.expose()));
        for public_key in unknown {
            mutations.push(Mutation::ConfigureWireGuard(WireGuardDevicePatch {
                private_key: FieldUpdate::Keep,
                listen_port: FieldUpdate::Keep,
                peer: Some(PeerMutation::Remove { public_key }),
            }));
        }
    }
    Ok(())
}

fn cleared_endpoint() -> std::net::SocketAddr {
    std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

fn same_prefix_set(first: &[NetworkPrefix], second: &[NetworkPrefix]) -> bool {
    first.len() == second.len()
        && first
            .iter()
            .all(|prefix| second.iter().any(|other| other == prefix))
}

fn execution_plan(desired: &DesiredManagedInterface, mutations: Vec<Mutation>) -> ExecutionPlan {
    let actions = mutations.iter().map(Mutation::summary).collect();
    ExecutionPlan {
        mutations,
        summary: ReconcilePlanSummary {
            interface: desired.interface.clone(),
            actions,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::{
        DesiredAddress, DesiredManagedPeer, DesiredWireGuardConfiguration, ManagedRoute,
    };
    use super::*;
    use crate::domain::{InstallationId, InterfaceId, InterfaceName, PublicKey};
    use crate::wireguard::ObservedWireGuardDevice;

    /// A single stable tag shared by every fixture in this module, because
    /// ownership is proven by an exact match between the desired tag and the
    /// alias observed on the link.
    fn owner_tag() -> OwnerTag {
        OwnerTag::new(
            "00000000-0000-4000-8000-0000000000a1"
                .parse::<InstallationId>()
                .unwrap(),
            "00000000-0000-4000-8000-0000000000b2"
                .parse::<InterfaceId>()
                .unwrap(),
        )
    }

    fn name() -> InterfaceName {
        "wg-test".parse().unwrap()
    }

    fn observed() -> ObservedManagedInterface {
        ObservedManagedInterface {
            interface: name(),
            ifindex: Some(7),
            link_kind: Some(ObservedLinkKind::WireGuard),
            admin_up: Some(false),
            addresses: Vec::new(),
            routes: Vec::new(),
            unsupported_route_count: 0,
            interface_alias: Some(owner_tag().as_str()),
            duplicate_owner_tag: false,
            wireguard: None,
        }
    }

    fn desired() -> DesiredManagedInterface {
        DesiredManagedInterface {
            interface: name(),
            ownership: OwnershipDeclaration::Managed,
            lifecycle: LinkLifecycle::Present,
            admin_up: Some(true),
            owner_tag: owner_tag(),
            wireguard: None,
            addresses: vec![DesiredAddress {
                address: "10.0.0.1/24".parse().unwrap(),
                presence: ResourcePresence::Present,
            }],
            routes: vec![ManagedRoute {
                destination: "10.1.0.0/16".parse().unwrap(),
                gateway: None,
                presence: ResourcePresence::Present,
            }],
        }
    }

    #[test]
    fn plans_in_deterministic_dependency_order() {
        let mut missing = observed();
        missing.ifindex = None;
        missing.link_kind = None;
        missing.admin_up = None;
        let plan = plan_execution(&desired(), &missing).unwrap();
        assert_eq!(
            plan.summary
                .actions
                .iter()
                .map(|action| action.kind)
                .collect::<Vec<_>>(),
            vec![
                MutationKind::CreateWireGuardLink,
                MutationKind::AddAddress,
                MutationKind::SetLinkUp,
                MutationKind::AddRoute,
            ]
        );
    }

    #[test]
    fn wrong_kind_and_unlisted_delete_resources_fail_closed() {
        let mut wrong_kind = observed();
        wrong_kind.link_kind = Some(ObservedLinkKind::Other);
        assert_eq!(
            plan_managed_interface(&desired(), &wrong_kind),
            Err(ReconcileError::WrongLinkKind)
        );

        let mut deleting = desired();
        deleting.lifecycle = LinkLifecycle::Absent;
        deleting.admin_up = None;
        deleting.addresses.clear();
        deleting.routes.clear();
        let with_address = ObservedManagedInterface {
            addresses: vec!["10.0.0.1/24".parse().unwrap()],
            ..observed()
        };
        assert_eq!(
            plan_managed_interface(&deleting, &with_address),
            Err(ReconcileError::UnlistedResourceOnDelete)
        );
        let with_unsupported_route = ObservedManagedInterface {
            unsupported_route_count: 1,
            interface_alias: Some(owner_tag().as_str()),
            duplicate_owner_tag: false,
            ..observed()
        };
        assert_eq!(
            plan_managed_interface(&deleting, &with_unsupported_route),
            Err(ReconcileError::UnlistedResourceOnDelete)
        );
    }

    #[test]
    fn route_conflict_on_another_interface_is_not_replaced() {
        let state = ObservedManagedInterface {
            routes: vec![ObservedRoute {
                destination: "10.1.0.0/16".parse().unwrap(),
                gateway: None,
                output_interface: Some(99),
            }],
            ..observed()
        };
        assert_eq!(
            plan_managed_interface(&desired(), &state),
            Err(ReconcileError::Conflict)
        );
    }

    #[test]
    fn telemetry_only_wireguard_changes_do_not_create_mutations() {
        let keypair = crate::wireguard::generate_keypair().unwrap();
        let public_key = derive_public_key(&keypair.private_key).unwrap();
        let peer_key =
            PublicKey::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()).unwrap();
        let allowed_ips: Vec<NetworkPrefix> = vec!["10.9.0.2/32".parse().unwrap()];
        let mut wanted = DesiredManagedInterface {
            addresses: Vec::new(),
            routes: Vec::new(),
            ..desired()
        };
        wanted.wireguard = Some(DesiredWireGuardConfiguration {
            private_key: keypair.private_key,
            listen_port: 51820,
            peers: vec![DesiredManagedPeer {
                public_key: peer_key.clone(),
                allowed_ips: allowed_ips.clone(),
                persistent_keepalive_seconds: Some(25),
                endpoint: Some("198.51.100.8:51820".parse().unwrap()),
            }],
            manage_all_peers: true,
        });
        let mut state = observed();
        state.admin_up = Some(true);
        state.wireguard = Some(ObservedWireGuardDevice {
            interface: name(),
            public_key: Some(public_key),
            listen_port: Some(51820),
            peers: vec![crate::wireguard::ObservedWireGuardPeer {
                public_key: peer_key,
                allowed_ips,
                persistent_keepalive_seconds: Some(25),
                endpoint: Some("198.51.100.8:51820".parse().unwrap()),
                latest_handshake: Some(std::time::Duration::from_secs(123)),
                rx_bytes: Some(4096),
                tx_bytes: Some(8192),
            }],
        });
        assert!(plan_managed_interface(&wanted, &state)
            .unwrap()
            .actions
            .is_empty());
    }

    fn owned(desired: &DesiredManagedInterface) -> ObservedManagedInterface {
        let mut observed = observed();
        observed.ifindex = Some(7);
        observed.interface_alias = Some(desired.owner_tag.as_str());
        observed
    }

    fn with_alias(
        desired: &DesiredManagedInterface,
        alias: Option<&str>,
    ) -> ObservedManagedInterface {
        let mut observed = owned(desired);
        observed.interface_alias = alias.map(str::to_owned);
        observed
    }

    #[test]
    fn a_missing_link_is_created_and_tagged() {
        let desired = desired();
        let observed = ObservedManagedInterface {
            interface: name(),
            ifindex: None,
            link_kind: None,
            admin_up: None,
            addresses: Vec::new(),
            routes: Vec::new(),
            unsupported_route_count: 0,
            interface_alias: None,
            duplicate_owner_tag: false,
            wireguard: None,
        };
        let plan = plan_execution(&desired, &observed).unwrap();
        assert!(
            plan.mutations
                .iter()
                .any(|mutation| matches!(mutation, Mutation::CreateWireGuardLink { owner_tag } if *owner_tag == desired.owner_tag)),
            "a new link must be created carrying its durable owner tag"
        );
    }

    #[test]
    fn a_matching_owner_tag_permits_full_owned_reconciliation() {
        let desired = desired();
        let observed = owned(&desired);
        // External drift in admin state is repaired because ownership is proven.
        let mut drifted = observed.clone();
        drifted.admin_up = Some(false);
        let plan = plan_execution(&desired, &drifted).expect("a matching tag proves ownership");
        assert!(!plan.mutations.is_empty());
    }

    #[test]
    fn an_absent_alias_is_a_conflict_for_an_existing_link() {
        let desired = desired();
        let observed = with_alias(&desired, None);
        assert!(matches!(
            plan_execution(&desired, &observed),
            Err(ReconcileError::OwnerTagMissing)
        ));
    }

    #[test]
    fn an_unrelated_alias_is_never_treated_as_ownership() {
        let desired = desired();
        for alias in ["", "my laptop uplink", "wg0"] {
            let observed = with_alias(&desired, Some(alias));
            assert!(
                matches!(
                    plan_execution(&desired, &observed),
                    Err(ReconcileError::OwnerTagMissing)
                ),
                "alias {alias:?} must not prove ownership"
            );
        }
    }

    #[test]
    fn a_foreign_installation_or_interface_tag_is_a_conflict() {
        let desired = desired();

        let other_installation =
            OwnerTag::new(InstallationId::new(), desired.owner_tag.interface_id());
        let observed = with_alias(&desired, Some(&other_installation.as_str()));
        assert!(matches!(
            plan_execution(&desired, &observed),
            Err(ReconcileError::OwnerTagForeign)
        ));

        let other_interface =
            OwnerTag::new(desired.owner_tag.installation_id(), InterfaceId::new());
        let observed = with_alias(&desired, Some(&other_interface.as_str()));
        assert!(matches!(
            plan_execution(&desired, &observed),
            Err(ReconcileError::OwnerTagForeign)
        ));
    }

    #[test]
    fn a_duplicate_owner_tag_elsewhere_is_a_conflict_and_survives() {
        let desired = desired();
        let mut observed = owned(&desired);
        observed.duplicate_owner_tag = true;
        assert!(matches!(
            plan_execution(&desired, &observed),
            Err(ReconcileError::OwnerTagDuplicated)
        ));
        assert!(
            observed.interface_alias.is_some(),
            "the conflicting link is observed, never modified"
        );
    }

    #[test]
    fn an_unowned_link_is_refused_before_destruction_too() {
        let mut desired = desired();
        desired.lifecycle = LinkLifecycle::Absent;
        desired.admin_up = None;
        desired.wireguard = None;
        desired.addresses.clear();
        desired.routes.clear();
        let observed = with_alias(&desired, Some("someone elses uplink"));
        // Deletion must be as ownership-gated as mutation.
        let error = plan_execution(&desired, &observed).expect_err("unowned deletion must fail");
        assert!(
            matches!(error, ReconcileError::OwnerTagMissing),
            "unexpected error for an unowned delete: {error:?}"
        );
    }

    #[test]
    fn a_wrong_kind_link_is_still_refused_before_ownership_is_considered() {
        let desired = desired();
        let mut observed = owned(&desired);
        observed.link_kind = Some(ObservedLinkKind::Other);
        assert!(matches!(
            plan_execution(&desired, &observed),
            Err(ReconcileError::WrongLinkKind)
        ));
    }
}
