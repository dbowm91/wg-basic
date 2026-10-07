//! Typed desired/observed reconciliation for one explicitly managed Linux interface.

mod linux;

pub use linux::LinuxNetworkBackend;

use crate::{
    domain::{InterfaceName, NetworkPrefix, PrivateKey, PublicKey},
    wireguard::{
        derive_public_key, prefixes_overlap, validate_allowed_ips, DesiredWireGuardPeer,
        FieldUpdate, ObservedWireGuardDevice, PeerMutation, WireGuardDevicePatch,
        WireGuardPeerPatch, WireGuardValidationError,
    },
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

const MAX_MANAGED_ADDRESSES: usize = 256;
const MAX_MANAGED_ROUTES: usize = 256;
const MAX_MANAGED_PEERS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipDeclaration {
    Managed,
    ObserveOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkLifecycle {
    Present,
    Absent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourcePresence {
    Present,
    Absent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredAddress {
    pub address: IpNet,
    pub presence: ResourcePresence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRoute {
    pub destination: NetworkPrefix,
    pub gateway: Option<IpAddr>,
    pub presence: ResourcePresence,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredWireGuardConfiguration {
    pub private_key: PrivateKey,
    pub listen_port: u16,
    pub peers: Vec<DesiredManagedPeer>,
    /// True authorizes removal of peers absent from this desired collection.
    pub manage_all_peers: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredManagedPeer {
    pub public_key: PublicKey,
    pub allowed_ips: Vec<NetworkPrefix>,
    pub persistent_keepalive_seconds: Option<u16>,
    pub endpoint: Option<std::net::SocketAddr>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredManagedInterface {
    pub interface: InterfaceName,
    pub ownership: OwnershipDeclaration,
    pub lifecycle: LinkLifecycle,
    /// Required for a present link and omitted for an absent link.
    pub admin_up: Option<bool>,
    pub wireguard: Option<DesiredWireGuardConfiguration>,
    /// Only these exact addresses/routes are managed. Unlisted resources survive.
    pub addresses: Vec<DesiredAddress>,
    pub routes: Vec<ManagedRoute>,
}

impl DesiredManagedInterface {
    pub fn validate(&self) -> Result<(), ReconcileError> {
        match self.lifecycle {
            LinkLifecycle::Present if self.admin_up.is_none() => {
                return Err(ReconcileError::InvalidDesiredState)
            }
            LinkLifecycle::Absent
                if self.admin_up.is_some()
                    || self.wireguard.is_some()
                    || self
                        .addresses
                        .iter()
                        .any(|address| address.presence != ResourcePresence::Absent)
                    || self
                        .routes
                        .iter()
                        .any(|route| route.presence != ResourcePresence::Absent) =>
            {
                return Err(ReconcileError::InvalidDesiredState)
            }
            _ => {}
        }
        if self.ownership == OwnershipDeclaration::ObserveOnly
            && (self.lifecycle == LinkLifecycle::Absent
                || self.wireguard.is_some()
                || self
                    .addresses
                    .iter()
                    .any(|address| address.presence == ResourcePresence::Present)
                || self
                    .routes
                    .iter()
                    .any(|route| route.presence == ResourcePresence::Present))
        {
            return Err(ReconcileError::OwnershipRequired);
        }
        if self.addresses.len() > MAX_MANAGED_ADDRESSES || self.routes.len() > MAX_MANAGED_ROUTES {
            return Err(ReconcileError::ResourceLimitExceeded);
        }
        let mut addresses = std::collections::HashSet::new();
        for address in &self.addresses {
            if !addresses.insert(address.address) {
                return Err(ReconcileError::DuplicateResource);
            }
        }
        let mut routes = std::collections::HashSet::new();
        for route in &self.routes {
            if route
                .gateway
                .is_some_and(|gateway| !route.destination.family_matches(gateway))
            {
                return Err(ReconcileError::InvalidDesiredState);
            }
            if !routes.insert((route.destination.clone(), route.gateway)) {
                return Err(ReconcileError::DuplicateResource);
            }
        }
        if let Some(wireguard) = &self.wireguard {
            if wireguard.listen_port == 0 || wireguard.peers.len() > MAX_MANAGED_PEERS {
                return Err(ReconcileError::InvalidDesiredState);
            }
            let mut public_keys = std::collections::HashSet::new();
            for peer in &wireguard.peers {
                if peer.persistent_keepalive_seconds == Some(0)
                    || peer.endpoint.is_some_and(|endpoint| endpoint.port() == 0)
                    || !public_keys.insert(peer.public_key.expose())
                {
                    return Err(ReconcileError::InvalidDesiredState);
                }
                validate_allowed_ips(&peer.allowed_ips).map_err(ReconcileError::WireGuard)?;
            }
            for (index, peer) in wireguard.peers.iter().enumerate() {
                for other in &wireguard.peers[index + 1..] {
                    if peer.allowed_ips.iter().any(|prefix| {
                        other
                            .allowed_ips
                            .iter()
                            .any(|other| prefixes_overlap(prefix, other))
                    }) {
                        return Err(ReconcileError::WireGuard(
                            WireGuardValidationError::ConflictingAllowedIps,
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedLinkKind {
    WireGuard,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRoute {
    pub destination: NetworkPrefix,
    pub gateway: Option<IpAddr>,
    pub output_interface: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedManagedInterface {
    pub interface: InterfaceName,
    pub ifindex: Option<u32>,
    pub link_kind: Option<ObservedLinkKind>,
    pub admin_up: Option<bool>,
    pub addresses: Vec<IpNet>,
    /// Main-table unicast routes that use this interface.
    pub routes: Vec<ObservedRoute>,
    /// Routes using this interface that are outside the supported ownership shape.
    pub unsupported_route_count: usize,
    pub wireguard: Option<ObservedWireGuardDevice>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    CreateWireGuardLink,
    ConfigureWireGuard,
    AddAddress,
    RemoveAddress,
    AddRoute,
    RemoveRoute,
    SetLinkUp,
    SetLinkDown,
    DeleteLink,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedAction {
    pub kind: MutationKind,
    pub target: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcilePlanSummary {
    pub interface: InterfaceName,
    pub actions: Vec<PlannedAction>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStatus {
    NoChange,
    Applied,
    AlreadyConverged,
    FailedBeforeMutation,
    PartialFailure,
    VerificationFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeFailureCategory {
    PermissionDenied,
    Unsupported,
    Conflict,
    KernelRejected,
    BackendFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyReceipt {
    pub interface: InterfaceName,
    pub status: ApplyStatus,
    pub planned_actions: Vec<PlannedAction>,
    pub completed_actions: usize,
    pub failed_action: Option<PlannedAction>,
    pub failure: Option<SafeFailureCategory>,
    pub observed_after: Option<ObservedManagedInterface>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReconcileError {
    #[error("desired network state is invalid")]
    InvalidDesiredState,
    #[error("the requested network resource is not declared as managed")]
    OwnershipRequired,
    #[error("desired network state exceeds a resource bound")]
    ResourceLimitExceeded,
    #[error("desired network state contains a duplicate resource")]
    DuplicateResource,
    #[error("interface exists with a non-WireGuard link kind")]
    WrongLinkKind,
    #[error("interface or route conflicts with existing host state")]
    Conflict,
    #[error("deleting the interface would remove an unlisted address or route")]
    UnlistedResourceOnDelete,
    #[error("network kernel observation or mutation failed")]
    BackendFailure,
    #[error("wireguard configuration is invalid")]
    WireGuard(#[from] WireGuardValidationError),
}

#[derive(Debug)]
enum Mutation {
    CreateWireGuardLink,
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
            Self::CreateWireGuardLink => (MutationKind::CreateWireGuardLink, "wireguard".into()),
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

fn route_target(route: &ObservedRoute) -> String {
    match route.gateway {
        Some(gateway) => format!("{} via {gateway}", route.destination),
        None => route.destination.to_string(),
    }
}

#[derive(Debug)]
struct ExecutionPlan {
    mutations: Vec<Mutation>,
    summary: ReconcilePlanSummary,
}

/// One installation-wide lock serializes observe/plan/apply/verify sequences.
/// The socket service also handles requests sequentially, so this lock makes
/// the invariant hold for in-process callers that use this controller directly.
pub struct ReconciliationService {
    backend: LinuxNetworkBackend,
    mutation_lock: Mutex<()>,
}

impl Default for ReconciliationService {
    fn default() -> Self {
        Self::new(LinuxNetworkBackend::default())
    }
}

impl ReconciliationService {
    pub fn new(backend: LinuxNetworkBackend) -> Self {
        Self {
            backend,
            mutation_lock: Mutex::new(()),
        }
    }

    pub fn plan(
        &self,
        desired: &DesiredManagedInterface,
    ) -> Result<ReconcilePlanSummary, ReconcileError> {
        desired.validate()?;
        let observed = self.backend.observe(&desired.interface)?;
        plan_managed_interface(desired, &observed)
    }

    pub fn apply(&self, desired: &DesiredManagedInterface) -> Result<ApplyReceipt, ReconcileError> {
        desired.validate()?;
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| ReconcileError::BackendFailure)?;
        apply_with_backend(desired, &self.backend)
    }
}

trait ReconcileBackend {
    fn observe(
        &self,
        interface: &InterfaceName,
    ) -> Result<ObservedManagedInterface, ReconcileError>;
    fn apply(&self, interface: &InterfaceName, mutation: Mutation) -> Result<(), ReconcileError>;
}

fn apply_with_backend(
    desired: &DesiredManagedInterface,
    backend: &impl ReconcileBackend,
) -> Result<ApplyReceipt, ReconcileError> {
    let before = backend.observe(&desired.interface)?;
    let plan = plan_execution(desired, &before)?;
    if plan.mutations.is_empty() {
        return Ok(ApplyReceipt {
            interface: desired.interface.clone(),
            status: ApplyStatus::NoChange,
            planned_actions: Vec::new(),
            completed_actions: 0,
            failed_action: None,
            failure: None,
            observed_after: Some(before),
        });
    }
    let planned_actions = plan.summary.actions;
    let mut completed_actions = 0;
    for (index, mutation) in plan.mutations.into_iter().enumerate() {
        if let Err(error) = backend.apply(&desired.interface, mutation) {
            let observed_after = backend.observe(&desired.interface).ok();
            let raced_to_desired = observed_after.as_ref().is_some_and(|observed| {
                plan_execution(desired, observed)
                    .is_ok_and(|remaining| remaining.mutations.is_empty())
            });
            return Ok(ApplyReceipt {
                interface: desired.interface.clone(),
                status: if raced_to_desired {
                    ApplyStatus::AlreadyConverged
                } else if completed_actions == 0 {
                    ApplyStatus::FailedBeforeMutation
                } else {
                    ApplyStatus::PartialFailure
                },
                failed_action: Some(planned_actions[index].clone()),
                failure: (!raced_to_desired).then_some(failure_category(&error)),
                planned_actions,
                completed_actions,
                observed_after,
            });
        }
        completed_actions += 1;
    }
    let observed_after = match backend.observe(&desired.interface) {
        Ok(observed) => observed,
        Err(error) => {
            return Ok(ApplyReceipt {
                interface: desired.interface.clone(),
                status: ApplyStatus::VerificationFailed,
                planned_actions,
                completed_actions,
                failed_action: None,
                failure: Some(failure_category(&error)),
                observed_after: None,
            })
        }
    };
    let converged = plan_execution(desired, &observed_after)
        .is_ok_and(|remaining| remaining.mutations.is_empty());
    Ok(ApplyReceipt {
        interface: desired.interface.clone(),
        status: if converged {
            ApplyStatus::Applied
        } else {
            ApplyStatus::VerificationFailed
        },
        planned_actions,
        completed_actions,
        failed_action: None,
        failure: (!converged).then_some(SafeFailureCategory::KernelRejected),
        observed_after: Some(observed_after),
    })
}

fn failure_category(error: &ReconcileError) -> SafeFailureCategory {
    match error {
        ReconcileError::OwnershipRequired
        | ReconcileError::Conflict
        | ReconcileError::WrongLinkKind => SafeFailureCategory::Conflict,
        ReconcileError::WireGuard(WireGuardValidationError::PermissionDenied) => {
            SafeFailureCategory::PermissionDenied
        }
        ReconcileError::WireGuard(WireGuardValidationError::UnsupportedBackend) => {
            SafeFailureCategory::Unsupported
        }
        ReconcileError::WireGuard(WireGuardValidationError::KernelRejected) => {
            SafeFailureCategory::KernelRejected
        }
        _ => SafeFailureCategory::BackendFailure,
    }
}

pub fn plan_managed_interface(
    desired: &DesiredManagedInterface,
    observed: &ObservedManagedInterface,
) -> Result<ReconcilePlanSummary, ReconcileError> {
    Ok(plan_execution(desired, observed)?.summary)
}

fn plan_execution(
    desired: &DesiredManagedInterface,
    observed: &ObservedManagedInterface,
) -> Result<ExecutionPlan, ReconcileError> {
    desired.validate()?;
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
                mutations.push(Mutation::CreateWireGuardLink);
            } else if observed.link_kind != Some(ObservedLinkKind::WireGuard) {
                return Err(ReconcileError::WrongLinkKind);
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
            ResourcePresence::Present if same_ip => return Err(ReconcileError::Conflict),
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
                return Err(ReconcileError::Conflict)
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
    use super::*;
    use std::sync::Mutex as StdMutex;

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
            wireguard: None,
        }
    }

    fn desired() -> DesiredManagedInterface {
        DesiredManagedInterface {
            interface: name(),
            ownership: OwnershipDeclaration::Managed,
            lifecycle: LinkLifecycle::Present,
            admin_up: Some(true),
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
    fn shipped_backend_uses_no_ip_subprocess() {
        let implementation = include_str!("reconcile/linux.rs");
        assert!(!implementation.contains("std::process::Command"));
        assert!(!implementation.contains("Command::new(\"ip\")"));
    }

    #[derive(Debug)]
    struct FakeBackend {
        state: StdMutex<ObservedManagedInterface>,
        fail_once_at: usize,
        applied: StdMutex<usize>,
    }

    impl ReconcileBackend for FakeBackend {
        fn observe(&self, _: &InterfaceName) -> Result<ObservedManagedInterface, ReconcileError> {
            self.state
                .lock()
                .map(|state| state.clone())
                .map_err(|_| ReconcileError::BackendFailure)
        }

        fn apply(&self, _: &InterfaceName, mutation: Mutation) -> Result<(), ReconcileError> {
            let mut applied = self
                .applied
                .lock()
                .map_err(|_| ReconcileError::BackendFailure)?;
            *applied += 1;
            if *applied == self.fail_once_at {
                return Err(ReconcileError::BackendFailure);
            }
            let mut state = self
                .state
                .lock()
                .map_err(|_| ReconcileError::BackendFailure)?;
            match mutation {
                Mutation::AddAddress(address) => state.addresses.push(address),
                Mutation::SetLinkUp(up) => state.admin_up = Some(up),
                _ => return Err(ReconcileError::BackendFailure),
            }
            Ok(())
        }
    }

    #[test]
    fn partial_apply_is_observed_and_retry_converges() {
        let wanted = DesiredManagedInterface {
            routes: Vec::new(),
            ..desired()
        };
        let backend = FakeBackend {
            state: StdMutex::new(observed()),
            fail_once_at: 2,
            applied: StdMutex::new(0),
        };
        let first = apply_with_backend(&wanted, &backend).unwrap();
        assert_eq!(first.status, ApplyStatus::PartialFailure);
        assert_eq!(first.completed_actions, 1);
        assert_eq!(first.observed_after.as_ref().unwrap().addresses.len(), 1);

        let retry = apply_with_backend(&wanted, &backend).unwrap();
        assert_eq!(retry.status, ApplyStatus::Applied);
        assert_eq!(retry.completed_actions, 1);
        let no_op = apply_with_backend(&wanted, &backend).unwrap();
        assert_eq!(no_op.status, ApplyStatus::NoChange);
    }
}
