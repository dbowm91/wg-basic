//! Desired/observed reconciliation data model shared by planning and application.
//!
//! Types here are the serialized and internal vocabulary of managed-interface
//! reconciliation. They contain no policy decisions and no backend behavior.

use crate::{
    domain::{InterfaceName, NetworkPrefix, PrivateKey, PublicKey},
    wireguard::{
        prefixes_overlap, validate_allowed_ips, ObservedWireGuardDevice, WireGuardValidationError,
    },
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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
