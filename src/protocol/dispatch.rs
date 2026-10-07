//! Operation dispatch and domain-error projection.
//!
//! Routing is closed: the request operation selects exactly one typed backend
//! call. Domain errors are projected onto the fixed protocol error set without
//! leaking backend detail.

use super::socket::SocketServer;
use super::wire::{
    ProtocolError, RequestEnvelope, RequestOperation, ResponseBody, ResponseEnvelope,
    PROTOCOL_VERSION,
};
use crate::firewall::FirewallError;
use crate::protocol::capability::NetworkCapabilitySnapshot;
use crate::reconcile::ReconcileError;
use crate::wireguard::WireGuardValidationError;

impl SocketServer {
    pub(crate) fn dispatch(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if request.protocol_version != PROTOCOL_VERSION {
            return ResponseEnvelope::failure(
                request.request_id,
                ProtocolError::UnsupportedVersion,
            );
        }
        let result = match request.operation {
            RequestOperation::Ping => Ok(ResponseBody::Pong {
                service: "wg-basic-netd".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            }),
            RequestOperation::InspectCapabilities => Ok(ResponseBody::Capabilities(
                NetworkCapabilitySnapshot::observe(&self.runtime_directory),
            )),
            RequestOperation::ObserveWireGuardDevice { interface } => self
                .wireguard
                .observe_device(&interface)
                .map(ResponseBody::WireGuardDevice)
                .map_err(map_wireguard_error),
            RequestOperation::ApplyWireGuardDevice { interface, patch } => self
                .wireguard
                .apply_patch(&interface, patch)
                .map(ResponseBody::WireGuardApplied)
                .map_err(map_wireguard_error),
            RequestOperation::PlanManagedInterface { desired } => self
                .reconciliation
                .plan(&desired)
                .map(ResponseBody::ManagedInterfacePlan)
                .map_err(map_reconcile_error),
            RequestOperation::ApplyManagedInterface { desired } => self
                .reconciliation
                .apply(&desired)
                .map(ResponseBody::ManagedInterfaceApplied)
                .map_err(map_reconcile_error),
            RequestOperation::PlanNetworkPolicy {
                wireguard_interface,
                policy,
            } => self
                .firewall
                .plan(&wireguard_interface, policy.as_ref())
                .map(ResponseBody::NetworkPolicyPlan)
                .map_err(map_firewall_error),
            RequestOperation::ApplyNetworkPolicy {
                wireguard_interface,
                policy,
            } => self
                .firewall
                .apply(&wireguard_interface, policy.as_ref())
                .map(ResponseBody::NetworkPolicyApplied)
                .map_err(map_firewall_error),
        };
        ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: request.request_id,
            result,
        }
    }
}

fn map_firewall_error(error: FirewallError) -> ProtocolError {
    match error {
        FirewallError::InvalidPolicy | FirewallError::ResourceLimitExceeded => {
            ProtocolError::InvalidInput
        }
        FirewallError::TableOwnershipConflict => ProtocolError::Conflict,
        FirewallError::PermissionDenied => ProtocolError::PermissionDenied,
        FirewallError::Unsupported => ProtocolError::UnsupportedBackend,
        FirewallError::BackendFailure => ProtocolError::BackendFailure,
    }
}

fn map_reconcile_error(error: ReconcileError) -> ProtocolError {
    match error {
        ReconcileError::InvalidDesiredState
        | ReconcileError::ResourceLimitExceeded
        | ReconcileError::DuplicateResource => ProtocolError::InvalidInput,
        ReconcileError::OwnershipRequired
        | ReconcileError::WrongLinkKind
        | ReconcileError::Conflict
        | ReconcileError::UnlistedResourceOnDelete => ProtocolError::Conflict,
        ReconcileError::BackendFailure => ProtocolError::BackendFailure,
        ReconcileError::WireGuard(error) => map_wireguard_error(error),
    }
}

fn map_wireguard_error(error: WireGuardValidationError) -> ProtocolError {
    match error {
        WireGuardValidationError::PeerNotFound | WireGuardValidationError::InterfaceUnavailable => {
            ProtocolError::NotFound
        }
        WireGuardValidationError::PeerAlreadyExists
        | WireGuardValidationError::ConflictingAllowedIps => ProtocolError::Conflict,
        WireGuardValidationError::PermissionDenied => ProtocolError::PermissionDenied,
        WireGuardValidationError::UnsupportedBackend => ProtocolError::UnsupportedBackend,
        WireGuardValidationError::KernelRejected => ProtocolError::KernelRejected,
        WireGuardValidationError::InvalidKey | WireGuardValidationError::InvalidBackendInput => {
            ProtocolError::InvalidInput
        }
        WireGuardValidationError::BackendFailure => ProtocolError::BackendFailure,
        _ => ProtocolError::InvalidInput,
    }
}
