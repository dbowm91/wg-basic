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
use crate::aggregate::{ApplyRejection, GenerationRejection, IntentError, PlanRejection};
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
                installation_id,
                wireguard_interface,
                policy,
            } => self
                .firewall
                .plan(installation_id, &wireguard_interface, policy.as_ref())
                .map(ResponseBody::NetworkPolicyPlan)
                .map_err(map_firewall_error),
            RequestOperation::ApplyNetworkPolicy {
                installation_id,
                wireguard_interface,
                policy,
            } => self
                .firewall
                .apply(installation_id, &wireguard_interface, policy.as_ref())
                .map(ResponseBody::NetworkPolicyApplied)
                .map_err(map_firewall_error),
            RequestOperation::PlanInstallationNetworkIntent { intent } => self
                .aggregate
                .plan(&intent)
                .map(|plan| {
                    ResponseBody::InstallationNetworkPlanned(
                        crate::protocol::wire::InstallationNetworkPlanBody {
                            installation_id: plan.installation_id,
                            generation: plan.generation,
                            enabling: plan.enabling,
                            interface_plan: plan.interface_plan,
                            firewall_plan: plan.firewall_plan,
                        },
                    )
                })
                .map_err(|rejection| match rejection {
                    PlanRejection::Interface(inner) => map_reconcile_error(inner),
                    PlanRejection::Firewall(inner) => map_firewall_error(inner),
                    PlanRejection::InvalidIntent(inner) => map_intent_error(inner),
                    PlanRejection::GenerationRejected(inner) => map_generation_rejection(inner),
                }),
            RequestOperation::ApplyInstallationNetworkIntent { intent } => self
                .aggregate
                .apply(&intent)
                .map(|receipt| {
                    ResponseBody::InstallationNetworkApplied(
                        crate::protocol::wire::InstallationNetworkApplyBody {
                            installation_id: receipt.installation_id,
                            generation: receipt.generation,
                            status: receipt.status,
                            interface: receipt.interface,
                            firewall: receipt.firewall,
                            failed_layer: receipt.failed_layer,
                            observed_after: receipt.observed_after,
                        },
                    )
                })
                .map_err(map_aggregate_error),
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
        FirewallError::TableOwnershipConflict | FirewallError::LegacyTableOwnership => {
            ProtocolError::Conflict
        }
        FirewallError::PermissionDenied => ProtocolError::PermissionDenied,
        FirewallError::Unsupported => ProtocolError::UnsupportedBackend,
        FirewallError::BackendFailure => ProtocolError::BackendFailure,
    }
}

fn map_intent_error(error: IntentError) -> ProtocolError {
    match error {
        IntentError::GenerationOutOfRange => ProtocolError::InvalidInput,
        IntentError::InvalidInterface(inner) => map_reconcile_error(inner),
        _ => ProtocolError::InvalidInput,
    }
}

fn map_generation_rejection(error: GenerationRejection) -> ProtocolError {
    // A stale generation and a foreign installation identity are both stable
    // conflict categories, so no new protocol error variant is needed.
    match error {
        GenerationRejection::InstallationMismatch | GenerationRejection::Stale { .. } => {
            ProtocolError::Conflict
        }
    }
}

fn map_aggregate_error(error: ApplyRejection) -> ProtocolError {
    match error {
        ApplyRejection::InvalidIntent(intent) => match intent {
            IntentError::GenerationOutOfRange => ProtocolError::InvalidInput,
            IntentError::InvalidInterface(inner) => map_reconcile_error(inner),
            _ => ProtocolError::InvalidInput,
        },
        ApplyRejection::GenerationRejected(rejection) => match rejection {
            GenerationRejection::InstallationMismatch => ProtocolError::Conflict,
            GenerationRejection::Stale { .. } => ProtocolError::Conflict,
        },
        ApplyRejection::Interface(inner) => map_reconcile_error(inner),
        ApplyRejection::InterfaceLayerIncomplete { .. } => ProtocolError::InternalFailure,
        ApplyRejection::Firewall(inner) => map_firewall_error(inner),
        ApplyRejection::FirewallDuringApply { interface, error } => {
            // An earlier layer already changed state, so this is a partial
            // failure rather than a clean rejection.
            if interface.completed_actions > 0 {
                ProtocolError::BackendFailure
            } else {
                map_firewall_error(error)
            }
        }
        ApplyRejection::FirewallLayerIncomplete { .. } => ProtocolError::InternalFailure,
    }
}

fn map_reconcile_error(error: ReconcileError) -> ProtocolError {
    match error {
        ReconcileError::InvalidDesiredState
        | ReconcileError::ResourceLimitExceeded
        | ReconcileError::DuplicateResource => ProtocolError::InvalidInput,
        // An absent, foreign, or duplicated durable owner tag is a conflict:
        // wg-basic cannot prove it owns the link, so it refuses authoritatively.
        ReconcileError::OwnershipRequired
        | ReconcileError::WrongLinkKind
        | ReconcileError::Conflict
        | ReconcileError::OwnerTagMissing
        | ReconcileError::OwnerTagForeign
        | ReconcileError::OwnerTagDuplicated
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
