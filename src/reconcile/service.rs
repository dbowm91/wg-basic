//! Serialized application of a planned reconciliation and receipt reporting.
//!
//! One installation-wide lock serializes observe/plan/apply/verify sequences.

use super::linux::LinuxNetworkBackend;
use super::model::{
    ApplyReceipt, ApplyStatus, DesiredManagedInterface, ObservedManagedInterface, ReconcileError,
    ReconcilePlanSummary, SafeFailureCategory,
};
use super::planner::{plan_execution, plan_managed_interface, Mutation};
use crate::{domain::InterfaceName, wireguard::WireGuardValidationError};
use std::sync::Mutex;

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

pub(crate) trait ReconcileBackend {
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

#[cfg(test)]
mod tests {
    use super::super::model::{
        DesiredAddress, DesiredManagedInterface, LinkLifecycle, OwnershipDeclaration,
        ResourcePresence,
    };
    use super::*;
    use crate::domain::InterfaceName;
    use crate::reconcile::model::ObservedLinkKind;
    use std::sync::Mutex as StdMutex;

    fn name() -> InterfaceName {
        "wg-test".parse().unwrap()
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
            routes: Vec::new(),
        }
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
