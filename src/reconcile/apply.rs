//! Portable serialized application of a planned reconciliation.
//!
//! The Linux and Darwin services execute the *same* portable plan through the
//! *same* observe/apply/verify sequence. Only the backend differs, so this
//! module owns the sequence and both platform services own their backend.
//!
//! The sequence is deliberately fail-closed at every step:
//!
//! 1. observe the link;
//! 2. plan the mutations;
//! 3. apply them in order, stopping at the first failure;
//! 4. re-observe and re-plan to decide whether the desired state was reached.
//!
//! A failure after at least one mutation is reported as a partial failure with
//! the observation that was actually seen, never as a success.

use super::model::{
    ApplyReceipt, ApplyStatus, DesiredManagedInterface, ObservedManagedInterface, ReconcileError,
    ReconcilePlanSummary, SafeFailureCategory,
};
use super::planner::{plan_execution, Mutation};
use crate::domain::{InterfaceName, OwnerTag};
use crate::wireguard::WireGuardValidationError;

/// The platform backend the portable service drives.
///
/// The backend observes the host and applies one planned mutation at a time.
/// It never decides *what* to change: that is the portable planner's job.
pub(crate) trait ReconcileBackend {
    /// Observes one managed interface.
    ///
    /// `owner_tag` is the ownership proof the backend must establish. A
    /// backend that cannot prove ownership must report it (by leaving the
    /// observation unproven) rather than adopting the link.
    fn observe(
        &self,
        interface: &InterfaceName,
        owner_tag: &OwnerTag,
    ) -> Result<ObservedManagedInterface, ReconcileError>;

    /// Applies one planned mutation.
    fn apply(&self, interface: &InterfaceName, mutation: Mutation) -> Result<(), ReconcileError>;
}

/// Observes, plans, applies, and verifies one desired managed interface.
pub(crate) fn apply_with_backend(
    desired: &DesiredManagedInterface,
    backend: &impl ReconcileBackend,
) -> Result<ApplyReceipt, ReconcileError> {
    let before = backend.observe(&desired.interface, &desired.owner_tag)?;
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
            let observed_after = backend.observe(&desired.interface, &desired.owner_tag).ok();
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
    let observed_after = match backend.observe(&desired.interface, &desired.owner_tag) {
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

/// Maps a backend failure onto the portable, secret-safe failure vocabulary.
pub(crate) fn failure_category(error: &ReconcileError) -> SafeFailureCategory {
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

/// The portable plan summary for one desired managed interface.
pub(crate) fn plan_with_backend(
    desired: &DesiredManagedInterface,
    backend: &impl ReconcileBackend,
) -> Result<ReconcilePlanSummary, ReconcileError> {
    let observed = backend.observe(&desired.interface, &desired.owner_tag)?;
    super::planner::plan_managed_interface(desired, &observed)
}
