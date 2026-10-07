//! The safe, non-secret projection of management health.
//!
//! This is the only module that decides what an operator would see. It derives
//! that view from stored convergence evidence, and it deliberately has no field
//! for a receipt, an error string, or key material — so a future Phase 7 surface
//! binds to one subject instead of reconstructing the rule from log lines.

use crate::{
    domain::{DesiredGeneration, InstallationId},
    state::{AttemptDisposition, ConvergenceRecord},
};

/// Whether the last reconcile reached the desired state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConvergenceState {
    /// The kernel matches the current desired generation.
    Converged,
    /// A newer desired generation exists than the last converged one.
    Pending,
    /// The last attempt did not converge and a retry may help.
    Retryable,
    /// The last attempt failed in a way that needs an operator or state change.
    Failed,
}

/// A safe, non-secret projection of management health for a future Phase 7.
///
/// This is exactly what a future Phase 7 surface may render: identifiers,
/// generations, and categories. It deliberately has no field for a receipt, an
/// error string, or key material.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ManagementHealth {
    pub database_healthy: bool,
    pub netd_reachable: bool,
    pub installation_id: Option<InstallationId>,
    pub current_desired_generation: Option<DesiredGeneration>,
    pub last_converged_generation: Option<DesiredGeneration>,
    pub convergence: ConvergenceState,
    /// A category only, never an error string.
    pub last_failure_category: Option<AttemptDisposition>,
}

impl ManagementHealth {
    /// The projection is safe to expose: it carries no receipt internals and no
    /// secret-bearing values.
    pub fn is_healthy(&self) -> bool {
        self.database_healthy
            && self.netd_reachable
            && self.convergence == ConvergenceState::Converged
    }
}

/// Derives the projected convergence state from stored evidence.
///
/// Evidence is stronger than a category: a recorded `Converged` disposition only
/// counts when the store still holds that generation, because the kernel may
/// have drifted since. Anything less is reported as a category so the caller can
/// decide between retrying and escalating.
pub(super) fn convergence_state(
    record: &ConvergenceRecord,
    metadata: Option<&crate::state::InstallationMetadata>,
) -> (ConvergenceState, Option<AttemptDisposition>) {
    let category = record
        .last_outcome
        .as_deref()
        .and_then(AttemptDisposition::parse_category);
    let Some(metadata) = metadata else {
        return (ConvergenceState::Failed, category);
    };
    let current = metadata.desired_generation;
    match category {
        Some(AttemptDisposition::StateConflict)
        | Some(AttemptDisposition::Unauthorized)
        | Some(AttemptDisposition::Rejected) => (ConvergenceState::Failed, category),
        Some(AttemptDisposition::BackendUnavailable)
        | Some(AttemptDisposition::PartialFailure)
        | Some(AttemptDisposition::VerificationFailed)
        | Some(AttemptDisposition::FailedBeforeMutation) => (ConvergenceState::Retryable, category),
        _ => match record.last_converged_generation {
            Some(converged) if converged == current => (ConvergenceState::Converged, category),
            _ => (ConvergenceState::Pending, category),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{DesiredGeneration, InstallationId};
    use crate::state::ConvergenceRecord;

    #[test]
    fn health_reports_pending_when_convergence_lags_the_desired_generation() {
        let metadata = crate::state::InstallationMetadata {
            installation_id: InstallationId::new(),
            desired_generation: DesiredGeneration::new(4).unwrap(),
            created_at: 0,
            updated_at: 0,
        };
        let record = ConvergenceRecord {
            last_attempted_generation: Some(DesiredGeneration::new(4).unwrap()),
            last_converged_generation: Some(DesiredGeneration::new(3).unwrap()),
            last_attempt_timestamp: Some(0),
            last_outcome: Some("converged".into()),
        };
        assert_eq!(
            convergence_state(&record, Some(&metadata)).0,
            ConvergenceState::Pending
        );

        let record = ConvergenceRecord {
            last_converged_generation: Some(DesiredGeneration::new(4).unwrap()),
            ..record
        };
        assert_eq!(
            convergence_state(&record, Some(&metadata)).0,
            ConvergenceState::Converged
        );

        let record = ConvergenceRecord {
            last_outcome: Some("state_conflict".into()),
            ..record
        };
        assert_eq!(
            convergence_state(&record, Some(&metadata)).0,
            ConvergenceState::Failed
        );
    }

    #[test]
    fn health_projection_never_carries_a_receipt_or_secret() {
        let health = ManagementHealth {
            database_healthy: true,
            netd_reachable: true,
            installation_id: Some(InstallationId::new()),
            current_desired_generation: DesiredGeneration::new(2),
            last_converged_generation: DesiredGeneration::new(2),
            convergence: ConvergenceState::Converged,
            last_failure_category: None,
        };
        let rendered = format!("{health:?}");
        for forbidden in ["PrivateKey", "PresharedKey", "REDACTED"] {
            assert!(!rendered.contains(forbidden), "{forbidden} in {rendered}");
        }
    }

    #[test]
    fn non_retryable_categories_never_project_as_retryable() {
        let metadata = crate::state::InstallationMetadata {
            installation_id: InstallationId::new(),
            desired_generation: DesiredGeneration::new(2).unwrap(),
            created_at: 0,
            updated_at: 0,
        };
        for category in ["state_conflict", "unauthorized", "rejected"] {
            let record = ConvergenceRecord {
                last_attempted_generation: Some(DesiredGeneration::new(2).unwrap()),
                last_converged_generation: Some(DesiredGeneration::new(2).unwrap()),
                last_attempt_timestamp: Some(0),
                last_outcome: Some(category.into()),
            };
            assert_eq!(
                convergence_state(&record, Some(&metadata)).0,
                ConvergenceState::Failed,
                "{category} needs an operator, not a retry"
            );
        }
    }
}
