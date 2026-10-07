//! Stored-state value types.
//!
//! These are the typed results the store returns. Row structs read from SQLite
//! live in [`super::store`] and never derive `Debug` in a way that would render
//! secret material.

use crate::domain::DesiredState;
use crate::domain::{DesiredGeneration, InstallationId};
use std::fmt;

/// Installation metadata that is independent of the desired snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallationMetadata {
    pub installation_id: InstallationId,
    pub desired_generation: DesiredGeneration,
    pub created_at: i64,
    pub updated_at: i64,
}

/// A desired snapshot paired with the generation that committed it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedDesiredState {
    pub generation: DesiredGeneration,
    pub state: DesiredState,
}

/// The result of a committed desired-state mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedDesiredState {
    pub generation: DesiredGeneration,
    pub state: DesiredState,
}

/// The category recorded for one apply attempt.
///
/// Categories only. A reconcile error message may contain kernel detail, and
/// the database must never accumulate secret-bearing strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptDisposition {
    Converged,
    PartialFailure,
    VerificationFailed,
    FailedBeforeMutation,
    /// The attempt finished for a generation that is no longer current.
    Superseded,
    /// A durable state or ownership problem; not retryable without an
    /// operator or state change.
    StateConflict,
    /// netd was unreachable.
    BackendUnavailable,
    /// netd rejected the caller rather than the request.
    Unauthorized,
    /// netd answered but refused the request: unsupported backend, invalid
    /// input, or a kernel/backend rejection.
    Rejected,
}

impl AttemptDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Converged => "converged",
            Self::PartialFailure => "partial_failure",
            Self::VerificationFailed => "verification_failed",
            Self::FailedBeforeMutation => "failed_before_mutation",
            Self::Superseded => "superseded",
            Self::StateConflict => "state_conflict",
            Self::BackendUnavailable => "backend_unavailable",
            Self::Unauthorized => "unauthorized",
            Self::Rejected => "rejected",
        }
    }

    pub fn parse_category(value: &str) -> Option<Self> {
        match value {
            "converged" => Some(Self::Converged),
            "partial_failure" => Some(Self::PartialFailure),
            "verification_failed" => Some(Self::VerificationFailed),
            "failed_before_mutation" => Some(Self::FailedBeforeMutation),
            "superseded" => Some(Self::Superseded),
            "state_conflict" => Some(Self::StateConflict),
            "backend_unavailable" => Some(Self::BackendUnavailable),
            "unauthorized" => Some(Self::Unauthorized),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

/// Recorded reconciliation evidence.
///
/// M001 persists this shape but does not yet drive kernel reconciliation from it;
/// later milestones populate it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConvergenceRecord {
    pub last_attempted_generation: Option<DesiredGeneration>,
    pub last_converged_generation: Option<DesiredGeneration>,
    pub last_attempt_timestamp: Option<i64>,
    pub last_outcome: Option<String>,
}

impl fmt::Display for ConvergenceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "attempted={:?} converged={:?} outcome={:?}",
            self.last_attempted_generation, self.last_converged_generation, self.last_outcome
        )
    }
}
