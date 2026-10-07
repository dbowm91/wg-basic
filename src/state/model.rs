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
