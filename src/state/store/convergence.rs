//! Reconciliation evidence: what was attempted, and what actually converged.
//!
//! Evidence is deliberately weaker than desired state. Recording that an attempt
//! began never implies the kernel reached the desired state, and the disposition
//! stored for an attempt is a category rather than a message, so a reconcile
//! failure cannot leak key material into the database.
//!
//! `record_converged_if_current` is the one guard that couples evidence back to
//! intent: a late completion for generation N must never mark a newer desired
//! state N+1 as converged.

use super::{
    sql::{read_generation, read_optional_generation},
    StateStore,
};
use crate::{
    domain::DesiredGeneration,
    state::{
        error::StateError,
        model::{AttemptDisposition, ConvergenceRecord},
        schema,
    },
};
use rusqlite::TransactionBehavior;

impl StateStore {
    /// Reads the recorded reconciliation evidence.
    pub fn convergence(&self) -> Result<ConvergenceRecord, StateError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT last_attempted_generation, last_converged_generation,
                        last_attempt_timestamp, last_outcome
                 FROM convergence_state WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .map_err(StateError::database)
            .and_then(|(attempted, converged, timestamp, outcome)| {
                Ok(ConvergenceRecord {
                    last_attempted_generation: read_optional_generation(attempted, "attempted")?,
                    last_converged_generation: read_optional_generation(converged, "converged")?,
                    last_attempt_timestamp: timestamp,
                    last_outcome: outcome,
                })
            })
    }

    /// Records that an apply attempt for `generation` has started.
    ///
    /// This is only evidence that an attempt began. It never implies the kernel
    /// reached the desired state.
    pub fn record_attempt_start(&self, generation: DesiredGeneration) -> Result<(), StateError> {
        let connection = self.lock()?;
        connection
            .execute(
                "UPDATE convergence_state
                 SET last_attempted_generation = ?1, last_attempt_timestamp = ?2
                 WHERE singleton = 1",
                rusqlite::params![generation.to_storage(), schema::now_seconds()],
            )
            .map_err(StateError::database)?;
        Ok(())
    }

    /// Records the outcome of an attempt for `generation`.
    ///
    /// The disposition is a category, never a secret-bearing message, so a
    /// reconcile failure cannot leak key material into the database.
    pub fn record_attempt_result(
        &self,
        generation: DesiredGeneration,
        disposition: &AttemptDisposition,
    ) -> Result<(), StateError> {
        let connection = self.lock()?;
        connection
            .execute(
                "UPDATE convergence_state
                 SET last_attempted_generation = ?1, last_outcome = ?2
                 WHERE singleton = 1",
                rusqlite::params![generation.to_storage(), disposition.as_str()],
            )
            .map_err(StateError::database)?;
        Ok(())
    }

    /// Marks `generation` converged only if it is still the current desired
    /// generation.
    ///
    /// This is the guard that stops a late receipt for generation N from
    /// marking a newer desired state N+1 as converged. Returns whether the
    /// write happened.
    pub fn record_converged_if_current(
        &self,
        generation: DesiredGeneration,
    ) -> Result<bool, StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;

        let current = read_generation(&transaction)?;
        if current != generation {
            // Stale completion: recorded as attempt evidence only. The current
            // desired generation is untouched and will be reconciled on its own.
            transaction
                .execute(
                    "UPDATE convergence_state SET last_outcome = ?1 WHERE singleton = 1",
                    rusqlite::params![AttemptDisposition::Superseded.as_str()],
                )
                .map_err(StateError::database)?;
            transaction.commit().map_err(StateError::database)?;
            return Ok(false);
        }

        transaction
            .execute(
                "UPDATE convergence_state
                 SET last_converged_generation = ?1, last_attempted_generation = ?1,
                     last_outcome = ?2
                 WHERE singleton = 1",
                rusqlite::params![
                    generation.to_storage(),
                    AttemptDisposition::Converged.as_str()
                ],
            )
            .map_err(StateError::database)?;
        transaction.commit().map_err(StateError::database)?;
        Ok(true)
    }
}
