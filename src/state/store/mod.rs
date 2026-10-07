//! The typed desired-state store.
//!
//! One store owns one `rusqlite` connection behind a single synchronization
//! boundary. `Connection` is never part of the public API, there are no async
//! traits, and no caller can issue SQL.
//!
//! This module owns only the façade: the store handle, its ownership lifecycle,
//! and how a database is opened. Everything a caller can ask the store to do
//! lives behind a named method, and the SQL behind those methods is private to
//! the module that owns the subject:
//!
//! - [`desired`] owns the desired snapshot — reading it, and committing a new
//!   one as an atomic generation advance.
//! - [`convergence`] owns reconciliation evidence: attempt start, attempt
//!   result, and the guard that marks a generation converged.
//! - [`sql`] owns row decoding shared by the two, so SQLite column values are
//!   turned into domain types in exactly one place.
//!
//! The layering is one-directional (`sql` → `desired` / `convergence` → this
//! module), so a future change to the stored representation has a single owner
//! and cannot introduce a cycle.
//!
//! Phase 7 must cross into this blocking store through a bounded
//! blocking-worker adapter rather than by making this API async.

mod convergence;
mod desired;
mod sql;

use super::{
    error::StateError,
    schema::{self, OpenIntent},
};
use crate::domain::{InstallationId, INITIAL_DESIRED_GENERATION};
use rusqlite::Connection;
use std::{
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

/// The authoritative unprivileged application-state store.
pub struct StateStore {
    path: PathBuf,
    connection: Mutex<Connection>,
}

impl std::fmt::Debug for StateStore {
    /// Deliberately opaque: the store holds secret-bearing rows.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Drop for StateStore {
    /// Releases this process's claim on the database path.
    ///
    /// Restoring over a path this process still holds open would corrupt the
    /// live store, so the claim is released exactly when the connection closes.
    fn drop(&mut self) {
        super::inuse::unregister(&self.path);
    }
}

impl StateStore {
    /// Creates a new store and runs every migration.
    ///
    /// Generates the installation identity. Refuses to touch an existing file.
    pub fn initialize(path: impl AsRef<Path>) -> Result<Self, StateError> {
        Self::with_expected_owner(path.as_ref(), OpenIntent::Initialize, current_uid())
    }

    /// Opens an existing store and applies any pending migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StateError> {
        Self::with_expected_owner(path.as_ref(), OpenIntent::Reopen, current_uid())
    }

    /// Opens a store with an explicit expected owner.
    ///
    /// Exposed so tests can assert the ownership checks independently of the
    /// process uid.
    pub fn open_with_expected_owner(
        path: impl AsRef<Path>,
        expected_uid: u32,
    ) -> Result<Self, StateError> {
        Self::with_expected_owner(path.as_ref(), OpenIntent::Reopen, expected_uid)
    }

    fn with_expected_owner(
        path: &Path,
        intent: OpenIntent,
        expected_uid: u32,
    ) -> Result<Self, StateError> {
        let connection = schema::open_connection(path, intent, expected_uid)?;
        if intent == OpenIntent::Initialize {
            schema::seed_installation(
                &connection,
                &InstallationId::new(),
                INITIAL_DESIRED_GENERATION,
            )?;
        }
        // Checked after seeding, so "exactly one row" holds for a brand-new
        // store and a missing installation row fails closed on reopen.
        schema::enforce_singleton(&connection)?;
        super::inuse::register(path);
        Ok(Self {
            path: path.to_path_buf(),
            connection: Mutex::new(connection),
        })
    }

    /// The schema version this database currently declares.
    pub fn schema_version(&self) -> Result<i64, StateError> {
        let connection = self.lock()?;
        connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(StateError::database)
    }

    /// The path this store was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The single synchronization boundary every query crosses.
    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Connection>, StateError> {
        self.connection
            .lock()
            .map_err(|_| StateError::Corrupt("state store mutex poisoned"))
    }
}

/// The uid the store refuses to share a database with.
fn current_uid() -> u32 {
    // The management role runs unprivileged; the store refuses a database or
    // parent directory it does not own rather than widening access to it.
    std::os::unix::fs::MetadataExt::uid(
        &std::fs::metadata("/proc/self").expect("effective uid is readable from /proc/self"),
    )
}
