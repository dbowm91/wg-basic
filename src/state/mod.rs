//! The authoritative unprivileged application-state store.
//!
//! SQLite desired state is authoritative; kernel state is derivative and is only
//! ever observed. This module owns storage, schema migration, the monotonic
//! desired generation, and deterministic projection into kernel intent.
//!
//! Ownership boundaries:
//!
//! - [`store`] is the only place that issues SQL;
//! - [`schema`] is the only place that opens a connection or runs migrations;
//! - [`projection`] is pure and performs no I/O;
//! - [`backup`] owns backup, restore, and candidate validation;
//! - [`error`] keeps operator diagnostics free of SQL text and secret values.
//!
//! The store is synchronous by design and holds one connection behind a single
//! lock. A future HTTP service must reach it through a bounded blocking-worker
//! adapter rather than by making this API async.
//!
//! # Secret-bearing files
//!
//! The database contains server private keys, client private keys, and
//! preshared keys. It and any backup of it are secret-bearing and must use
//! restrictive filesystem permissions. This is not a sanitized export.

mod backup;
mod error;
mod inuse;
mod model;
mod projection;
mod schema;
mod store;

pub use backup::{
    restore, retained_previous_path, validate_candidate, BackupDisposition, BackupReceipt,
    RestoreReceipt,
};
pub use error::StateError;
// The identifiers themselves live in `crate::domain` so the privileged side can
// derive an owner tag without depending on the state store. They are re-exported
// here because that is where callers of the store expect to find them.
pub use crate::domain::{
    DesiredGeneration, InstallationId, INITIAL_DESIRED_GENERATION, MAX_DESIRED_GENERATION,
};
pub use model::{
    AttemptDisposition, CommittedDesiredState, ConvergenceRecord, InstallationMetadata,
    PersistedDesiredState,
};
#[cfg(target_os = "linux")]
pub use projection::{project, ClientVisibility, ProjectionError, ResolvedNetworkIntent};
pub use schema::OpenIntent;
pub use store::product::{
    ClientProductRecord, CommittedProductState, InterfaceProductState, PersistedProductState,
    ProductAudit, ProductState,
};
pub use store::{PrincipalRecord, SessionRecord, StateStore, StoredSession};

/// Current Unix time in seconds, the same clock every stored timestamp uses.
///
/// Re-exported so the product service can stamp `created_at`/`updated_at`
/// without reaching into the private schema module.
pub(crate) fn now_seconds() -> i64 {
    schema::now_seconds()
}

/// The default production state database path.
///
/// Phase 10 owns installation; this is the documented direction, not a frozen
/// service layout.
pub const DEFAULT_STATE_PATH: &str = "/var/lib/wg-basic/state.db";
