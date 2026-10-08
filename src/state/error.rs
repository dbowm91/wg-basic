//! Errors produced by the durable state store.
//!
//! These are management-side errors. Nothing here reaches the privileged
//! protocol, and no variant carries secret material or SQL text.

use crate::domain::StateValidationError;
use thiserror::Error;

/// A failure while opening, migrating, or using the state store.
#[derive(Debug, Error)]
pub enum StateError {
    #[error("state database path is required")]
    MissingPath,

    #[error("state parent directory {path} is missing")]
    MissingParent { path: String },

    #[error("state parent directory {path} is not a real directory")]
    ParentNotDirectory { path: String },

    #[error("state parent directory {path} is owned by uid {owner}, expected {expected}")]
    ParentWrongOwner {
        path: String,
        owner: u32,
        expected: u32,
    },

    #[error("state parent directory {path} is group or world writable")]
    ParentTooPermissive { path: String },

    #[error("state database {path} is not a regular file")]
    DatabaseNotRegularFile { path: String },

    #[error("state database {path} is a symbolic link")]
    DatabaseIsSymlink { path: String },

    #[error("state database {path} is owned by uid {owner}, expected {expected}")]
    DatabaseWrongOwner {
        path: String,
        owner: u32,
        expected: u32,
    },

    #[error("state database {path} is group or world accessible")]
    DatabaseTooPermissive { path: String },

    #[error("state database {path} already exists; initialization refuses to overwrite it")]
    DatabaseAlreadyExists { path: String },

    #[error("database schema version {found} is newer than this binary supports ({supported})")]
    SchemaTooNew { found: i64, supported: i64 },

    #[error("database schema version {0} is invalid")]
    SchemaVersionInvalid(i64),

    #[error("database file could not be read")]
    DatabaseOpenFailed,

    #[error("database pragma {pragma} did not take effect")]
    PragmaNotApplied { pragma: &'static str },

    #[error("database migration {version} ({name}) failed")]
    MigrationFailed { version: i64, name: &'static str },

    #[error("database integrity check failed")]
    IntegrityCheckFailed,

    #[error("foreign key enforcement is not enabled")]
    ForeignKeysDisabled,

    #[error("stored data is not valid: {0}")]
    Corrupt(&'static str),

    #[error("desired state validation failed: {0}")]
    Validation(#[from] StateValidationError),

    #[error("desired generation {expected} is stale; current generation is {actual}")]
    StaleGeneration { expected: u64, actual: u64 },

    #[error("desired generation cannot advance past the storage ceiling")]
    GenerationExhausted,

    #[error("database operation failed")]
    Database,

    #[error("a stored constraint rejected the write")]
    ConstraintViolation,

    #[error("backup destination {path} already exists; refusing to overwrite it")]
    BackupDestinationExists { path: String },

    #[error("the restore target is still open in this process; stop the management service first")]
    TargetInUse,

    #[error("the restore candidate is still open in this process")]
    CandidateInUse,

    #[error("the database was busy")]
    Busy,

    #[error("the selected tunnel prefix cannot serve another client address")]
    AddressPoolUnavailable,
}

impl StateError {
    /// Maps a rusqlite failure without propagating SQL text or bound values.
    ///
    /// rusqlite's `Display` can include the failing statement, so operator-facing
    /// diagnostics deliberately collapse to a stable, secret-free message.
    pub(crate) fn database(error: rusqlite::Error) -> Self {
        match error {
            rusqlite::Error::SqliteFailure(failure, _) => match failure.code {
                rusqlite::ErrorCode::ConstraintViolation => Self::ConstraintViolation,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => {
                    Self::Busy
                }
                _ => Self::Database,
            },
            _ => Self::Database,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_errors_never_carry_sql_text_or_bound_values() {
        let failure = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
            Some("INSERT INTO peers (private_key) VALUES ('hunter2')".to_owned()),
        );
        let rendered = StateError::database(failure).to_string();
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("INSERT"), "{rendered}");
    }

    #[test]
    fn path_and_ownership_errors_name_only_the_path_and_uids() {
        let error = StateError::ParentWrongOwner {
            path: "/var/lib/wg-basic".into(),
            owner: 1000,
            expected: 0,
        };
        assert_eq!(
            error.to_string(),
            "state parent directory /var/lib/wg-basic is owned by uid 1000, expected 0"
        );
    }
}
