//! Schema definition and the migration runner.
//!
//! Migrations are ordered, immutable steps. A shipped migration is never
//! rewritten: a schema change is a new step, so a database's version history
//! stays replayable and the runner never has to guess what a database used to
//! look like.
//!
//! The pre-migration recovery snapshot lives here rather than in the opener
//! because it exists for exactly one reason: to protect a schema-changing
//! migration. The opener calls it and otherwise knows nothing about it.

use super::validation::DATABASE_MODE;
use crate::state::error::StateError;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};

#[cfg(test)]
use super::validation::configure;
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// One ordered, immutable schema step.
#[derive(Clone)]
pub(crate) struct Migration {
    pub(crate) version: i64,
    pub(crate) name: &'static str,
    pub(crate) sql: &'static str,
}

/// Every migration in exact application order.
pub(crate) const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial",
        sql: include_str!("../migrations/001_initial.sql"),
    },
    Migration {
        version: 2,
        name: "auth_sessions",
        sql: include_str!("../migrations/002_auth_sessions.sql"),
    },
    Migration {
        version: 3,
        name: "product_management",
        sql: include_str!("../migrations/003_product_management.sql"),
    },
];

/// The highest schema version this binary understands.
pub(crate) fn supported_version() -> i64 {
    MIGRATIONS.last().map_or(0, |m| m.version)
}
/// Creates a recovery snapshot before a schema-changing migration runs.
///
/// A snapshot is taken only when the database is already at a schema version
/// *and* a newer migration is pending. A brand-new initialization has nothing
/// to lose, and a database already at the newest version has nothing to migrate.
///
/// The versions are parameters rather than read internally so the behavior can
/// be qualified against a simulated upgrade without shipping a meaningless
/// production migration. The production call site passes the real ones.
///
/// Retention is deliberately bounded: the snapshot name carries the
/// pre-migration version, and an existing snapshot for that same version is
/// kept rather than replaced. wg-basic never accumulates automatic backups.
pub(super) fn recovery_snapshot(
    connection: &Connection,
    path: &Path,
    from_version: i64,
    to_version: i64,
) -> Result<(), StateError> {
    // A brand-new initialization has nothing to lose, and a database already at
    // the newest version has nothing to migrate.
    if from_version <= 0 || from_version >= to_version {
        return Ok(());
    }
    let current = from_version;

    let target = recovery_snapshot_path(path, current);
    // A snapshot that already exists corresponds to the same pre-migration
    // schema, so it is kept rather than replaced.
    if fs::symlink_metadata(&target).is_ok() {
        return Ok(());
    }

    let staging = target.with_extension(format!("partial.{}", std::process::id()));
    let outcome = (|| -> Result<(), StateError> {
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(DATABASE_MODE)
            .open(&staging)
            .map_err(|_| StateError::Corrupt("recovery snapshot could not be created"))?;
        let mut destination = Connection::open_with_flags(
            &staging,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(StateError::database)?;
        {
            let backup = rusqlite::backup::Backup::new(connection, &mut destination)
                .map_err(StateError::database)?;
            backup
                .run_to_completion(64, std::time::Duration::from_millis(0), None)
                .map_err(StateError::database)?;
        }
        destination
            .close()
            .map_err(|(_, _)| StateError::Corrupt("recovery snapshot could not be finalized"))?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(DATABASE_MODE))
            .map_err(|_| StateError::Corrupt("recovery snapshot permissions are unsafe"))?;
        fs::rename(&staging, &target)
            .map_err(|_| StateError::Corrupt("recovery snapshot could not be installed"))
    })();

    if outcome.is_err() {
        // Only this operation's own staging artifact is removed. A failure here
        // must not prevent the migration from running on the original database.
        let _ = fs::remove_file(&staging);
    }
    outcome
}

/// The deterministic location of the pre-migration recovery snapshot.
pub(super) fn recovery_snapshot_path(database: &Path, from_version: i64) -> PathBuf {
    let parent = database.parent().unwrap_or_else(|| Path::new("."));
    let name = database
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state.db".to_owned());
    parent.join(format!("{name}.pre-migration-v{from_version}"))
}
/// Applies every production migration in order.
pub(super) fn run_migrations(connection: &mut Connection) -> Result<(), StateError> {
    apply_migrations(connection, MIGRATIONS)
}

/// Applies pending migrations in order inside one IMMEDIATE transaction.
///
/// Historical migration SQL is never rewritten to make a test pass: a new
/// schema change is a new migration. The `available` slice is a parameter only
/// so the runner mechanics can be qualified against a simulated version history.
pub(super) fn apply_migrations(
    connection: &mut Connection,
    available: &[Migration],
) -> Result<(), StateError> {
    let current: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(StateError::database)?;

    if current < 0 {
        return Err(StateError::SchemaVersionInvalid(current));
    }
    let supported = available.last().map_or(0, |migration| migration.version);
    if current > supported {
        return Err(StateError::SchemaTooNew {
            found: current,
            supported,
        });
    }

    let pending: Vec<&Migration> = available
        .iter()
        .filter(|migration| migration.version > current)
        .collect();
    if pending.is_empty() {
        return Ok(());
    }

    // IMMEDIATE avoids a read-then-write snapshot upgrade race for the
    // read-validate-write sequence below.
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(StateError::database)?;

    for migration in pending {
        transaction
            .execute_batch(migration.sql)
            .map_err(|_| StateError::MigrationFailed {
                version: migration.version,
                name: migration.name,
            })?;
        transaction
            .pragma_update(None, "user_version", migration.version)
            .map_err(StateError::database)?;
        foreign_key_check(&transaction).map_err(|_| StateError::MigrationFailed {
            version: migration.version,
            name: migration.name,
        })?;
    }

    transaction.commit().map_err(StateError::database)
}

/// Fails when any row violates a declared foreign key.
///
/// `PRAGMA foreign_key_check` returns one row per violation and no rows at all
/// when the schema is consistent, so it is inspected as a row stream rather
/// than with `query_row`.
fn foreign_key_check(transaction: &rusqlite::Transaction<'_>) -> Result<(), rusqlite::Error> {
    let mut statement = transaction.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    if rows.next()?.is_some() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}
/// Creates a database migrated only as far as `through_version`.
///
/// The filter runs over the **production** migration list, so the result is a
/// genuine historical database at that version rather than a simulated one.
/// Phase 7 M002 added migration 2, so `initialize_at_version(path, 1)` now
/// builds a real v1 store -- the boundary a real user would be upgrading from.
#[cfg(test)]
pub(super) fn initialize_at_version(path: &Path, through_version: i64) -> Result<(), StateError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| StateError::DatabaseOpenFailed)?;
    configure(&connection)?;
    let available: Vec<Migration> = MIGRATIONS
        .iter()
        .filter(|migration| migration.version <= through_version)
        .cloned()
        .collect();
    let mut connection = connection;
    apply_migrations(&mut connection, &available)?;
    super::seed_installation(
        &connection,
        &crate::domain::InstallationId::new(),
        crate::domain::INITIAL_DESIRED_GENERATION,
    )?;
    connection
        .close()
        .map_err(|(_, _)| StateError::Corrupt("historical fixture could not be finalized"))
}
