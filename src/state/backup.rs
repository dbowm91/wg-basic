//! Backup, restore, and validation of the durable state database.
//!
//! # Backup
//!
//! Backup uses SQLite's **online backup API**, never a `cp` of a live WAL
//! database. Copying `state.db` while WAL sidecars hold committed transactions
//! produces a file that is missing recent commits, which is worse than an
//! obviously stale backup because it looks intact.
//!
//! The store's own mutation lock is held for the duration. The database is
//! small, so serializing is cheap, and it turns "backup corresponds to
//! generation N" from a hopeful claim into a receipt the caller can rely on.
//!
//! # Restore
//!
//! Restore is **offline and exclusive**. It never writes into a database a live
//! store still owns, and it never touches the kernel: after a restore, ordinary
//! startup reconciliation does that, under the ordinary owner-tag rules. A
//! restored database is not authority over unrelated host state.
//!
//! The order is validate-then-replace. A candidate is proved readable,
//! integrity-clean, not-newer-than-this-binary, migratable, and fully loadable
//! into typed state **before** anything replaces the target. A failure at any
//! step leaves the original database exactly as it was.
//!
//! # Secret handling
//!
//! Backups contain server private keys, client private keys, and preshared
//! keys. A backup is a second copy of the secrets, never a sanitized export:
//! every artifact is created `0600`, the temporary file is owned by this
//! operation and removed on failure, and no receipt or diagnostic ever carries
//! row contents.

use super::{
    error::StateError,
    inuse,
    schema::{self},
    store::StateStore,
};
use crate::domain::{validate_desired_state, DesiredGeneration, InstallationId};
use rusqlite::backup::{Backup, StepResult};
use std::{
    fs,
    io::Write,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
};

/// The restrictive mode every backup and restore artifact must carry.
const SECRET_MODE: u32 = 0o600;

/// The mode a restored database itself must carry.
const DATABASE_MODE: u32 = 0o600;

/// How many pages the online backup copies per step.
///
/// The backup API is stepwise; a bounded step keeps the loop simple and the
/// worst-case pause per step small.
const PAGES_PER_STEP: i32 = 64;

/// How many times the backup loop will step before giving up.
///
/// A small database needs one or two steps. The bound exists so a pathological
/// page count cannot spin forever.
const MAX_BACKUP_STEPS: u32 = 1_000_000;

/// How long to wait when the backup source reports itself busy or locked.
const TRANSIENT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

/// How a completed backup ended.
///
/// A backup that did not fully complete is an error, not a receipt: a partial
/// file is never promoted into place. This enum exists so the receipt can say
/// so explicitly rather than leaving it implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupDisposition {
    /// The full source database was copied and the result is in place.
    Complete,
}

/// What a backup produced.
///
/// Carries only identifiers and locations. It never carries row contents, so it
/// is safe to log or print in full.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupReceipt {
    /// The installation identity of the source database.
    pub installation_id: InstallationId,
    /// The desired generation the snapshot corresponds to.
    pub generation: DesiredGeneration,
    /// The schema version of the source database.
    pub schema_version: i64,
    /// Where the backup was written.
    pub destination: PathBuf,
    pub disposition: BackupDisposition,
}

/// What a restore validated and replaced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreReceipt {
    /// The installation identity carried by the restored database.
    pub installation_id: InstallationId,
    /// The desired generation carried by the restored database.
    pub generation: DesiredGeneration,
    /// The schema version after pending migrations were applied.
    pub schema_version: i64,
    /// The target that now holds the restored database.
    pub target: PathBuf,
    /// The previous target contents, retained for operator recovery.
    ///
    /// `None` when the target did not previously exist.
    pub previous_retained_at: Option<PathBuf>,
}

/// Secret-free verification of a candidate state database.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateVerification {
    pub path: PathBuf,
    pub installation_id: InstallationId,
    pub generation: DesiredGeneration,
    pub schema_version: i64,
    pub supported_schema_version: i64,
    pub integrity_ok: bool,
    pub foreign_keys_ok: bool,
    pub would_migrate: bool,
    pub too_new: bool,
}

/// Verifies the candidate without applying migrations or writing to it.
pub fn verify_candidate_readonly(candidate: &Path) -> Result<CandidateVerification, StateError> {
    verify_candidate(candidate)?;
    let connection = open_read_only(candidate)?;
    let schema_version = user_version(&connection)?;
    let supported_schema_version = schema::supported_version();
    let installation_id = read_installation_id(&connection)?;
    let generation = read_generation(&connection)?;
    Ok(CandidateVerification {
        path: candidate.to_path_buf(),
        installation_id,
        generation,
        schema_version,
        supported_schema_version,
        integrity_ok: true,
        foreign_keys_ok: true,
        would_migrate: schema_version < supported_schema_version,
        too_new: schema_version > supported_schema_version,
    })
}

impl StateStore {
    /// Writes a consistent snapshot of this store to `destination`.
    ///
    /// The mutation lock is held for the whole operation, so the receipt's
    /// generation is exactly the generation the file contains. The destination
    /// must not already exist: overwriting is refused rather than done
    /// unsafely, because the safe operation here is to choose a new path.
    pub fn backup(&self, destination: impl AsRef<Path>) -> Result<BackupReceipt, StateError> {
        let _maintenance = super::MaintenanceLease::shared(self.path())
            .map_err(|_| StateError::MaintenanceLeaseUnavailable)?;
        let destination = destination.as_ref();
        let connection = self.lock()?;
        let installation_id = read_installation_id(&connection)?;
        let generation = read_generation(&connection)?;
        let schema_version = user_version(&connection)?;

        prepare_destination(destination)?;
        let temporary = temporary_artifact(destination, ".backup")?;

        let outcome = (|| -> Result<(), StateError> {
            create_private_file(&temporary)?;
            let mut target = rusqlite::Connection::open_with_flags(
                &temporary,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(StateError::database)?;

            {
                // The online backup API takes a consistent snapshot of a live
                // database; this is why backup is not a file copy.
                let backup = Backup::new(&connection, &mut target).map_err(StateError::database)?;
                let mut remaining = MAX_BACKUP_STEPS;
                loop {
                    match backup.step(PAGES_PER_STEP).map_err(StateError::database)? {
                        StepResult::Done => break,
                        StepResult::More => {
                            remaining -= 1;
                            if remaining == 0 {
                                // The artifact is still owned by this operation and
                                // is removed by the caller, so an unfinished copy is
                                // never left behind looking like a backup.
                                return Err(StateError::Corrupt("backup did not converge"));
                            }
                        }
                        // A busy or locked source is transient. Retry rather than
                        // treat it as completion, but keep it inside the same bound
                        // so a contended source cannot spin forever.
                        StepResult::Busy | StepResult::Locked => {
                            remaining -= 1;
                            if remaining == 0 {
                                return Err(StateError::Corrupt("backup source stayed busy"));
                            }
                            std::thread::sleep(TRANSIENT_BACKOFF);
                        }
                        // `StepResult` is `#[non_exhaustive]`, so an unhandled
                        // variant is treated as a failure rather than completion.
                        _ => return Err(StateError::Corrupt("backup ended unexpectedly")),
                    }
                }
            }

            target
                .close()
                .map_err(|(_, _)| StateError::Corrupt("backup could not be finalized"))?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(SECRET_MODE))
                .map_err(|_| StateError::Corrupt("backup permissions could not be narrowed"))?;
            sync_file(&temporary)?;
            verify_candidate(&temporary)?;
            if read_installation_id_from_file(&temporary)? != installation_id
                || read_generation_from_file(&temporary)? != generation
                || user_version(&open_read_only(&temporary)?)? != schema_version
            {
                return Err(StateError::Corrupt(
                    "backup verification did not match its receipt",
                ));
            }
            promote(&temporary, destination)?;
            Ok(())
        })();

        if outcome.is_err() {
            // Only this operation's own temporary artifact is removed. The
            // destination was never touched, and nothing else is deleted.
            let _ = fs::remove_file(&temporary);
        }

        outcome?;
        Ok(BackupReceipt {
            installation_id,
            generation,
            schema_version,
            destination: destination.to_path_buf(),
            disposition: BackupDisposition::Complete,
        })
    }
}

/// Restores `candidate` into `target` after validating it.
///
/// The caller must have stopped the management service. This function refuses
/// if this process still holds the target or candidate open, and it never
/// contacts the kernel.
pub fn restore(
    candidate: impl AsRef<Path>,
    target: impl AsRef<Path>,
) -> Result<RestoreReceipt, StateError> {
    let candidate = candidate.as_ref();
    let target = target.as_ref();
    let _lease = super::ServiceLease::acquire(target)
        .map_err(|_| StateError::MaintenanceLeaseUnavailable)?;
    let _maintenance = super::MaintenanceLease::exclusive(target)
        .map_err(|_| StateError::MaintenanceLeaseUnavailable)?;

    if inuse::is_open_in_this_process(target) {
        return Err(StateError::TargetInUse);
    }
    if inuse::is_open_in_this_process(candidate) {
        return Err(StateError::CandidateInUse);
    }
    verify_candidate(candidate)?;
    verify_target_parent(target)?;

    let installation_id = read_installation_id_from_file(candidate)?;
    let generation = read_generation_from_file(candidate)?;

    // Everything below works on a private copy. The candidate is an operator
    // artifact and must not be modified in place by migrating it.
    let staging = temporary_artifact(target, ".restore")?;
    let outcome = stage_restore(candidate, &staging, target);

    let (schema_version, previous) = match outcome {
        Ok(result) => result,
        Err(error) => {
            // A failed restore must leave the original database untouched. The
            // staging artifact belongs to this operation alone.
            let _ = fs::remove_file(&staging);
            return Err(error);
        }
    };

    Ok(RestoreReceipt {
        installation_id,
        generation,
        schema_version,
        target: target.to_path_buf(),
        previous_retained_at: previous,
    })
}

/// Validates the candidate, migrates the staging copy, and replaces the target.
///
/// Returns the post-migration schema version and the retained previous target.
fn stage_restore(
    candidate: &Path,
    staging: &Path,
    target: &Path,
) -> Result<(i64, Option<PathBuf>), StateError> {
    create_private_file(staging)?;

    {
        let mut connection = rusqlite::Connection::open_with_flags(
            staging,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        )
        .map_err(StateError::database)?;
        schema::configure_for_restore(&connection)?;
        let source = open_read_only(candidate)?;
        {
            let backup = Backup::new(&source, &mut connection).map_err(StateError::database)?;
            backup
                .run_to_completion(PAGES_PER_STEP, std::time::Duration::from_millis(0), None)
                .map_err(StateError::database)?;
        }
    }

    // Validate the *staged* copy: same bytes as the candidate, but it is ours,
    // so migrations may be applied without touching the operator's file.
    let inspection = StateStore::open_with_expected_owner(staging, current_uid())?;
    let schema_version = inspection.schema_version()?;
    let persisted = inspection.load()?;
    validate_desired_state(&persisted.state).map_err(StateError::Validation)?;
    let metadata = inspection.installation_metadata()?;
    if metadata.installation_id != installation_id_from_path(candidate)? {
        return Err(StateError::Corrupt(
            "installation identity changed during restore",
        ));
    }
    if persisted.generation != metadata.desired_generation {
        return Err(StateError::Corrupt(
            "desired generation does not match the installation row",
        ));
    }
    drop(inspection);

    fs::set_permissions(staging, fs::Permissions::from_mode(DATABASE_MODE))
        .map_err(|_| StateError::Corrupt("restored database permissions are unsafe"))?;
    sync_file(staging)?;

    let previous = replace_target(staging, target)?;
    Ok((schema_version, previous))
}

/// Atomically installs `staging` as `target`, retaining the previous target.
///
/// The previous contents are moved aside rather than deleted, so a restore that
/// turns out to be wrong is still recoverable. The retained name is
/// deterministic so operators can find it without reading a log.
fn replace_target(staging: &Path, target: &Path) -> Result<Option<PathBuf>, StateError> {
    let previous = match fs::symlink_metadata(target) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let retained = retained_previous_path(target);
            let _ = fs::remove_file(&retained);
            fs::rename(target, &retained)
                .map_err(|_| StateError::Corrupt("previous target could not be retained"))?;
            sync_directory(&parent_of(target)?)?;
            Some(retained)
        }
        Ok(_) => return Err(StateError::Corrupt("existing target is not a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => {
            return Err(StateError::Corrupt(
                "existing target could not be inspected",
            ))
        }
    };

    fs::rename(staging, target)
        .map_err(|_| StateError::Corrupt("restored database could not be installed"))?;
    // The directory entry, not just the file contents, must be durable.
    sync_directory(&parent_of(target)?)?;
    Ok(previous)
}

/// Validates a restore candidate before anything is copied or replaced.
pub fn validate_candidate(candidate: &Path) -> Result<(), StateError> {
    verify_candidate(candidate)?;
    let connection = open_read_only(candidate)?;
    let found = user_version(&connection)?;
    let supported = schema::supported_version();
    if found > supported {
        return Err(StateError::SchemaTooNew { found, supported });
    }
    Ok(())
}

fn verify_candidate(candidate: &Path) -> Result<(), StateError> {
    let metadata = fs::symlink_metadata(candidate).map_err(|_| StateError::MissingParent {
        path: candidate.display().to_string(),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(StateError::DatabaseIsSymlink {
            path: candidate.display().to_string(),
        });
    }
    if !metadata.is_file() {
        return Err(StateError::DatabaseNotRegularFile {
            path: candidate.display().to_string(),
        });
    }
    if metadata.uid() != current_uid() {
        return Err(StateError::DatabaseWrongOwner {
            path: candidate.display().to_string(),
            owner: metadata.uid(),
            expected: current_uid(),
        });
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(StateError::DatabaseTooPermissive {
            path: candidate.display().to_string(),
        });
    }

    for suffix in ["-wal", "-shm"] {
        let mut sidecar = candidate.as_os_str().to_os_string();
        sidecar.push(suffix);
        if fs::symlink_metadata(PathBuf::from(sidecar)).is_ok() {
            return Err(StateError::Busy);
        }
    }

    let connection = open_read_only(candidate)?;
    // `quick_check` is enough to reject a malformed or truncated file, and it
    // runs against the read-only handle so a candidate is never written.
    let verdict: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| StateError::IntegrityCheckFailed)?;
    if verdict != "ok" {
        return Err(StateError::IntegrityCheckFailed);
    }
    if any_row(&connection, "PRAGMA foreign_key_check")? {
        return Err(StateError::IntegrityCheckFailed);
    }
    Ok(())
}

/// Refuses a backup destination that is not a safe, new, private path.
fn prepare_destination(destination: &Path) -> Result<(), StateError> {
    if destination.as_os_str().is_empty() {
        return Err(StateError::MissingPath);
    }
    let parent = parent_of(destination)?;
    let metadata = fs::symlink_metadata(&parent).map_err(|_| StateError::MissingParent {
        path: parent.display().to_string(),
    })?;
    if !metadata.is_dir() {
        return Err(StateError::ParentNotDirectory {
            path: parent.display().to_string(),
        });
    }
    if metadata.uid() != current_uid() {
        return Err(StateError::ParentWrongOwner {
            path: parent.display().to_string(),
            owner: metadata.uid(),
            expected: current_uid(),
        });
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(StateError::ParentTooPermissive {
            path: parent.display().to_string(),
        });
    }
    match fs::symlink_metadata(destination) {
        // An existing destination is refused rather than replaced: the safe
        // operation is to choose a new path, and an overwrite feature would
        // need its own atomic-replacement justification.
        Ok(_) => Err(StateError::BackupDestinationExists {
            path: destination.display().to_string(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(StateError::Corrupt(
            "backup destination could not be inspected",
        )),
    }
}

fn verify_target_parent(target: &Path) -> Result<(), StateError> {
    let parent = parent_of(target)?;
    let metadata = fs::symlink_metadata(&parent).map_err(|_| StateError::MissingParent {
        path: parent.display().to_string(),
    })?;
    if !metadata.is_dir() {
        return Err(StateError::ParentNotDirectory {
            path: parent.display().to_string(),
        });
    }
    if metadata.uid() != current_uid() {
        return Err(StateError::ParentWrongOwner {
            path: parent.display().to_string(),
            owner: metadata.uid(),
            expected: current_uid(),
        });
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(StateError::ParentTooPermissive {
            path: parent.display().to_string(),
        });
    }
    Ok(())
}

/// Opens the candidate read-only, so validation can never modify it.
fn open_read_only(path: &Path) -> Result<rusqlite::Connection, StateError> {
    // A normal read-only open of a WAL-mode database can still create -wal and
    // -shm sidecars. Immutable mode reads only the main file and guarantees
    // inspection never changes the candidate or depends on live WAL state.
    let uri_path = path.to_string_lossy();
    let mut uri = String::from("file:");
    for byte in uri_path.bytes() {
        if byte.is_ascii_alphanumeric() || b"/:._-".contains(&byte) {
            uri.push(byte as char);
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    rusqlite::Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| StateError::DatabaseOpenFailed)
}

/// Creates a file that only this user can read, even if it did not exist.
///
/// The mode is applied at creation rather than afterwards, so there is no
/// window in which a secret-bearing artifact is world-readable.
fn create_private_file(path: &Path) -> Result<(), StateError> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(SECRET_MODE)
        .open(path)
        .map(|_| ())
        .map_err(|_| StateError::Corrupt("backup artifact could not be created"))
}

/// A deterministic temporary name beside the final destination.
///
/// Beside the destination rather than in `/tmp` so the rename is within one
/// filesystem and therefore atomic.
fn temporary_artifact(destination: &Path, suffix: &str) -> Result<PathBuf, StateError> {
    let parent = parent_of(destination)?;
    let name = destination
        .file_name()
        .ok_or(StateError::MissingPath)?
        .to_string_lossy()
        .into_owned();
    Ok(parent.join(format!(".{name}{suffix}.{}", std::process::id())))
}

/// Renames a finished artifact into its final name.
fn promote(temporary: &Path, destination: &Path) -> Result<(), StateError> {
    fs::rename(temporary, destination)
        .map_err(|_| StateError::Corrupt("backup could not be installed"))?;
    sync_directory(&parent_of(destination)?)?;
    Ok(())
}

/// Where the previous target contents are retained after a restore.
pub fn retained_previous_path(target: &Path) -> PathBuf {
    match target.file_name() {
        Some(name) => parent_of(target)
            .unwrap_or_else(|_| target.to_path_buf())
            .join(format!("{}.pre-restore", name.to_string_lossy())),
        None => target.to_path_buf(),
    }
}

fn parent_of(path: &Path) -> Result<PathBuf, StateError> {
    path.parent()
        .map(Path::to_path_buf)
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| StateError::MissingParent {
            path: path.display().to_string(),
        })
}

fn read_installation_id(connection: &rusqlite::Connection) -> Result<InstallationId, StateError> {
    let raw: String = connection
        .query_row(
            "SELECT installation_id FROM installation WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(StateError::database)?;
    raw.parse::<InstallationId>()
        .map_err(|_| StateError::Corrupt("installation identity is not valid"))
}

fn read_generation(connection: &rusqlite::Connection) -> Result<DesiredGeneration, StateError> {
    let raw: i64 = connection
        .query_row(
            "SELECT desired_generation FROM installation WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(StateError::database)?;
    DesiredGeneration::from_storage(raw).ok_or(StateError::Corrupt(
        "stored desired generation is not valid",
    ))
}

fn read_installation_id_from_file(path: &Path) -> Result<InstallationId, StateError> {
    read_installation_id(&open_read_only(path)?)
}

fn read_generation_from_file(path: &Path) -> Result<DesiredGeneration, StateError> {
    read_generation(&open_read_only(path)?)
}

fn installation_id_from_path(path: &Path) -> Result<InstallationId, StateError> {
    read_installation_id_from_file(path)
}

fn user_version(connection: &rusqlite::Connection) -> Result<i64, StateError> {
    connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(StateError::database)
}

fn any_row(connection: &rusqlite::Connection, query: &str) -> Result<bool, StateError> {
    let mut statement = connection.prepare(query).map_err(StateError::database)?;
    let mut rows = statement.query([]).map_err(StateError::database)?;
    match rows.next() {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(_) => Err(StateError::IntegrityCheckFailed),
    }
}

fn sync_file(path: &Path) -> Result<(), StateError> {
    let file =
        fs::File::open(path).map_err(|_| StateError::Corrupt("artifact could not be synced"))?;
    // `File::sync_all` is `fsync(2)`. The database's own durability contract
    // also sets `synchronous = FULL`; this covers the file we just created.
    let mut handle = file;
    handle
        .flush()
        .map_err(|_| StateError::Corrupt("artifact could not be synced"))?;
    handle
        .sync_all()
        .map_err(|_| StateError::Corrupt("artifact could not be synced"))
}

/// fsyncs the directory so a rename is durable, not just the file contents.
fn sync_directory(path: &Path) -> Result<(), StateError> {
    let directory =
        fs::File::open(path).map_err(|_| StateError::Corrupt("directory could not be synced"))?;
    let _ = directory.as_raw_fd();
    directory
        .sync_all()
        .map_err(|_| StateError::Corrupt("directory could not be synced"))
}

fn current_uid() -> u32 {
    // The effective uid of this process. Reading it from the database file's own
    // ownership would make a chown'd database appear valid.
    std::os::unix::fs::MetadataExt::uid(
        &fs::metadata("/proc/self").unwrap_or_else(|_| fs::metadata(".").expect("cwd")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_receipts_carry_no_row_contents() {
        let receipt = BackupReceipt {
            installation_id: InstallationId::new(),
            generation: DesiredGeneration::new(3).unwrap(),
            schema_version: 1,
            destination: PathBuf::from("/tmp/state-backup.db"),
            disposition: BackupDisposition::Complete,
        };
        let rendered = format!("{receipt:?}");
        for forbidden in ["private_key", "secret", "peer"] {
            assert!(!rendered.contains(forbidden), "{forbidden} in {rendered}");
        }
    }

    #[test]
    fn a_retained_previous_target_has_a_deterministic_name() {
        let first = retained_previous_path(Path::new("/var/lib/wg-basic/state.db"));
        let second = retained_previous_path(Path::new("/var/lib/wg-basic/state.db"));
        assert_eq!(first, second);
        assert_eq!(
            first,
            PathBuf::from("/var/lib/wg-basic/state.db.pre-restore")
        );
    }
}
