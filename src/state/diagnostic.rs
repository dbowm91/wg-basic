//! Non-mutating, typed inspection of the authoritative database.

use crate::{
    domain::{validate_desired_state, DesiredGeneration},
    state::{
        store::{desired, product, sql},
        ConvergenceRecord, InstallationMetadata, PersistedDesiredState, ProductState, StateError,
    },
};
use rusqlite::{Connection, OpenFlags};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

/// A fully decoded state view. The type deliberately has no `Debug` or
/// serialization implementation because the desired state contains secrets.
pub struct StateDiagnostic {
    pub schema_version: i64,
    pub metadata: InstallationMetadata,
    pub desired: PersistedDesiredState,
    pub product: ProductState,
    pub convergence: ConvergenceRecord,
    pub recovery_artifacts: Vec<RecoveryArtifactStatus>,
}

pub struct RecoveryArtifactStatus {
    pub source_schema: i64,
    pub present: bool,
    pub safe: bool,
}

/// Secret-free identity for update compatibility checks.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct StateIdentity {
    pub installation_id: String,
    pub schema_version: i64,
    pub desired_generation: i64,
    pub network_enabled: bool,
    pub product_identity_sha256: String,
}

/// Reads the update identity from a live database without applying migrations
/// or changing SQLite pragmas. A read-only connection observes committed WAL
/// data when the service is running.
pub fn inspect_identity_readonly(path: &Path) -> Result<StateIdentity, StateError> {
    use sha2::Digest;

    let path = std::path::absolute(path).map_err(|_| StateError::DatabaseOpenFailed)?;
    verify_path_readonly(&path)?;
    let wal_exists = sidecar(&path, "-wal").exists();
    let shm_exists = sidecar(&path, "-shm").exists();
    if wal_exists != shm_exists {
        return Err(StateError::Busy);
    }
    for suffix in ["-wal", "-shm"] {
        let sidecar = sidecar(&path, suffix);
        let metadata = match fs::symlink_metadata(&sidecar) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(StateError::DatabaseOpenFailed),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != uid()
            || metadata.mode() & 0o077 != 0
        {
            return Err(StateError::DatabaseOpenFailed);
        }
    }
    let connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| StateError::DatabaseOpenFailed)?;
    let schema_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(StateError::database)?;
    if schema_version <= 0 {
        return Err(StateError::SchemaVersionInvalid(schema_version));
    }
    let supported = super::schema::supported_version();
    if schema_version > supported {
        return Err(StateError::SchemaTooNew {
            found: schema_version,
            supported,
        });
    }
    super::schema::enforce_singleton(&connection)?;
    let metadata = sql::read_installation(&connection)?;
    let product = product::read_product_at_schema(&connection, schema_version)?;
    let identifiers = serde_json::json!({
        "interfaces": product.interfaces.keys().map(ToString::to_string).collect::<Vec<_>>(),
        "clients": product.clients.keys().map(ToString::to_string).collect::<Vec<_>>(),
    });
    let encoded = serde_json::to_vec(&identifiers).map_err(|_| StateError::IntegrityCheckFailed)?;
    let product_identity_sha256 = sha2::Sha256::digest(&encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(StateIdentity {
        installation_id: metadata.installation_id.to_string(),
        schema_version,
        desired_generation: metadata.desired_generation.to_storage(),
        network_enabled: product
            .network_operational_enabled
            .values()
            .any(|enabled| *enabled),
        product_identity_sha256,
    })
}

/// Loads and validates one immutable SQLite snapshot without migrations,
/// pragma updates, WAL creation, or any other writes.
pub fn inspect_readonly(path: &Path) -> Result<StateDiagnostic, StateError> {
    let path = std::path::absolute(path).map_err(|_| StateError::DatabaseOpenFailed)?;
    verify_path_readonly(&path)?;
    if sidecar(&path, "-wal").exists() || sidecar(&path, "-shm").exists() {
        return Err(StateError::Busy);
    }
    let uri = immutable_uri(&path)?;
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|_| StateError::DatabaseOpenFailed)?;

    let quick_check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(StateError::database)?;
    if quick_check != "ok" {
        return Err(StateError::IntegrityCheckFailed);
    }
    let foreign_key_failures: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(StateError::database)?;
    if foreign_key_failures != 0 {
        return Err(StateError::IntegrityCheckFailed);
    }
    let schema_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(StateError::database)?;
    if schema_version <= 0 {
        return Err(StateError::SchemaVersionInvalid(schema_version));
    }
    let supported = super::schema::supported_version();
    if schema_version > supported {
        return Err(StateError::SchemaTooNew {
            found: schema_version,
            supported,
        });
    }
    super::schema::enforce_singleton(&connection)?;

    let metadata = sql::read_installation(&connection)?;
    let desired = desired::load_desired(&connection)?;
    validate_desired_state(&desired.state)?;
    let product = product::read_product_at_schema(&connection, schema_version)?;
    let convergence = connection
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
                last_attempted_generation: parse_generation(attempted)?,
                last_converged_generation: parse_generation(converged)?,
                last_attempt_timestamp: timestamp,
                last_outcome: outcome,
            })
        })?;

    // Immutable mode intentionally ignores WAL data. Refuse a result if a
    // writer created sidecars while inspection was in progress.
    if sidecar(&path, "-wal").exists() || sidecar(&path, "-shm").exists() {
        return Err(StateError::Busy);
    }
    let recovery_artifacts = (1..schema_version)
        .map(|source_schema| {
            let artifact = super::schema::recovery_snapshot_path(&path, source_schema);
            match fs::symlink_metadata(&artifact) {
                Ok(metadata) => RecoveryArtifactStatus {
                    source_schema,
                    present: true,
                    safe: metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.uid() == uid()
                        && metadata.mode() & 0o077 == 0,
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    RecoveryArtifactStatus {
                        source_schema,
                        present: false,
                        safe: true,
                    }
                }
                Err(_) => RecoveryArtifactStatus {
                    source_schema,
                    present: true,
                    safe: false,
                },
            }
        })
        .collect();
    Ok(StateDiagnostic {
        schema_version,
        metadata,
        desired,
        product,
        convergence,
        recovery_artifacts,
    })
}

fn parse_generation(value: Option<i64>) -> Result<Option<DesiredGeneration>, StateError> {
    value
        .map(|value| DesiredGeneration::from_storage(value).ok_or(StateError::IntegrityCheckFailed))
        .transpose()
}

fn verify_path_readonly(path: &Path) -> Result<(), StateError> {
    let parent = path.parent().ok_or(StateError::MissingPath)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| StateError::MissingParent {
        path: parent.display().to_string(),
    })?;
    let uid = uid();
    if !parent_metadata.is_dir() {
        return Err(StateError::ParentNotDirectory {
            path: parent.display().to_string(),
        });
    }
    if parent_metadata.uid() != uid {
        return Err(StateError::ParentWrongOwner {
            path: parent.display().to_string(),
            owner: parent_metadata.uid(),
            expected: uid,
        });
    }
    if parent_metadata.mode() & 0o022 != 0 {
        return Err(StateError::ParentTooPermissive {
            path: parent.display().to_string(),
        });
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| StateError::MissingParent {
        path: path.display().to_string(),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(StateError::DatabaseIsSymlink {
            path: path.display().to_string(),
        });
    }
    if !metadata.is_file() {
        return Err(StateError::DatabaseNotRegularFile {
            path: path.display().to_string(),
        });
    }
    if metadata.uid() != uid {
        return Err(StateError::DatabaseWrongOwner {
            path: path.display().to_string(),
            owner: metadata.uid(),
            expected: uid,
        });
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(StateError::DatabaseTooPermissive {
            path: path.display().to_string(),
        });
    }
    Ok(())
}

fn uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

fn immutable_uri(path: &Path) -> Result<String, StateError> {
    use std::os::unix::ffi::OsStrExt;
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'-' | b'_' | b'.' | b'~') {
            uri.push(char::from(*byte));
        } else {
            uri.push('%');
            uri.push_str(&format!("{byte:02X}"));
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    Ok(uri)
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    value.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn immutable_inspection_decodes_state_without_mutating_files() {
        let directory = Path::new("/tmp").join(format!(
            "wg-basic-state-diagnostic-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let database = directory.join("state.db");
        drop(crate::state::StateStore::initialize(&database).unwrap());
        let before = fs::read(&database).unwrap();
        let entries_before = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();

        let inspected = inspect_readonly(&database).unwrap();
        assert_eq!(
            inspected.schema_version,
            super::super::schema::supported_version()
        );
        assert_eq!(inspected.metadata.desired_generation.to_storage(), 1);
        assert!(inspected.desired.state.interfaces.is_empty());
        assert!(inspected.product.clients.is_empty());
        assert!(inspected.convergence.last_converged_generation.is_none());
        assert!(inspected
            .recovery_artifacts
            .iter()
            .all(|artifact| !artifact.present));
        assert_eq!(fs::read(&database).unwrap(), before);
        let entries_after = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries_after, entries_before);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn immutable_inspection_refuses_a_newer_schema_without_migrating_it() {
        let directory = Path::new("/tmp").join(format!(
            "wg-basic-newer-diagnostic-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let database = directory.join("state.db");
        drop(crate::state::StateStore::initialize(&database).unwrap());
        let connection = Connection::open(&database).unwrap();
        connection
            .pragma_update(None, "user_version", 999_i64)
            .unwrap();
        drop(connection);
        let before = fs::read(&database).unwrap();
        assert!(matches!(
            inspect_readonly(&database),
            Err(StateError::SchemaTooNew { found: 999, .. })
        ));
        assert_eq!(fs::read(&database).unwrap(), before);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn identity_inspection_reads_v4_with_live_wal_without_migrating() {
        let directory = Path::new("/tmp").join(format!(
            "wg-basic-identity-diagnostic-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let database = directory.join("state.db");
        drop(crate::state::StateStore::initialize(&database).unwrap());
        let connection = Connection::open(&database).unwrap();
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .unwrap();
        connection
            .pragma_update(None, "user_version", 4_i64)
            .unwrap();
        connection
            .execute(
                "UPDATE installation SET desired_generation = 7 WHERE singleton = 1",
                [],
            )
            .unwrap();
        assert!(sidecar(&database, "-wal").exists());

        let identity = inspect_identity_readonly(&database).unwrap();
        assert_eq!(identity.schema_version, 4);
        assert_eq!(identity.desired_generation, 7);
        assert!(!identity.network_enabled);
        assert!(sidecar(&database, "-wal").exists());
        let schema_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(schema_version, 4);
        drop(connection);
        fs::remove_dir_all(directory).unwrap();
    }
}
