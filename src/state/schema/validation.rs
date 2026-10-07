//! Path and pragma hardening for the state database.
//!
//! Both concerns live here because they are the same concern: proving, before
//! any SQL runs, that the file about to be opened is the one this process owns,
//! in the directory this process owns, with no access anyone else has. The
//! pragma contract is read back rather than assumed, so an unsupported setting
//! fails loudly instead of leaving the database quietly weaker than intended.

use super::OpenIntent;
use crate::state::error::StateError;
use rusqlite::Connection;
use std::{
    fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

/// `PRAGMA synchronous` value for `FULL`.
pub(super) const SQLITE_SYNCHRONOUS_FULL: i64 = 2;
/// The restrictive mode a secret-bearing database must carry.
pub(super) const DATABASE_MODE: u32 = 0o600;
pub(super) fn verify_path(
    path: &Path,
    intent: OpenIntent,
    expected_uid: u32,
) -> Result<(), StateError> {
    let parent = path.parent().ok_or(StateError::MissingPath)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| StateError::MissingParent {
        path: parent.display().to_string(),
    })?;
    if !parent_metadata.is_dir() {
        return Err(StateError::ParentNotDirectory {
            path: parent.display().to_string(),
        });
    }
    if parent_metadata.uid() != expected_uid {
        return Err(StateError::ParentWrongOwner {
            path: parent.display().to_string(),
            owner: parent_metadata.uid(),
            expected: expected_uid,
        });
    }
    if parent_metadata.mode() & 0o022 != 0 {
        return Err(StateError::ParentTooPermissive {
            path: parent.display().to_string(),
        });
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
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
            if metadata.uid() != expected_uid {
                return Err(StateError::DatabaseWrongOwner {
                    path: path.display().to_string(),
                    owner: metadata.uid(),
                    expected: expected_uid,
                });
            }
            // Ownership is already proven above, so group/world access can be
            // safely narrowed rather than merely refused. The file holds server
            // and client private keys and preshared keys.
            if metadata.mode() & 0o077 != 0 {
                fs::set_permissions(path, fs::Permissions::from_mode(DATABASE_MODE)).map_err(
                    |_| StateError::DatabaseTooPermissive {
                        path: path.display().to_string(),
                    },
                )?;
                let narrowed =
                    fs::symlink_metadata(path).map_err(|_| StateError::DatabaseTooPermissive {
                        path: path.display().to_string(),
                    })?;
                if narrowed.mode() & 0o077 != 0 {
                    return Err(StateError::DatabaseTooPermissive {
                        path: path.display().to_string(),
                    });
                }
            }
            if intent == OpenIntent::Initialize {
                return Err(StateError::DatabaseAlreadyExists {
                    path: path.display().to_string(),
                });
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if intent == OpenIntent::Reopen {
                return Err(StateError::MissingParent {
                    path: path.display().to_string(),
                });
            }
        }
        Err(_) => {
            return Err(StateError::DatabaseNotRegularFile {
                path: path.display().to_string(),
            })
        }
    }

    if intent == OpenIntent::Initialize {
        // Create the file with the restrictive mode up front. Letting SQLite
        // create it would briefly expose a world-readable file (and its WAL
        // sidecars inherit the database mode) before any check could run.
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(DATABASE_MODE)
            .open(path)
            .map_err(|_| StateError::DatabaseOpenFailed)?;
    }
    Ok(())
}

/// Applies the hardened connection contract and reads it back.
///
/// Every pragma is read back so a typo or an unsupported setting fails loudly
/// instead of silently leaving the database weaker than intended.
pub(super) fn configure(connection: &Connection) -> Result<(), StateError> {
    connection
        .pragma_update(None, "foreign_keys", true)
        .and_then(|_| connection.pragma_update(None, "trusted_schema", false))
        .and_then(|_| connection.pragma_update(None, "journal_mode", "WAL"))
        .and_then(|_| connection.pragma_update(None, "synchronous", "FULL"))
        .and_then(|_| connection.pragma_update(None, "mmap_size", 0i64))
        .map_err(StateError::database)?;

    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(StateError::database)?;

    // Read back the settings that change correctness or durability.
    let foreign_keys: i64 = read_pragma(connection, "foreign_keys")?;
    if foreign_keys != 1 {
        return Err(StateError::ForeignKeysDisabled);
    }
    let journal_mode: String = read_pragma(connection, "journal_mode")?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StateError::PragmaNotApplied {
            pragma: "journal_mode",
        });
    }
    // `PRAGMA synchronous` reports a numeric code: 0=OFF, 1=NORMAL, 2=FULL.
    let synchronous: i64 = read_pragma(connection, "synchronous")?;
    if synchronous != SQLITE_SYNCHRONOUS_FULL {
        return Err(StateError::PragmaNotApplied {
            pragma: "synchronous",
        });
    }
    let mmap_size: i64 = read_pragma(connection, "mmap_size")?;
    if mmap_size != 0 {
        return Err(StateError::PragmaNotApplied {
            pragma: "mmap_size",
        });
    }
    // `trusted_schema` reports 0 when disabled. A connection that cannot express
    // the setting is rejected rather than accepted with unknown behavior.
    let trusted_schema: i64 = read_pragma(connection, "trusted_schema")?;
    if trusted_schema != 0 {
        return Err(StateError::PragmaNotApplied {
            pragma: "trusted_schema",
        });
    }
    Ok(())
}

fn read_pragma<T: rusqlite::types::FromSql>(
    connection: &Connection,
    name: &str,
) -> Result<T, StateError> {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .map_err(|_| StateError::PragmaNotApplied {
            pragma: "unreadable",
        })
}
