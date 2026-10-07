//! Schema definition, migration runner, and the single canonical connection
//! initializer.
//!
//! Every path that opens the state database goes through [`open_connection`] so
//! the file ownership checks, open flags, and pragmas cannot drift apart.

use super::error::StateError;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use std::{
    fs,
    os::unix::{
        fs::PermissionsExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

/// `PRAGMA synchronous` value for `FULL`.
const SQLITE_SYNCHRONOUS_FULL: i64 = 2;

/// One ordered, immutable schema step.
pub(crate) struct Migration {
    pub(crate) version: i64,
    pub(crate) name: &'static str,
    pub(crate) sql: &'static str,
}

/// Every migration in exact application order.
pub(crate) const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "initial",
    sql: include_str!("migrations/001_initial.sql"),
}];

/// The highest schema version this binary understands.
pub(crate) fn supported_version() -> i64 {
    MIGRATIONS.last().map_or(0, |m| m.version)
}

/// How the caller intends to open a database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenIntent {
    /// Create the database and run migrations. Fails if it already exists.
    Initialize,
    /// Open an existing database and run any pending migrations.
    Reopen,
}

/// Opens the state database, applying the hardened connection contract.
///
/// Checks performed before and immediately after open:
/// - the parent directory exists, is a real directory, is owned by the expected
///   uid, and is not group/world writable;
/// - the database path is a regular file and not a symbolic link;
/// - the database is owned by the expected uid and is not group/world
///   accessible.
///
/// Flags: `READ_WRITE`, `CREATE` for initialization, `NO_MUTEX`, `NOFOLLOW`.
/// The URI flag is not used, so a path is never reinterpreted as a URI.
pub fn open_connection(
    path: &Path,
    intent: OpenIntent,
    expected_uid: u32,
) -> Result<Connection, StateError> {
    verify_path(path, intent, expected_uid)?;

    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    flags |= OpenFlags::SQLITE_OPEN_NOFOLLOW;
    if intent == OpenIntent::Initialize {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }

    let mut connection =
        Connection::open_with_flags(path, flags).map_err(|_| StateError::DatabaseOpenFailed)?;

    configure(&connection)?;
    run_migrations(&mut connection)?;
    enforce_singleton(&connection)?;
    Ok(connection)
}

/// The restrictive mode a secret-bearing database must carry.
const DATABASE_MODE: u32 = 0o600;

fn verify_path(path: &Path, intent: OpenIntent, expected_uid: u32) -> Result<(), StateError> {
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
fn configure(connection: &Connection) -> Result<(), StateError> {
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

/// Applies pending migrations in order inside one IMMEDIATE transaction.
pub(crate) fn run_migrations(connection: &mut Connection) -> Result<(), StateError> {
    let current: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(StateError::database)?;

    if current < 0 {
        return Err(StateError::SchemaVersionInvalid(current));
    }
    let supported = supported_version();
    if current > supported {
        return Err(StateError::SchemaTooNew {
            found: current,
            supported,
        });
    }

    let pending: Vec<&Migration> = MIGRATIONS
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

/// Confirms the structural singleton invariants after migration.
fn enforce_singleton(connection: &Connection) -> Result<(), StateError> {
    for table in ["installation", "convergence_state"] {
        let rows: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .map_err(StateError::database)?;
        if rows > 1 {
            return Err(StateError::IntegrityCheckFailed);
        }
    }
    Ok(())
}

/// Creates the singleton rows for a freshly initialized store.
pub(crate) fn seed_installation(
    connection: &Connection,
    installation_id: &crate::domain::InstallationId,
    generation: crate::domain::DesiredGeneration,
) -> Result<(), StateError> {
    let now = now_seconds();
    connection
        .execute(
            "INSERT INTO installation
                 (singleton, installation_id, desired_generation, created_at, updated_at)
             VALUES (1, ?1, ?2, ?3, ?3)",
            rusqlite::params![installation_id.to_string(), generation.to_storage(), now],
        )
        .and_then(|_| {
            connection.execute(
                "INSERT INTO convergence_state
                     (singleton, last_attempted_generation, last_converged_generation,
                      last_attempt_timestamp, last_outcome)
                 VALUES (1, NULL, NULL, NULL, NULL)",
                [],
            )
        })
        .map_err(StateError::database)?;
    Ok(())
}

/// Current wall-clock seconds since the Unix epoch.
///
/// Recorded for operator diagnostics only; it never participates in ordering or
/// correctness decisions.
pub(crate) fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DesiredGeneration;
    use crate::state::store::StateStore;
    use std::{
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
    };

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wg-basic-schema-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }

        fn db(&self) -> PathBuf {
            self.path.join("state.db")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// Opens through the same canonical initializer the store uses, so the
    /// assertions below describe the real production contract.
    fn open_inspection(path: &Path) -> Result<Connection, StateError> {
        open_connection(path, OpenIntent::Reopen, current_test_uid())
    }

    /// A minimal valid snapshot: one present managed interface with one peer.
    fn populated_state() -> crate::domain::DesiredState {
        use crate::domain::{
            ClientId, DesiredInterface, DesiredPeer, DesiredState, InterfaceId, LinkLifecycle,
            NetworkPrefix, OwnershipDeclaration, PeerId, PrivateKey, PublicKey,
        };
        let peer_id = PeerId::new();
        let address: ipnet::IpNet = "10.8.0.2/32".parse().unwrap();
        DesiredState {
            interfaces: vec![DesiredInterface {
                id: InterfaceId::new(),
                name: "wg0".parse().unwrap(),
                ownership: OwnershipDeclaration::Managed,
                lifecycle: LinkLifecycle::Present,
                admin_up: Some(true),
                private_key: PrivateKey::new("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".into())
                    .unwrap(),
                listen_port: Some(51820),
                manage_all_peers: true,
                tunnel_prefixes: vec![NetworkPrefix::new("10.8.0.0/24".parse().unwrap())],
                addresses: Vec::new(),
                routes: Vec::new(),
                peers: vec![DesiredPeer {
                    id: peer_id,
                    public_key: PublicKey::new(
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                    )
                    .unwrap(),
                    private_key: None,
                    preshared_key: None,
                    allowed_ips: vec![NetworkPrefix::new(address)],
                    persistent_keepalive_seconds: None,
                    endpoint: None,
                }],
                clients: vec![crate::domain::DesiredClient {
                    id: ClientId::new(),
                    peer_id,
                    assigned_address: address,
                    route_policy: Default::default(),
                }],
            }],
            client_routes: Default::default(),
            network_policy: None,
        }
    }

    fn current_test_uid() -> u32 {
        std::os::unix::fs::MetadataExt::uid(
            &fs::metadata("/proc/self").expect("effective uid is readable from /proc/self"),
        )
    }

    #[test]
    fn the_opened_database_enforces_the_hardened_pragma_contract() {
        let temp = TempDir::new();
        let store = StateStore::initialize(temp.db()).unwrap();
        drop(store);
        let connection = open_inspection(&temp.db()).unwrap();

        let foreign_keys: i64 = connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1, "foreign key enforcement must be on");

        let trusted_schema: i64 = connection
            .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
            .unwrap();
        assert_eq!(trusted_schema, 0, "trusted_schema must be off");

        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert!(journal_mode.eq_ignore_ascii_case("wal"));

        // `PRAGMA synchronous` reports 0=OFF, 1=NORMAL, 2=FULL.
        let synchronous: i64 = connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(synchronous, 2, "synchronous must be FULL");

        let mmap_size: i64 = connection
            .query_row("PRAGMA mmap_size", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mmap_size, 0, "mmap must be disabled");
    }

    #[test]
    fn extension_loading_is_absent_from_the_dependency_configuration() {
        // rusqlite's `load_extension` feature is deliberately not enabled, so the
        // C extension entry points are not linked at all. This is a build-time
        // guarantee rather than a runtime one.
        let manifest = include_str!("../../Cargo.toml");
        let rusqlite_line = manifest
            .lines()
            .find(|line| line.starts_with("rusqlite"))
            .expect("rusqlite dependency is declared");
        assert!(!rusqlite_line.contains("load_extension"), "{rusqlite_line}");
        assert!(
            rusqlite_line.contains("default-features = false"),
            "extension loading and other default features must stay off: {rusqlite_line}"
        );
    }

    #[test]
    fn migration_zero_to_one_creates_the_initial_schema() {
        let temp = TempDir::new();
        let store = StateStore::initialize(temp.db()).unwrap();
        drop(store);
        let connection = open_inspection(&temp.db()).unwrap();

        let user_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, 1);

        for table in [
            "installation",
            "managed_interfaces",
            "interface_tunnel_prefixes",
            "interface_addresses",
            "managed_routes",
            "peers",
            "peer_allowed_ips",
            "clients",
            "client_route_prefixes",
            "client_global_route_prefixes",
            "network_policy",
            "network_policy_source_prefixes",
            "convergence_state",
        ] {
            let exists: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "migration 1 must create {table}");
        }
    }

    #[test]
    fn a_schema_newer_than_the_binary_is_rejected() {
        let temp = TempDir::new();
        let store = StateStore::initialize(temp.db()).unwrap();
        drop(store);
        let connection = open_inspection(&temp.db()).unwrap();
        connection
            .execute("PRAGMA user_version = 9999", [])
            .unwrap();
        drop(connection);

        assert!(matches!(
            StateStore::open(temp.db()),
            Err(StateError::SchemaTooNew {
                found: 9999,
                supported: 1
            })
        ));
    }

    #[test]
    fn the_schema_contains_no_live_telemetry_columns() {
        let temp = TempDir::new();
        let store = StateStore::initialize(temp.db()).unwrap();
        drop(store);
        let connection = open_inspection(&temp.db()).unwrap();

        let mut statement = connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap();
        let tables: Vec<String> = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let mut columns = Vec::new();
        for table in tables {
            let sql: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE name = ?1",
                    [&table],
                    |row| row.get(0),
                )
                .unwrap();
            columns.push(sql.to_ascii_lowercase());
        }
        let schema = columns.join("\n");

        for forbidden in [
            "handshake",
            "endpoint_observed",
            "rx_bytes",
            "tx_bytes",
            "ifindex",
            "route_handle",
            "nft_handle",
            "counter",
        ] {
            assert!(
                !schema.contains(forbidden),
                "schema must not persist live telemetry column {forbidden}"
            );
        }
    }

    #[test]
    fn foreign_key_constraints_are_rejected_by_sqlite() {
        let temp = TempDir::new();
        let store = StateStore::initialize(temp.db()).unwrap();
        drop(store);
        let connection = open_inspection(&temp.db()).unwrap();

        let result = connection.execute(
        "INSERT INTO peer_allowed_ips (peer_id, prefix, position) VALUES ('missing', '10.0.0.0/8', 0)",
        [],
    );
        assert!(
            result.is_err(),
            "a peer_allowed_ips row for an unknown peer must be refused"
        );
    }

    #[test]
    fn client_dns_servers_are_not_stored_in_a_route_table() {
        let temp = TempDir::new();
        let store = StateStore::initialize(temp.db()).unwrap();
        store
            .mutate(crate::domain::INITIAL_DESIRED_GENERATION, |_| {
                Ok(populated_state())
            })
            .unwrap();
        drop(store);
        let connection = open_inspection(&temp.db()).unwrap();

        let dns_table: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name LIKE '%dns%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            dns_table, 0,
            "DNS has no consumer yet and must not be overloaded"
        );
    }

    #[test]
    fn a_corrupted_generation_value_is_refused_at_both_layers() {
        let temp = TempDir::new();
        let store = StateStore::initialize(temp.db()).unwrap();
        drop(store);
        let connection = open_inspection(&temp.db()).unwrap();

        // Layer one: the schema's own CHECK constraint rejects the invalid value.
        connection
            .execute("UPDATE installation SET desired_generation = 0", [])
            .expect_err("the schema must reject a non-positive generation outright");
        connection
            .execute("UPDATE installation SET desired_generation = -1", [])
            .expect_err("a negative generation must also be refused");

        // Layer two: even if an invalid value somehow reached the column, the
        // reader refuses it rather than treating it as authoritative state.
        assert!(
            DesiredGeneration::from_storage(0).is_none(),
            "the reader must not accept generation 0"
        );
        assert!(DesiredGeneration::from_storage(-1).is_none());
    }
}
