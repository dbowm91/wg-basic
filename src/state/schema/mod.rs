//! Schema contract: the single canonical connection initializer and the
//! structural singleton invariants.
//!
//! Every path that opens the state database goes through [`open_connection`] so
//! the file ownership checks, open flags, and pragmas cannot drift apart. The
//! concerns that initializer depends on are split by subject rather than
//! duplicated:
//!
//! - [`validation`] owns the ownership/permission checks and the hardened
//!   pragma contract, and reads each pragma back rather than assuming it.
//! - [`migrations`] owns the ordered migration runner and the pre-migration
//!   recovery snapshot.
//!
//! What stays here is the opener itself plus the structural invariants only this
//! module can enforce: that `installation` and `convergence_state` each hold
//! exactly one row.

mod migrations;
mod validation;

use super::error::StateError;
use rusqlite::{Connection, OpenFlags};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

/// The highest schema version this binary understands.
///
/// Re-exported so a caller outside this module reads the version through the
/// schema contract rather than reaching into the migration runner.
pub(crate) use migrations::supported_version;

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
    validation::verify_path(path, intent, expected_uid)?;

    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    flags |= OpenFlags::SQLITE_OPEN_NOFOLLOW;
    if intent == OpenIntent::Initialize {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }

    let mut connection =
        Connection::open_with_flags(path, flags).map_err(|_| StateError::DatabaseOpenFailed)?;

    validation::configure(&connection)?;
    let starting_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(StateError::database)?;
    migrations::recovery_snapshot(&connection, path, starting_version, supported_version())?;
    migrations::run_migrations(&mut connection)?;
    Ok(connection)
}

/// Applies the hardened connection contract without running any migration.
///
/// Exists only so a test can populate a genuine historical database *before*
/// something upgrades it. Every production path migrates on open, which is what
/// `open_connection` does.
#[cfg(test)]
pub(crate) fn open_connection_without_migrating(
    path: &Path,
    expected_uid: u32,
) -> Result<Connection, StateError> {
    // Every check `open_connection` performs is still performed here; only the
    // snapshot-and-migrate tail is skipped.
    validation::verify_path(path, OpenIntent::Reopen, expected_uid)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| StateError::DatabaseOpenFailed)?;
    validation::configure(&connection)?;
    Ok(connection)
}

/// Applies the read side of the connection contract without migrating.
///
/// A restore validates a private staging copy that it owns, so it must apply
/// the hardened pragmas but must not itself run migrations: migration runs once,
/// later, through the normal store opener after the file is in place.
pub(crate) fn configure_for_restore(connection: &Connection) -> Result<(), StateError> {
    validation::configure(connection)
}

/// Confirms the structural singleton invariants.
///
/// Each of these tables must hold **exactly one** row. More than one means the
/// database is not the store this binary expects; zero means the installation
/// identity is missing, which must fail closed rather than produce a store that
/// opens successfully and is then unusable. Both are treated as corruption.
pub(crate) fn enforce_singleton(connection: &Connection) -> Result<(), StateError> {
    for table in ["installation", "convergence_state"] {
        let rows: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .map_err(StateError::database)?;
        if rows != 1 {
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
    use super::migrations::{
        apply_migrations, initialize_at_version, recovery_snapshot, recovery_snapshot_path,
        MIGRATIONS,
    };
    use super::validation::DATABASE_MODE;
    use super::*;
    use crate::domain::DesiredGeneration;
    use crate::state::store::StateStore;
    use std::{fs, os::unix::fs::MetadataExt};
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
        let manifest = include_str!("../../../Cargo.toml");
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
    fn migration_zero_to_head_creates_every_schema() {
        let temp = TempDir::new();
        let store = StateStore::initialize(temp.db()).unwrap();
        drop(store);
        let connection = open_inspection(&temp.db()).unwrap();

        let user_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, migrations::supported_version());
        assert_eq!(
            user_version, 4,
            "a fresh database is created at the current head, never behind it"
        );

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
            "interface_product_settings",
            "client_product_settings",
            "client_dns_servers",
            "audit_events",
        ] {
            let exists: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "the schema at head must create {table}");
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
                supported: 4
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
    fn dns_is_stored_in_its_own_table_and_never_overloaded_into_routes() {
        let temp = TempDir::new();
        let store = StateStore::initialize(temp.db()).unwrap();
        store
            .mutate(crate::domain::INITIAL_DESIRED_GENERATION, |_| {
                Ok(populated_state())
            })
            .unwrap();
        drop(store);
        let connection = open_inspection(&temp.db()).unwrap();

        // Phase 7 forbade a DNS *column* anywhere, because at that time nothing
        // consumed DNS and any column would have had to be smuggled into an
        // existing route structure. Phase 8 M001 gives DNS a consumer and a
        // dedicated `client_dns_servers` table instead, which is the resolution
        // of that concern rather than a retreat from it.
        let dns_table: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name LIKE '%dns%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            dns_table, 1,
            "DNS must have exactly one dedicated table, never a shared one"
        );

        // The invariant that actually mattered is that DNS never borrows the
        // route/AllowedIP tables: a DNS server is not a route, and encoding one
        // as a prefix would make it indistinguishable from real tunnel traffic
        // to every consumer, including the kernel-facing ones.
        for table in [
            "client_route_prefixes",
            "client_global_route_prefixes",
            "peer_allowed_ips",
            "interface_tunnel_prefixes",
            "managed_routes",
        ] {
            let columns: Vec<String> = {
                let mut statement = connection
                    .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
                    .unwrap();
                let rows = statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                rows
            };
            for column in columns {
                assert!(
                    !column.to_ascii_lowercase().contains("dns"),
                    "{table}.{column} would overload a route table with DNS"
                );
            }
        }

        // And the dedicated table must not smuggle routes back the other way.
        let dns_columns: Vec<String> = {
            let mut statement = connection
                .prepare("SELECT name FROM pragma_table_info('client_dns_servers')")
                .unwrap();
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        for column in dns_columns {
            assert!(
                !column.to_ascii_lowercase().contains("prefix")
                    && !column.to_ascii_lowercase().contains("route"),
                "client_dns_servers.{column} would store a route, not a resolver"
            );
        }
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

    /// Builds a genuine version-1 database from the production migration list.
    ///
    /// Since Phase 7 M002 added migration 2 and Phase 8 M001 added migration 3,
    /// this is a real historical schema: exactly what a user who installed
    /// wg-basic during Phase 6 would still have on disk. It is no longer a
    /// simulation.
    fn historical_v1(temp: &TempDir) {
        migrations::initialize_at_version(&temp.db(), 1).expect("historical v1 fixture");
    }

    /// `PRAGMA user_version` for a raw connection, for the migration fixtures.
    fn user_version_of(connection: &Connection) -> i64 {
        connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("user_version is readable")
    }

    /// Commits a real typed snapshot into the historical file and returns the
    /// equivalent desired state with the installation identity, so a later step
    /// can compare it against the upgrade.
    ///
    /// The rows are seeded with plain SQL rather than through `StateStore::mutate`,
    /// and that is the point: `mutate` writes the Phase 8 product tables, which do
    /// not exist in a version-1 file, so it cannot be the tool that fills one. A
    /// genuine historical database was written by a binary that had never heard of
    /// those tables, and seeding it that way is what makes "the upgrade preserved
    /// the data" a claim about an older writer's rows rather than about this one.
    fn commit_snapshot_at_v2(
        temp: &TempDir,
    ) -> (crate::domain::InstallationId, crate::domain::DesiredState) {
        use crate::domain::{ClientId, InterfaceId, PeerId};

        let interface_id = InterfaceId::new();
        let peer_id = PeerId::new();
        let client_id = ClientId::new();
        let connection = Connection::open(temp.db()).unwrap();
        connection
            .execute_batch(&format!(
                "INSERT INTO managed_interfaces
                     (id, name, ownership, lifecycle, admin_up, private_key,
                      listen_port, manage_all_peers, position)
                 VALUES ('{interface_id}', 'wg0', 'managed', 'present', 1,
                         'yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=', 51820, 1, 0);
                 INSERT INTO interface_tunnel_prefixes (interface_id, prefix, position)
                 VALUES ('{interface_id}', '10.8.0.0/24', 0);
                 INSERT INTO peers
                     (id, interface_id, public_key, private_key, preshared_key,
                      persistent_keepalive_seconds, endpoint, position)
                 VALUES ('{peer_id}', '{interface_id}',
                         'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', NULL, NULL, NULL, NULL, 0);
                 INSERT INTO peer_allowed_ips (peer_id, prefix, position)
                 VALUES ('{peer_id}', '10.8.0.2/32', 0);
                 INSERT INTO clients (id, interface_id, peer_id, assigned_address, position)
                 VALUES ('{client_id}', '{interface_id}', '{peer_id}', '10.8.0.2/32', 0);
                 UPDATE installation SET desired_generation = 2 WHERE singleton = 1;"
            ))
            .expect("seed a genuine version-1 snapshot");

        let identity: crate::domain::InstallationId = connection
            .query_row(
                "SELECT installation_id FROM installation WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
            .parse()
            .unwrap();
        connection.close().unwrap();

        let store = StateStore::open_without_migrating(temp.db()).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.generation, DesiredGeneration::new(2).unwrap());
        assert_eq!(loaded.state.interfaces.len(), 1);
        drop(store);

        (identity, loaded.state)
    }

    /// Applies the real production upgrade from version 1 to the current head.
    ///
    /// This is no longer simulated: it runs `MIGRATIONS`, the same list the
    /// production opener runs, against a genuine version-1 file. No re-stamping
    /// is needed because the resulting version is one this binary supports.
    fn apply_production_upgrade(temp: &TempDir) {
        let mut connection = Connection::open(temp.db()).unwrap();
        migrations::apply_migrations(&mut connection, MIGRATIONS).unwrap();
        assert_eq!(
            user_version_of(&connection),
            migrations::supported_version()
        );
        connection.close().unwrap();
    }

    #[test]
    fn the_runner_upgrades_a_historical_fixture_to_the_latest_version() {
        let temp = TempDir::new();
        historical_v1(&temp);
        let (identity, _) = commit_snapshot_at_v2(&temp);

        let mut connection = Connection::open(temp.db()).expect("open the historical fixture");
        assert_eq!(
            user_version_of(&connection),
            1,
            "the fixture must start at the historical boundary"
        );

        migrations::apply_migrations(&mut connection, MIGRATIONS).unwrap();
        assert_eq!(user_version_of(&connection), 4);

        // Every version the upgrade ran through must actually have created its
        // schema.
        for table in [
            "admin_principals",
            "admin_sessions",
            "interface_product_settings",
            "client_product_settings",
            "client_dns_servers",
            "audit_events",
            "enrollment_capabilities",
        ] {
            let exists: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "{table} must exist after the upgrade");
        }

        let stored_identity: String = connection
            .query_row(
                "SELECT installation_id FROM installation WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_identity, identity.to_string());
        connection.close().unwrap();

        // The production opener must accept the migrated file: version 4 is one
        // this binary actually supports, so refusing it would be a false alarm.
        StateStore::open(temp.db())
            .expect("a migrated database must open through the production path");
    }

    #[test]
    fn an_upgrade_preserves_installation_identity_and_typed_state() {
        let temp = TempDir::new();
        historical_v1(&temp);
        let (identity, expected) = commit_snapshot_at_v2(&temp);

        apply_production_upgrade(&temp);

        let store = StateStore::open(temp.db()).unwrap();
        let metadata = store.installation_metadata().unwrap();
        let loaded = store.load().unwrap();

        assert_eq!(
            metadata.installation_id, identity,
            "an upgrade must never mint a new installation identity"
        );
        assert_eq!(
            metadata.desired_generation,
            DesiredGeneration::new(2).unwrap(),
            "an upgrade must not advance or rewind the desired generation"
        );
        assert_eq!(
            loaded.generation,
            DesiredGeneration::new(2).unwrap(),
            "the committed generation must survive the upgrade"
        );
        assert_eq!(
            loaded.state, expected,
            "the typed desired state must survive the upgrade unchanged"
        );
    }

    #[test]
    fn a_schema_newer_than_the_binary_is_refused_rather_than_downgraded() {
        let temp = TempDir::new();
        historical_v1(&temp);

        // The production list stops at version 4, so a database stamped 5 comes
        // from a future binary.
        let connection = Connection::open(temp.db()).unwrap();
        connection.execute("PRAGMA user_version = 5", []).unwrap();
        drop(connection);

        let mut connection = Connection::open(temp.db()).unwrap();
        let error = apply_migrations(&mut connection, MIGRATIONS).unwrap_err();
        assert!(
            matches!(
                error,
                StateError::SchemaTooNew {
                    found: 5,
                    supported: 4
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn foreign_keys_are_checked_after_every_migration_step() {
        let temp = TempDir::new();
        migrations::initialize_at_version(&temp.db(), 1).unwrap();
        let mut connection = Connection::open(temp.db()).unwrap();

        // Introduce a dangling client row that violates the declared relation.
        connection
            .execute_batch(
                "PRAGMA foreign_keys = OFF;
                 INSERT INTO clients
                     (id, interface_id, peer_id, assigned_address, position)
                 VALUES ('00000000-0000-4000-8000-000000000001',
                         '00000000-0000-4000-8000-0000000000aa',
                         '00000000-0000-4000-8000-0000000000ff',
                         '10.8.0.9/32', 0);",
            )
            .expect("seed a dangling client row");

        let error = apply_migrations(&mut connection, MIGRATIONS).unwrap_err();
        assert!(
            matches!(error, StateError::MigrationFailed { version: 2, .. }),
            "a foreign-key violation must fail the migration: {error:?}"
        );
    }

    #[test]
    fn a_pre_migration_snapshot_is_taken_before_a_schema_change() {
        let temp = TempDir::new();
        migrations::initialize_at_version(&temp.db(), 1).unwrap();
        let connection = Connection::open(temp.db()).unwrap();
        let expected = recovery_snapshot_path(&temp.db(), 1);

        recovery_snapshot(&connection, &temp.db(), 1, 2).unwrap();

        let metadata = fs::symlink_metadata(&expected).expect("snapshot must exist");
        assert!(metadata.is_file());
        assert_eq!(
            metadata.mode() & 0o777,
            DATABASE_MODE,
            "a recovery snapshot holds the same secrets as the database"
        );

        // The snapshot must correspond to the *pre-migration* schema.
        let snapshot = Connection::open_with_flags(
            &expected,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        assert_eq!(user_version_of(&snapshot), 1);
    }

    #[test]
    fn no_snapshot_is_taken_when_there_is_nothing_to_migrate() {
        let temp = TempDir::new();
        let connection = Connection::open({
            initialize_at_version(&temp.db(), 1).unwrap();
            temp.db()
        })
        .unwrap();

        // Already current: no migration is pending, so no snapshot.
        recovery_snapshot(&connection, &temp.db(), 1, 1).unwrap();
        assert!(!recovery_snapshot_path(&temp.db(), 1).exists());

        // Brand-new initialization (version 0) has nothing to lose.
        recovery_snapshot(&connection, &temp.db(), 0, 2).unwrap();
        assert!(!recovery_snapshot_path(&temp.db(), 0).exists());
    }

    #[test]
    fn a_snapshot_name_is_deterministic_and_documented() {
        assert_eq!(
            recovery_snapshot_path(Path::new("/var/lib/wg-basic/state.db"), 1),
            PathBuf::from("/var/lib/wg-basic/state.db.pre-migration-v1")
        );
    }
}
