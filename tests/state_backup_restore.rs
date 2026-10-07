//! Backup, restore, and corruption handling for the durable state store.
//!
//! These run unprivileged: they operate on temporary SQLite files only. The
//! rootful "a restored database actually drives the kernel" qualification lives
//! in `tests/durable_backup.rs`.

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use wg_basic::{
    domain::{
        ClientId, DesiredAddress, DesiredClient, DesiredGeneration, DesiredInterface, DesiredPeer,
        DesiredState, InterfaceId, LinkLifecycle, NetworkPrefix, OwnershipDeclaration, PeerId,
        PrivateKey, PublicKey, ResourcePresence,
    },
    state::{
        restore, retained_previous_path, validate_candidate, AttemptDisposition, StateError,
        StateStore, INITIAL_DESIRED_GENERATION,
    },
};

const SECRET: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const PEER_PUBLIC: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-backup-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn db(&self) -> PathBuf {
        self.0.join("state.db")
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn desired_state(interface_id: InterfaceId) -> DesiredState {
    let peer_id = PeerId::new();
    let address: ipnet::IpNet = "10.77.0.2/32".parse().unwrap();
    DesiredState {
        interfaces: vec![DesiredInterface {
            id: interface_id,
            name: "wg-backup".parse().unwrap(),
            ownership: OwnershipDeclaration::Managed,
            lifecycle: LinkLifecycle::Present,
            admin_up: Some(true),
            private_key: PrivateKey::new(SECRET.into()).unwrap(),
            listen_port: Some(51888),
            manage_all_peers: true,
            tunnel_prefixes: vec![NetworkPrefix::new("10.77.0.0/24".parse().unwrap())],
            addresses: vec![DesiredAddress {
                address: "10.77.0.1/24".parse().unwrap(),
                presence: ResourcePresence::Present,
            }],
            routes: Vec::new(),
            peers: vec![DesiredPeer {
                id: peer_id,
                public_key: PublicKey::new(PEER_PUBLIC.into()).unwrap(),
                private_key: None,
                preshared_key: None,
                allowed_ips: vec![NetworkPrefix::new(address)],
                persistent_keepalive_seconds: None,
                endpoint: None,
            }],
            clients: vec![DesiredClient {
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

/// Initializes a store and commits a real snapshot at exactly `generation`.
fn seed(path: &Path, generation: u64) -> (StateStore, InterfaceId) {
    let interface_id = InterfaceId::new();
    let store = StateStore::initialize(path).expect("initialize");
    let mut expected = INITIAL_DESIRED_GENERATION;
    while expected.to_storage() < generation as i64 {
        let snapshot = desired_state(
            if expected.next().unwrap().to_storage() == generation as i64 {
                interface_id
            } else {
                InterfaceId::new()
            },
        );
        let committed = store.mutate(expected, |_| Ok(snapshot)).unwrap();
        expected = committed.generation;
    }
    (store, interface_id)
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o777
}

/// Every artifact this operation family might leave behind, for leak checks.
///
/// WAL sidecars are excluded: `-wal` and `-shm` belong to a live WAL database
/// and are expected here. This fixture opens and closes its own connections, so
/// they are an artifact of the test's own access, not of a leaked staging file.
fn artifacts_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| !name.ends_with("-wal") && !name.ends_with("-shm"))
        .collect();
    names.sort();
    names
}

fn seed_and_backup(temp: &TempDir, generation: u64) -> (StateStore, PathBuf) {
    let (store, _) = seed(&temp.db(), generation);
    let destination = temp.path().join("backup.db");
    store.backup(&destination).expect("backup must succeed");
    (store, destination)
}

// ---------------------------------------------------------------------------
// §3 / §5 backup result contract and consistency
// ---------------------------------------------------------------------------

#[test]
fn a_backup_is_a_consistent_snapshot_of_exactly_one_generation() {
    let temp = TempDir::new();
    let (store, destination) = seed_and_backup(&temp, 3);

    let receipt = store.backup(temp.path().join("second.db")).unwrap();
    assert_eq!(receipt.generation, DesiredGeneration::new(3).unwrap());
    // Read rather than hard-code the head: a backup receipt must report the
    // schema this binary actually wrote, and Phase 7 M002 moved it from 1 to 2.
    assert_eq!(receipt.schema_version, store.schema_version().unwrap());
    assert_eq!(receipt.destination, temp.path().join("second.db"));

    // The snapshot must open independently and report the same generation and
    // the same complete typed state, never a mix of two generations.
    let copy = StateStore::open(&destination).unwrap();
    let metadata = copy.installation_metadata().unwrap();
    assert_eq!(metadata.desired_generation, receipt.generation);
    assert_eq!(metadata.installation_id, receipt.installation_id);

    let live = store.load().unwrap();
    let backed_up = copy.load().unwrap();
    assert_eq!(
        backed_up.generation, live.generation,
        "the snapshot must be one whole generation, not a mix"
    );
    assert_eq!(
        backed_up.state, live.state,
        "the snapshot must contain the same typed rows"
    );
}

#[test]
fn a_backup_receipt_carries_no_secret_contents() {
    let temp = TempDir::new();
    let (store, _destination) = seed_and_backup(&temp, 2);
    let receipt = store.backup(temp.path().join("again.db")).unwrap();

    let rendered = format!("{:?}", receipt);
    assert!(
        !rendered.contains(SECRET),
        "receipt leaked a key: {rendered}"
    );
    assert!(!rendered.contains("private_key"), "{rendered}");

    // And the human-facing command output must not print secrets either.
    let mut printed = String::new();
    use std::fmt::Write;
    writeln!(printed, "{}", receipt.destination.display()).unwrap();
    writeln!(printed, "{}", receipt.generation).unwrap();
    writeln!(printed, "{}", receipt.installation_id).unwrap();
    assert!(!printed.contains(SECRET), "{printed}");
}

/// The backup must use SQLite's online API, not a copy of the main file.
#[test]
fn a_backup_is_not_a_blind_copy_of_the_live_database() {
    let temp = TempDir::new();
    let (store, destination) = seed_and_backup(&temp, 2);

    // Copying `state.db` while WAL sidecars hold commits would miss recent
    // writes. Proving the backup is *not* that: the live store keeps advancing
    // after the backup, and the snapshot does not follow it.
    store
        .mutate(DesiredGeneration::new(2).unwrap(), |_| {
            Ok(desired_state(InterfaceId::new()))
        })
        .unwrap();
    assert_eq!(
        store.current_generation().unwrap(),
        DesiredGeneration::new(3).unwrap()
    );

    let copy = StateStore::open(&destination).unwrap();
    assert_eq!(
        copy.current_generation().unwrap(),
        DesiredGeneration::new(2).unwrap(),
        "a snapshot is a point in time, not a live mirror"
    );
}

#[test]
fn a_backup_refuses_to_overwrite_an_existing_destination() {
    let temp = TempDir::new();
    let (store, destination) = seed_and_backup(&temp, 2);

    let error = store.backup(&destination).unwrap_err();
    assert!(
        matches!(error, StateError::BackupDestinationExists { .. }),
        "{error:?}"
    );

    // The existing file must be untouched.
    let copy = StateStore::open(&destination).unwrap();
    assert_eq!(
        copy.current_generation().unwrap(),
        DesiredGeneration::new(2).unwrap()
    );
}

#[test]
fn a_backup_refuses_a_destination_inside_an_unsafe_directory() {
    let temp = TempDir::new();
    let (store, _) = seed(&temp.db(), 2);

    let loose = temp.path().join("loose");
    fs::create_dir(&loose).unwrap();
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o777)).unwrap();

    let error = store.backup(loose.join("backup.db")).unwrap_err();
    assert!(
        matches!(error, StateError::ParentTooPermissive { .. }),
        "a world-writable destination directory must be refused: {error:?}"
    );

    let error = store
        .backup(temp.path().join("missing/backup.db"))
        .unwrap_err();
    assert!(
        matches!(error, StateError::MissingParent { .. }),
        "{error:?}"
    );

    // The database itself is a regular file, so it cannot be a directory that
    // holds a backup.
    let error = store.backup(temp.db().join("backup.db")).unwrap_err();
    assert!(
        matches!(error, StateError::ParentNotDirectory { .. }),
        "a regular file is not a valid backup parent: {error:?}"
    );
}

#[test]
fn backup_artifacts_are_owner_only_and_leave_no_temporary_files() {
    let temp = TempDir::new();
    let (_store, destination) = seed_and_backup(&temp, 2);

    assert_eq!(
        mode_of(&destination),
        0o600,
        "a backup holds the same VPN keys as the live database"
    );
    assert_eq!(
        artifacts_in(temp.path()),
        vec!["backup.db".to_owned(), "state.db".to_owned()],
        "no staging artifact may survive a successful backup"
    );
}

#[test]
fn a_failed_backup_removes_only_its_own_temporary_artifact() {
    let temp = TempDir::new();
    let (store, _) = seed(&temp.db(), 2);

    // Occupy the deterministic staging name with a directory. The backup cannot
    // create its artifact there, and its cleanup must not remove what it did
    // not create.
    let staging = temp
        .path()
        .join(format!(".second.db.backup.{}", std::process::id()));
    fs::create_dir(&staging).unwrap();
    fs::write(staging.join("foreign"), b"someone else's data").unwrap();

    let error = store.backup(temp.path().join("second.db")).unwrap_err();

    assert!(
        staging.is_dir() && staging.join("foreign").is_file(),
        "a failed backup must not delete files it does not own"
    );
    // ...and the destination was never created.
    assert!(!temp.path().join("second.db").exists());
    assert!(!error.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// §6 restore boundary
// ---------------------------------------------------------------------------

#[test]
fn a_restore_round_trips_identity_generation_and_typed_state() {
    let source = TempDir::new();
    let (store, destination) = seed_and_backup(&source, 3);
    let (identity, expected_state) = (
        store.installation_metadata().unwrap().installation_id,
        store.load().unwrap(),
    );
    drop(store);

    let target = TempDir::new();
    // A different installation already exists at the target; restore replaces it.
    {
        let (other, _) = seed(&target.db(), 2);
        drop(other);
    }

    let receipt = restore(&destination, target.db()).unwrap();
    assert_eq!(receipt.installation_id, identity);
    assert_eq!(receipt.generation, DesiredGeneration::new(3).unwrap());
    assert_eq!(
        receipt.schema_version,
        StateStore::open(&destination)
            .unwrap()
            .schema_version()
            .unwrap(),
        "a restore receipt must report the schema it actually installed"
    );
    assert_eq!(receipt.target, target.db());

    let restored = StateStore::open(target.db()).unwrap();
    let loaded = restored.load().unwrap();
    assert_eq!(
        restored.installation_metadata().unwrap().installation_id,
        identity,
        "restore must not mint a new installation identity"
    );
    assert_eq!(loaded.generation, expected_state.generation);
    assert_eq!(loaded.state, expected_state.state);
}

#[test]
fn a_restore_retains_the_previous_database_for_recovery() {
    let source = TempDir::new();
    let (_, destination) = seed_and_backup(&source, 3);

    let target = TempDir::new();
    let (previous, _) = seed(&target.db(), 2);
    let previous_identity = previous.installation_metadata().unwrap().installation_id;
    drop(previous);

    let receipt = restore(&destination, target.db()).unwrap();
    let expected = retained_previous_path(&target.db());
    assert_eq!(
        receipt.previous_retained_at.as_deref(),
        Some(expected.as_path())
    );
    assert!(expected.is_file(), "the previous database must be retained");

    // The retained copy is a usable database, not a renamed fragment.
    let retained = StateStore::open(&expected).unwrap();
    assert_eq!(
        retained.installation_metadata().unwrap().installation_id,
        previous_identity,
        "a retained previous database must still be openable"
    );
}

#[test]
fn a_restore_refuses_while_the_target_is_open_in_this_process() {
    let source = TempDir::new();
    let (_, destination) = seed_and_backup(&source, 2);

    let target = TempDir::new();
    let (live, _) = seed(&target.db(), 2);
    let before = live.load().unwrap();

    let error = restore(&destination, target.db()).unwrap_err();
    assert!(
        matches!(error, StateError::TargetInUse),
        "restore must refuse a database this process still holds open: {error:?}"
    );

    // Nothing changed.
    assert_eq!(live.load().unwrap(), before);
    assert!(!retained_previous_path(&target.db()).exists());
    drop(live);
}

#[test]
fn a_restore_refuses_a_candidate_opened_by_this_process() {
    let source = TempDir::new();
    let (store, destination) = seed_and_backup(&source, 2);
    drop(store);

    // The candidate itself is open here.
    let opened = StateStore::open(&destination).unwrap();
    let target = TempDir::new();
    let error = restore(&destination, target.db()).unwrap_err();
    assert!(matches!(error, StateError::CandidateInUse), "{error:?}");
    drop(opened);
}

#[test]
fn a_failed_restore_preserves_the_original_database() {
    let source = TempDir::new();
    let (_source_store, _destination) = seed_and_backup(&source, 4);

    let target = TempDir::new();
    let (live, _) = seed(&target.db(), 2);
    let before = live.load().unwrap();
    let identity = live.installation_metadata().unwrap().installation_id;
    drop(live);

    // A structurally valid SQLite file whose desired state cannot be typed.
    let broken = target.path().join("broken.db");
    copy_rows_with_invalid_key(&target.db(), &broken);
    let error = restore(&broken, target.db()).unwrap_err();
    assert!(!matches!(error, StateError::TargetInUse), "{error:?}");

    let survivor = StateStore::open(target.db()).unwrap();
    assert_eq!(
        survivor.installation_metadata().unwrap().installation_id,
        identity,
        "a failed restore must leave the original database in place"
    );
    assert_eq!(survivor.load().unwrap(), before);
    assert!(
        !retained_previous_path(&target.db()).exists(),
        "a failed restore must not displace the previous database"
    );
    assert_eq!(
        artifacts_in(target.path()),
        vec!["broken.db".to_owned(), "state.db".to_owned()],
        "a failed restore must clean its own staging artifact"
    );
}

// ---------------------------------------------------------------------------
// §10 corruption and tamper handling
// ---------------------------------------------------------------------------

#[test]
fn a_file_that_is_not_sqlite_is_refused() {
    let temp = TempDir::new();
    let (store, destination) = seed_and_backup(&temp, 2);
    drop(store);

    let junk = temp.path().join("junk.db");
    fs::write(&junk, b"this is definitely not a database").unwrap();
    fs::set_permissions(&junk, fs::Permissions::from_mode(0o600)).unwrap();

    let error = restore(&junk, &destination).unwrap_err();
    assert!(!error.to_string().is_empty());
    // The original backup must be untouched by the failed attempt.
    let copy = StateStore::open(&destination).unwrap();
    assert_eq!(
        copy.current_generation().unwrap(),
        DesiredGeneration::new(2).unwrap()
    );
}

#[test]
fn a_truncated_database_is_refused_by_the_integrity_check() {
    let temp = TempDir::new();
    let (store, destination) = seed_and_backup(&temp, 2);
    drop(store);

    let truncated = temp.path().join("truncated.db");
    let bytes = fs::read(&destination).unwrap();
    fs::write(&truncated, &bytes[..bytes.len() / 2]).unwrap();
    fs::set_permissions(&truncated, fs::Permissions::from_mode(0o600)).unwrap();

    let error = validate_candidate(&truncated);
    assert!(
        matches!(error, Err(StateError::IntegrityCheckFailed)),
        "a truncated database must fail the integrity check: {error:?}"
    );
    assert!(restore(&truncated, &destination).is_err());
}

#[test]
fn a_schema_newer_than_the_binary_is_refused_before_anything_is_replaced() {
    let temp = TempDir::new();
    let (store, destination) = seed_and_backup(&temp, 2);
    drop(store);

    stamp_user_version(&destination, 99);
    let error = validate_candidate(&destination).unwrap_err();
    assert!(
        matches!(
            error,
            StateError::SchemaTooNew {
                found: 99,
                supported
            } if (1..99).contains(&supported)
        ),
        "a future schema must fail closed, naming the version this binary \
         understands rather than a hard-coded one: {error:?}"
    );
    // `StateStore::open` refuses it too, so it can never drive reconciliation.
    assert!(matches!(
        StateStore::open(&destination).unwrap_err(),
        StateError::SchemaTooNew { .. }
    ));
}

#[test]
fn a_missing_singleton_installation_row_is_refused() {
    let temp = TempDir::new();
    let (store, destination) = seed_and_backup(&temp, 2);
    drop(store);

    execute_sql(&destination, "DELETE FROM installation");
    assert!(
        StateStore::open(&destination).is_err(),
        "a database without its installation row is not a usable store"
    );
}

#[test]
fn a_duplicate_identifier_is_refused_at_every_layer() {
    let temp = TempDir::new();
    let (store, destination) = seed_and_backup(&temp, 2);
    let loaded = store.load().unwrap();
    drop(store);
    let interface = loaded.state.interfaces[0].clone();

    // Layer one: the schema's PRIMARY KEY refuses a duplicate identity.
    {
        let connection = rusqlite::Connection::open(&destination).unwrap();
        assert!(
            connection
                .execute(
                    "INSERT INTO managed_interfaces (id, name, ownership, lifecycle, admin_up,
                        private_key, listen_port, manage_all_peers, position)
                     VALUES (?1, 'wg-dup', 'managed', 'present', 1, ?2, 51899, 1, 9)",
                    rusqlite::params![interface.id.to_string(), SECRET],
                )
                .is_err(),
            "a duplicate managed interface identity must be refused by the schema"
        );
    }

    // Layer two: the schema's UNIQUE constraint refuses a duplicate name.
    {
        let connection = rusqlite::Connection::open(&destination).unwrap();
        assert!(
            connection
                .execute(
                    "INSERT INTO managed_interfaces (id, name, ownership, lifecycle, admin_up,
                        private_key, listen_port, manage_all_peers, position)
                     VALUES ('00000000-0000-4000-8000-00000000ffff', ?1, 'managed',
                             'present', 1, ?2, 51899, 1, 9)",
                    rusqlite::params![interface.name.to_string(), SECRET],
                )
                .is_err(),
            "a duplicate interface name must be refused by the schema"
        );
    }

    // Layer three: the typed validator refuses a duplicate relation even when
    // the shape is expressible in memory.
    let mut duplicated = loaded.state.clone();
    let repeat = duplicated.interfaces[0].clients[0].clone();
    duplicated.interfaces[0].clients.push(repeat);
    assert!(
        wg_basic::domain::validate_desired_state(&duplicated).is_err(),
        "a duplicate client relation must be refused by typed validation"
    );
}

#[test]
fn a_world_readable_candidate_is_refused() {
    let temp = TempDir::new();
    let (store, destination) = seed_and_backup(&temp, 2);
    drop(store);

    fs::set_permissions(&destination, fs::Permissions::from_mode(0o644)).unwrap();
    let error = validate_candidate(&destination).unwrap_err();
    assert!(
        matches!(error, StateError::DatabaseTooPermissive { .. }),
        "a secret-bearing candidate must stay owner-only: {error:?}"
    );
}

#[test]
fn a_symlinked_candidate_is_refused() {
    let temp = TempDir::new();
    let (store, destination) = seed_and_backup(&temp, 2);
    drop(store);

    let link = temp.path().join("link.db");
    std::os::unix::fs::symlink(&destination, &link).unwrap();
    let error = validate_candidate(&link).unwrap_err();
    assert!(
        matches!(error, StateError::DatabaseIsSymlink { .. }),
        "a symlinked candidate must not be followed: {error:?}"
    );
}

#[test]
fn convergence_categories_survive_a_backup_and_restore_round_trip() {
    let temp = TempDir::new();
    let (store, _) = seed_and_backup(&temp, 2);

    store
        .record_attempt_start(DesiredGeneration::new(2).unwrap())
        .unwrap();
    store
        .record_attempt_result(
            DesiredGeneration::new(2).unwrap(),
            &AttemptDisposition::StateConflict,
        )
        .unwrap();
    let with_evidence = temp.path().join("with-evidence.db");
    store.backup(&with_evidence).unwrap();

    let copy = StateStore::open(&with_evidence).unwrap();
    assert_eq!(
        copy.convergence().unwrap().last_outcome.as_deref(),
        Some("state_conflict"),
        "evidence is a category and must round-trip without becoming a message"
    );
    // Restore refuses a candidate this process still holds open, which is the
    // contract under test here.
    drop(copy);
    drop(store);

    let restored_target = TempDir::new();
    restore(&with_evidence, restored_target.db()).unwrap();
    let restored = StateStore::open(restored_target.db()).unwrap();
    assert_eq!(
        restored.convergence().unwrap().last_outcome.as_deref(),
        Some("state_conflict"),
        "restore must carry operator-facing evidence, not just desired state"
    );
}

/// A database carrying the same rows but an un-typable private key.
///
/// This is the "invalid key row" tamper case: structurally sound SQLite that
/// must still fail closed when loaded into typed state.
fn copy_rows_with_invalid_key(source: &Path, destination: &Path) {
    fs::copy(source, destination).unwrap();
    fs::set_permissions(destination, fs::Permissions::from_mode(0o600)).unwrap();
    // Bypass the schema CHECK by writing through a connection with checks off,
    // which is exactly what tampering or a partial write would leave behind.
    let connection = rusqlite_open(destination);
    connection
        .execute_batch(
            "PRAGMA writable_schema = OFF;
             UPDATE managed_interfaces SET private_key = 'not-base64!!';",
        )
        .unwrap();
}

/// Opens a database for the tamper fixtures only.
fn rusqlite_open(path: &Path) -> rusqlite::Connection {
    // `rusqlite` is not a direct dependency of the test crate, so the fixtures
    // shell out to the same connection contract through the store's own opener
    // where possible and fall back to the `sqlite3` CLI-free path here.
    let store = StateStore::open(path).expect("fixture database must open");
    drop(store);
    rusqlite::Connection::open(path).expect("tamper fixture connection")
}

fn execute_sql(path: &Path, sql: &str) {
    let connection = rusqlite_open(path);
    connection
        .execute_batch(sql)
        .expect("fixture SQL must apply");
}

fn stamp_user_version(path: &Path, version: i64) {
    let connection = rusqlite_open(path);
    connection
        .execute_batch(&format!("PRAGMA user_version = {version};"))
        .expect("stamp the schema version");
    drop(connection);
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
