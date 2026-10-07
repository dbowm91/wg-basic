//! Durability evidence for the state store under abrupt process termination.
//!
//! These tests make no durability claim they cannot support. They show that an
//! interrupted process leaves a database that reopens cleanly and whose contents
//! are one whole generation rather than a partial write. They do **not** claim
//! hardware power-cut safety: a filesystem or disk that lies about `fsync(2)`
//! is outside the application's control, and no application-level test can
//! detect that. See `docs/state-backup-restore.md`.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
use wg_basic::{
    domain::{
        ClientId, DesiredAddress, DesiredClient, DesiredGeneration, DesiredInterface, DesiredPeer,
        DesiredState, InterfaceId, LinkLifecycle, NetworkPrefix, OwnershipDeclaration, PeerId,
        PrivateKey, PublicKey, ResourcePresence, INITIAL_DESIRED_GENERATION,
    },
    state::{AttemptDisposition, StateError, StateStore},
};

const SECRET: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const PEER_PUBLIC: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// Set on the child so it knows it is the crash worker.
const CRASH_ENV: &str = "WGB_CRASH_CHILD";

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-durability-{}-{}",
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
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn desired_state(interface_id: InterfaceId) -> DesiredState {
    let peer_id = PeerId::new();
    let address: ipnet::IpNet = "10.88.0.2/32".parse().unwrap();
    DesiredState {
        interfaces: vec![DesiredInterface {
            id: interface_id,
            name: "wg-durable".parse().unwrap(),
            ownership: OwnershipDeclaration::Managed,
            lifecycle: LinkLifecycle::Present,
            admin_up: Some(true),
            private_key: PrivateKey::new(SECRET.into()).unwrap(),
            listen_port: Some(51877),
            manage_all_peers: true,
            tunnel_prefixes: vec![NetworkPrefix::new("10.88.0.0/24".parse().unwrap())],
            addresses: vec![DesiredAddress {
                address: "10.88.0.1/24".parse().unwrap(),
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

// ---------------------------------------------------------------------------
// Crash worker
// ---------------------------------------------------------------------------

/// Commits real generations and then dies abruptly, with no unwinding.
///
/// This runs as its own test in the same binary, re-executed as a child
/// process. `abort()` raises `SIGABRT`, so no destructor runs: the connection is
/// not closed cleanly and SQLite gets no chance to checkpoint. Whatever the
/// parent finds afterwards is what a real crash would leave behind.
#[test]
fn crash_worker() {
    let Ok(database) = std::env::var(CRASH_ENV) else {
        // Not the child: nothing to do, and the parent drives the real test.
        return;
    };

    let store = StateStore::open(&database).expect("child must open the store");
    let mut generation = store.current_generation().expect("current generation");
    for _ in 0..8 {
        let snapshot = desired_state(InterfaceId::new());
        let committed = store
            .mutate(generation, |_| Ok(snapshot))
            .expect("child commit must succeed");
        generation = committed.generation;
        store
            .record_attempt_start(generation)
            .expect("child evidence must be recorded");
        store
            .record_attempt_result(generation, &AttemptDisposition::BackendUnavailable)
            .expect("child outcome must be recorded");
    }

    // Die without closing the connection or flushing anything.
    std::process::abort();
}

fn run_crash_worker(database: &Path) {
    let mut child = Command::new(std::env::current_exe().expect("current test binary"))
        .args(["--exact", "crash_worker", "--nocapture", "--test-threads=1"])
        .env(CRASH_ENV, database)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn the crash worker");
    let status = child.wait().expect("the crash worker must terminate");
    assert!(
        !status.success(),
        "the crash worker must die abruptly, got {status}"
    );
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

#[test]
fn an_abrupt_kill_leaves_a_reopenable_database_with_whole_generations() {
    let temp = TempDir::new();

    // Seed generation 2 so the child has a starting point.
    {
        let store = StateStore::initialize(temp.db()).unwrap();
        store
            .mutate(INITIAL_DESIRED_GENERATION, |_| {
                Ok(desired_state(InterfaceId::new()))
            })
            .unwrap();
    }

    run_crash_worker(&temp.db());

    // The database must reopen cleanly after an unclean death.
    let store = StateStore::open(temp.db()).expect("the database must reopen");
    let generation = store.current_generation().unwrap();
    assert!(
        generation > DesiredGeneration::new(2).unwrap(),
        "commits before the crash must survive: {generation}"
    );

    // Whatever survived must be one whole generation, not a partial write.
    let loaded = store.load().expect("the desired snapshot must load");
    assert_eq!(
        loaded.generation, generation,
        "the snapshot and the generation row must agree"
    );
    assert_eq!(loaded.state.interfaces.len(), 1);
    assert!(
        wg_basic::domain::validate_desired_state(&loaded.state).is_ok(),
        "a recovered snapshot must pass typed validation"
    );

    // And the recovered store must still be usable for further work.
    let committed = store
        .mutate(generation, |_| Ok(desired_state(InterfaceId::new())))
        .expect("a recovered store must accept new work");
    assert_eq!(
        committed.generation.to_storage(),
        generation.to_storage() + 1
    );
}

#[test]
fn an_abrupt_kill_does_not_leave_secrets_exposed() {
    let temp = TempDir::new();
    {
        let store = StateStore::initialize(temp.db()).unwrap();
        store
            .mutate(INITIAL_DESIRED_GENERATION, |_| {
                Ok(desired_state(InterfaceId::new()))
            })
            .unwrap();
    }
    run_crash_worker(&temp.db());

    // WAL sidecars hold the same secrets as the database and must not be
    // world-readable just because the process died without closing them.
    for entry in fs::read_dir(&temp.0).unwrap() {
        let path = entry.unwrap().path();
        let mode = std::os::unix::fs::MetadataExt::mode(&fs::symlink_metadata(&path).unwrap());
        assert_eq!(
            mode & 0o777,
            0o600,
            "{} must stay owner-only after a crash",
            path.display()
        );
    }
}

#[test]
fn a_backup_taken_after_a_crash_is_itself_consistent() {
    let temp = TempDir::new();
    {
        let store = StateStore::initialize(temp.db()).unwrap();
        store
            .mutate(INITIAL_DESIRED_GENERATION, |_| {
                Ok(desired_state(InterfaceId::new()))
            })
            .unwrap();
    }
    run_crash_worker(&temp.db());

    let store = StateStore::open(temp.db()).unwrap();
    let destination = temp.0.join("after-crash.db");
    let receipt = store.backup(&destination).unwrap();
    drop(store);

    let copy = StateStore::open(&destination).unwrap();
    assert_eq!(
        copy.current_generation().unwrap(),
        receipt.generation,
        "a backup of a recovered database must be internally consistent"
    );
    assert_eq!(
        std::os::unix::fs::MetadataExt::mode(&fs::symlink_metadata(&destination).unwrap()) & 0o777,
        0o600
    );
}

#[test]
fn the_store_refuses_a_database_whose_singleton_row_is_missing() {
    let temp = TempDir::new();
    {
        let store = StateStore::initialize(temp.db()).unwrap();
        store
            .mutate(INITIAL_DESIRED_GENERATION, |_| {
                Ok(desired_state(InterfaceId::new()))
            })
            .unwrap();
    }

    // A database that lost its installation row must fail closed on open, not
    // open successfully and then be unusable.
    {
        let connection = rusqlite::Connection::open(temp.db()).unwrap();
        connection
            .execute_batch("DELETE FROM installation; DELETE FROM convergence_state;")
            .unwrap();
    }
    fs::set_permissions(temp.db(), fs::Permissions::from_mode(0o600)).unwrap();

    let error = StateStore::open(temp.db()).unwrap_err();
    assert!(
        matches!(error, StateError::IntegrityCheckFailed),
        "a store missing its singleton rows must fail closed: {error:?}"
    );
}
