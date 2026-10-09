//! Phase 7 M002 qualification: real schema v1→v2, credentials, and sessions.
//!
//! M002's central claim is that a *real* production migration exists and that
//! authenticating does not disturb desired state. Both are claims about a file
//! on disk, so the evidence here is built over a genuine version-1 database
//! produced by the production migration runner — not over a fresh store, and not
//! over a simulated schema.
//!
//! Nothing in this file talks HTTP. M002 adds credential and session primitives
//! behind the worker and deliberately adds no route; the HTTP surface is
//! qualified for exactly one route until M003.

use std::sync::Arc;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use wg_basic::{
    domain::{
        check_password_policy, CsrfToken, PasswordVerifier, SessionId, SessionToken,
        SessionTokenDigest, ARGON2ID_PHC_PREFIX, ARGON2_ITERATIONS, ARGON2_MEMORY_KIB,
        ARGON2_PARALLELISM, MIN_PASSWORD_BYTES,
    },
    management::{spawn, AuthService, WorkerClient, WorkerConfig, WorkerStartup},
    state::{SessionRecord, StateStore},
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const PASSWORD: &str = "an administrator password";

/// A self-cleaning scratch directory.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-m002-{}-{}",
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

    fn absent_socket(&self) -> PathBuf {
        self.0.join("no-such-netd.sock")
    }

    /// Builds a genuine version-1 database.
    ///
    /// `StateStore` cannot express "stop at version 1", so the fixture is built
    /// the way the migration runner itself would: by applying migration 1 and
    /// nothing else.
    fn version_1(&self) {
        let path = self.db();
        let connection = rusqlite_connection(&path);
        drop(connection);
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Applies exactly migration 1 to a fresh file and closes it.
///
/// Written out here rather than reaching into `state::schema`, because the
/// migration runner's internals are deliberately not public: a fixture that used
/// them would stop proving anything about the production path the moment they
/// changed.
fn rusqlite_connection(path: &Path) -> rusqlite::Connection {
    let sql = include_str!("../src/state/migrations/001_initial.sql");
    let connection = rusqlite::Connection::open(path).expect("a writable scratch path");
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    connection.execute_batch(sql).expect("migration 1 applies");
    connection
        .pragma_update(None, "user_version", 1i64)
        .unwrap();
    connection
}

/// Seeds the singleton installation row directly into a version-1 file.
///
/// Written as SQL rather than through `StateStore` because every public store
/// entry point migrates on open, so the typed API cannot populate a file that is
/// still at the old version. That is the correct production behaviour; the
/// fixture simply needs the other side of it.
fn seed_v1_installation(path: &Path) {
    let connection = rusqlite::Connection::open(path).unwrap();
    // Both singleton tables, because the store refuses to open a database that
    // is missing either one. A version-1 store always had exactly these two.
    connection
        .execute_batch(
            "INSERT INTO installation
                 (singleton, installation_id, desired_generation, created_at, updated_at)
             VALUES (1, '00000000-0000-4000-8000-00000000a001', 1, 1, 1);
             INSERT INTO convergence_state
                 (singleton, last_attempted_generation, last_converged_generation,
                  last_attempt_timestamp, last_outcome)
             VALUES (1, NULL, NULL, NULL, NULL);",
        )
        .expect("a version-1 store always carries both singleton rows");
}

/// Reads the installation identity that was seeded at version 1.
fn read_v1_installation_id(path: &Path) -> String {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .query_row("SELECT installation_id FROM installation", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap()
}

/// Reads `PRAGMA user_version` from a file without holding the store open.
fn user_version_of(path: &Path) -> i64 {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap()
}

/// A provisioned administrator plus a live worker, for the worker-path tests.
struct Fixture {
    _scratch: Scratch,
    startup: Option<WorkerStartup>,
}

impl Fixture {
    fn new() -> Self {
        let scratch = Scratch::new();
        StateStore::initialize(scratch.db()).expect("a fresh store");
        let startup = spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket()))
            .expect("an empty store and an absent netd still start");
        Self {
            _scratch: scratch,
            startup: Some(startup),
        }
    }

    fn client(&self) -> WorkerClient {
        self.startup
            .as_ref()
            .expect("the worker is live until the fixture drops")
            .client()
            .clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Stopping is synchronous-blocking, so it cannot be awaited from a
        // destructor. Dropping the startup value drops the client clone and the
        // join handle, which ends the worker's command queue and lets its thread
        // exit on its own.
        drop(self.startup.take());
    }
}

#[test]
fn a_real_v1_database_upgrades_to_head_and_preserves_desired_state() {
    let scratch = Scratch::new();
    scratch.version_1();
    seed_v1_installation(&scratch.db());
    assert_eq!(
        user_version_of(&scratch.db()),
        1,
        "the fixture must start at the historical boundary"
    );

    // Opening through the production path performs the real migration and takes
    // the pre-migration recovery snapshot.
    let store = StateStore::open(scratch.db()).expect("the v1 database upgrades");
    assert_eq!(
        store.schema_version().unwrap(),
        6,
        "a v1 file upgrades all the way to head, not one step at a time"
    );

    let after = store.installation_metadata().expect("metadata survives");
    assert_eq!(
        after.desired_generation,
        wg_basic::domain::INITIAL_DESIRED_GENERATION,
        "an upgrade must not advance the desired generation"
    );
    assert_eq!(
        after.installation_id.to_string(),
        read_v1_installation_id(&scratch.db()),
        "an upgrade must never mint a new installation identity"
    );
    assert_eq!(
        store.load().unwrap().generation,
        wg_basic::domain::INITIAL_DESIRED_GENERATION,
        "the desired snapshot survives the upgrade at its own generation"
    );
    assert!(
        store
            .convergence()
            .unwrap()
            .last_attempted_generation
            .is_none(),
        "the evidence table survives empty rather than being reset"
    );
}

#[test]
fn the_upgrade_takes_a_recovery_snapshot_holding_the_v1_schema() {
    let scratch = Scratch::new();
    scratch.version_1();
    seed_v1_installation(&scratch.db());

    StateStore::open(scratch.db()).expect("the upgrade runs");

    let snapshot = scratch.0.join("state.db.pre-migration-v1");
    assert!(
        snapshot.exists(),
        "a schema-changing migration must leave a recovery snapshot behind"
    );
    let metadata = fs::symlink_metadata(&snapshot).unwrap();
    assert_eq!(
        metadata.permissions().mode() & 0o777,
        0o600,
        "the snapshot holds the same credentials as the database"
    );
    assert_eq!(
        user_version_of(&snapshot),
        1,
        "the snapshot must hold the *pre-migration* schema"
    );
    // The live file has moved on; the snapshot has not.
    assert_eq!(user_version_of(&scratch.db()), 6);
}

#[test]
fn the_new_tables_exist_and_credential_values_are_absent_from_desired_state() {
    let scratch = Scratch::new();
    let store = StateStore::initialize(scratch.db()).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(scratch.db()).unwrap();

    for table in ["admin_principals", "admin_sessions"] {
        let exists: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "{table} must exist");
    }

    // The session table has no column that could hold a bearer token, so the
    // "digest only" property is a schema fact, not a convention.
    let mut statement = connection
        .prepare("SELECT name FROM pragma_table_info('admin_sessions')")
        .unwrap();
    let columns: Vec<String> = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        columns,
        vec![
            "id",
            "principal_id",
            "token_digest",
            "csrf_token",
            "created_at",
            "expires_at"
        ]
    );
    assert!(
        !columns
            .iter()
            .any(|name| name.contains("token") && *name != "token_digest" && *name != "csrf_token"),
        "no column may hold a bearer token: {columns:?}"
    );
}

#[test]
fn a_v1_database_that_cannot_migrate_is_left_at_version_one() {
    // A migration that fails must leave the file at a single coherent version,
    // not half-migrated. The runner applies every pending step inside one
    // IMMEDIATE transaction and runs `PRAGMA foreign_key_check` after each, so a
    // pre-existing violation is what makes it fail.
    let scratch = Scratch::new();
    scratch.version_1();

    let connection = rusqlite::Connection::open(scratch.db()).unwrap();
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
        .expect("plant a dangling client row");
    drop(connection);

    assert!(
        StateStore::open(scratch.db()).is_err(),
        "a database with a dangling foreign key must fail closed"
    );
    assert_eq!(
        user_version_of(&scratch.db()),
        1,
        "the failed migration must roll back to the previous version"
    );
    // And the new tables must not exist, which is what "rolled back" means here.
    let connection = rusqlite::Connection::open(scratch.db()).unwrap();
    let auth_tables: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' \
             AND name IN ('admin_principals', 'admin_sessions')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        auth_tables, 0,
        "a rolled-back migration leaves no partial schema"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_worker_owns_credential_and_session_operations() {
    let fixture = Fixture::new();
    let client = fixture.client();

    // The whole session lifecycle crosses the bounded worker queue.
    let status = client
        .set_admin_password("admin".into(), PASSWORD.into())
        .await
        .expect("provisioning crosses the worker");
    assert_eq!(status.username, "admin");

    let issued = client
        .authenticate("admin".into(), PASSWORD.into())
        .await
        .expect("authentication crosses the worker");

    let resolved = client
        .resolve_session(issued.token.expose_once().to_owned())
        .await
        .expect("resolution crosses the worker");
    assert_eq!(resolved.session.id, issued.session.id);

    client
        .revoke_session(issued.token.expose_once().to_owned())
        .await
        .expect("logout crosses the worker");
    assert!(
        client
            .resolve_session(issued.token.expose_once().to_owned())
            .await
            .is_err(),
        "a revoked session must stop resolving"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_login_is_distinguishable_from_an_outage_by_the_caller() {
    let fixture = Fixture::new();
    let client = fixture.client();
    client
        .set_admin_password("admin".into(), PASSWORD.into())
        .await
        .unwrap();

    let refused = client
        .authenticate("admin".into(), "a different long password".into())
        .await
        .expect_err("a wrong password is refused");
    assert!(refused.is_refusal(), "{refused} must be a refusal");
    assert!(
        !refused.is_overload(),
        "a refused password must not be retryable, or a caller would hammer Argon2id"
    );

    let unknown_user = client
        .authenticate("nobody".into(), PASSWORD.into())
        .await
        .expect_err("an unknown username is refused");
    assert!(unknown_user.is_refusal());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_password_reset_across_the_worker_revokes_every_session() {
    let fixture = Fixture::new();
    let client = fixture.client();
    client
        .set_admin_password("admin".into(), PASSWORD.into())
        .await
        .unwrap();

    let first = client
        .authenticate("admin".into(), PASSWORD.into())
        .await
        .unwrap();
    let second = client
        .authenticate("admin".into(), PASSWORD.into())
        .await
        .unwrap();
    assert_eq!(
        client.admin_status().await.unwrap().unwrap().live_sessions,
        2
    );

    let replacement = "a completely different admin password";
    client
        .set_admin_password("admin".into(), replacement.into())
        .await
        .unwrap();

    assert_eq!(
        client.admin_status().await.unwrap().unwrap().live_sessions,
        0,
        "a reset must invalidate every outstanding session"
    );
    for issued in [&first, &second] {
        assert!(client
            .resolve_session(issued.token.expose_once().to_owned())
            .await
            .is_err());
    }
    assert!(client
        .authenticate("admin".into(), replacement.into())
        .await
        .is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authentication_across_the_worker_never_advances_the_desired_generation() {
    let scratch = Scratch::new();
    let store = StateStore::initialize(scratch.db()).unwrap();
    let before = store.installation_metadata().unwrap();
    drop(store);

    let startup = spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket())).unwrap();
    let client = startup.client().clone();

    client
        .set_admin_password("admin".into(), PASSWORD.into())
        .await
        .unwrap();
    let issued = client
        .authenticate("admin".into(), PASSWORD.into())
        .await
        .unwrap();
    client
        .resolve_session(issued.token.expose_once().to_owned())
        .await
        .unwrap();
    client
        .revoke_session(issued.token.expose_once().to_owned())
        .await
        .unwrap();
    client
        .authenticate("admin".into(), PASSWORD.into())
        .await
        .unwrap();
    client.purge_expired_sessions().await.unwrap();
    startup.stop().await.unwrap();

    let store = StateStore::open(scratch.db()).unwrap();
    let after = store.installation_metadata().unwrap();
    assert_eq!(
        after.desired_generation, before.desired_generation,
        "a login must never cause the kernel to be reconciled"
    );
    assert_eq!(after.installation_id, before.installation_id);
    assert_eq!(store.load().unwrap().generation, before.desired_generation);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_raw_token_is_absent_from_the_database_after_a_worker_login() {
    let scratch = Scratch::new();
    StateStore::initialize(scratch.db()).unwrap();
    let startup = spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket())).unwrap();
    let client = startup.client().clone();
    client
        .set_admin_password("admin".into(), PASSWORD.into())
        .await
        .unwrap();
    let issued = client
        .authenticate("admin".into(), PASSWORD.into())
        .await
        .unwrap();
    startup.stop().await.unwrap();

    // Read the file with an independent connection so this proves what is on
    // disk, not what the store's own API reports.
    let connection = rusqlite::Connection::open(scratch.db()).unwrap();
    let digest: String = connection
        .query_row("SELECT token_digest FROM admin_sessions", [], |row| {
            row.get(0)
        })
        .unwrap();
    let csrf: String = connection
        .query_row("SELECT csrf_token FROM admin_sessions", [], |row| {
            row.get(0)
        })
        .unwrap();
    let verifier: String = connection
        .query_row("SELECT verifier FROM admin_principals", [], |row| {
            row.get(0)
        })
        .unwrap();
    let bytes = std::fs::read(scratch.db()).unwrap();

    assert_eq!(digest, issued.token.digest().expose_for_storage());
    assert_eq!(csrf, issued.session.csrf_token.expose_once());
    assert!(verifier.starts_with(ARGON2ID_PHC_PREFIX));
    // The two raw secrets must appear nowhere in any stored value, and nowhere
    // in the database file at all.
    for secret in [issued.token.expose_once(), PASSWORD] {
        for (label, stored) in [
            ("digest", &digest),
            ("csrf", &csrf),
            ("verifier", &verifier),
        ] {
            assert!(
                !stored.contains(secret),
                "{label} must not contain the raw secret {secret:?}"
            );
        }
        assert!(
            !String::from_utf8_lossy(&bytes).contains(secret),
            "a raw secret leaked into the database file"
        );
    }
    // And the verifier must not contain the password it verifies.
    assert!(!verifier.contains(PASSWORD));
}

#[test]
fn the_argon2id_policy_is_the_roadmap_minimum() {
    // Asserted against the crate's own constants rather than a literal so a
    // silent downgrade fails here instead of in production.
    assert_eq!(ARGON2_MEMORY_KIB, 19 * 1024, "19 MiB");
    assert_eq!(ARGON2_ITERATIONS, 2);
    assert_eq!(ARGON2_PARALLELISM, 1);
    assert!(check_password_policy(PASSWORD.as_bytes()).is_ok());
    assert!(check_password_policy(b"short").is_err());
    // Checked as a value, not as a literal, so a downgrade fails here rather than
    // passing silently.
    let floor = MIN_PASSWORD_BYTES;
    assert!(
        floor >= 12,
        "the administrator password floor must not fall below 12"
    );
}

#[test]
fn an_argon2id_verifier_round_trips_through_the_database_and_never_stores_a_password() {
    let scratch = Scratch::new();
    let store = StateStore::initialize(scratch.db()).unwrap();
    let auth = AuthService::new(&store);
    let principal = auth.set_password("admin", PASSWORD).unwrap();

    let stored = store
        .principal_verifier_for_test(principal.id)
        .unwrap()
        .expect("the row exists");
    assert!(stored.starts_with(ARGON2ID_PHC_PREFIX));
    assert!(!stored.contains(PASSWORD));
    assert!(!Path::new(&scratch.db())
        .file_name()
        .unwrap()
        .to_string_lossy()
        .contains(PASSWORD));

    // The verifier read back from storage still verifies, and still rejects.
    let adopted = PasswordVerifier::parse(stored).unwrap();
    assert!(adopted.verify(PASSWORD));
    assert!(!adopted.verify("not the password at all"));
    assert!(!principal.verifier.verify("not the password at all"));
}

#[test]
fn the_digest_is_what_is_looked_up_not_the_token() {
    let token = SessionToken::generate().unwrap();
    let digest = token.digest();
    let stored = digest.expose_for_storage();
    assert_eq!(SessionTokenDigest::parse(stored).unwrap(), digest);
    assert_eq!(SessionToken::digest_of(token.expose_once()), digest);
    assert_ne!(SessionToken::digest_of("other"), digest);

    // Two independent draws must not agree, or lookup would not be selective.
    let first = SessionToken::generate().unwrap();
    let second = SessionToken::generate().unwrap();
    assert_ne!(first.digest(), second.digest());
    assert!(!first.digest().constant_time_eq(&second.digest()));
}

#[test]
fn a_csrf_token_is_issued_per_session_and_is_not_the_bearer() {
    let scratch = Scratch::new();
    let store = StateStore::initialize(scratch.db()).unwrap();
    let auth = AuthService::new(&store);
    auth.set_password("admin", PASSWORD).unwrap();

    let first = auth.authenticate("admin", PASSWORD).unwrap();
    let second = auth.authenticate("admin", PASSWORD).unwrap();
    assert_ne!(
        first.csrf_token().expose_once(),
        second.csrf_token().expose_once(),
        "each session gets its own CSRF token"
    );
    assert_ne!(
        first.token.expose_once(),
        second.token.expose_once(),
        "each session gets its own bearer token"
    );
    assert_ne!(first.csrf_token().expose_once(), first.token.expose_once());
    let _ = CsrfToken::generate().unwrap();
}

#[test]
fn concurrent_session_issuance_is_capped_without_advancing_desired_generation() {
    let scratch = Scratch::new();
    let store = Arc::new(StateStore::initialize(scratch.db()).unwrap());
    let auth = AuthService::new(&store);
    auth.set_password("admin", PASSWORD).unwrap();
    let principal = store.principal_by_username("admin").unwrap().unwrap();
    let generation = store.current_generation().unwrap();

    let writers = (0..48)
        .map(|_| {
            let store = store.clone();
            let principal_id = principal.id;
            std::thread::spawn(move || {
                let token = SessionToken::generate().unwrap();
                store
                    .insert_session(
                        &SessionRecord {
                            id: SessionId::new(),
                            principal_id,
                            csrf_token: CsrfToken::generate().unwrap(),
                            created_at: 100,
                            expires_at: 10_000,
                        },
                        &token.digest(),
                    )
                    .unwrap();
            })
        })
        .collect::<Vec<_>>();
    for writer in writers {
        writer.join().unwrap();
    }

    assert_eq!(
        store.session_count().unwrap(),
        wg_basic::state::MAX_LIVE_SESSIONS_PER_PRINCIPAL,
        "serialized issuance never exceeds the live-session cap"
    );
    assert_eq!(
        store.current_generation().unwrap(),
        generation,
        "authentication housekeeping is not desired network state"
    );
}

#[test]
fn a_one_shot_admin_command_never_reports_a_credential() {
    let scratch = Scratch::new();
    StateStore::initialize(scratch.db()).unwrap();

    let status = wg_basic::management::set_password_at(scratch.db(), "admin", PASSWORD).unwrap();
    assert_eq!(status.username, "admin");
    assert!(status.enabled);
    let rendered = format!("{status:?}");
    assert!(!rendered.contains(PASSWORD));
    assert!(!rendered.contains(ARGON2ID_PHC_PREFIX));

    let status = wg_basic::management::status_at(scratch.db())
        .unwrap()
        .unwrap();
    assert_eq!(status.username, "admin");
    assert_eq!(status.live_sessions, 0);
}

#[test]
fn argon2id_cost_evidence_is_printed_for_ci() {
    // The plan requires the configured cost and a measured latency on CI, and
    // requires that they be recorded rather than assumed. Printed under
    // `--nocapture` so the number lands in the CI log; the assertions keep it
    // inside a sane band so a silently changed work factor fails the suite
    // rather than only showing up in a log nobody reads.
    let scratch = Scratch::new();
    let store = StateStore::initialize(scratch.db()).unwrap();
    let auth = AuthService::new(&store);
    auth.set_password("admin", PASSWORD).unwrap();

    let mut hash = std::time::Duration::ZERO;
    let mut verify = std::time::Duration::ZERO;
    let samples = 3;
    for _ in 0..samples {
        let cost = auth.measure_verification(PASSWORD).unwrap();
        hash += cost.hash_elapsed;
        verify += cost.verify_elapsed;
        println!(
            "argon2id: m={} KiB t={} p={} hash={:?} verify={:?}",
            cost.memory_kib,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            cost.hash_elapsed,
            cost.verify_elapsed
        );
    }
    let per_sample = |total: std::time::Duration| total / samples;
    println!(
        "argon2id mean over {samples} samples: hash={:?} verify={:?} memory={} KiB",
        per_sample(hash),
        per_sample(verify),
        ARGON2_MEMORY_KIB
    );

    // A band, not a target. Slow enough to be a real work factor, fast enough
    // that a queue of legitimate logins drains. The plan explicitly forbids
    // weakening the minimum parameters to hit a latency number, so a machine
    // that lands outside this band is a fact to record, not a reason to lower
    // `m_cost`.
    assert!(
        per_sample(verify) >= std::time::Duration::from_millis(10),
        "Argon2id verify below 10ms means the work factor is not doing its job"
    );
    assert!(
        per_sample(verify) < std::time::Duration::from_secs(5),
        "Argon2id verify above 5s would make a login queue unusable"
    );
}
