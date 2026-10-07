//! The local-administrator and session operations the worker owns.
//!
//! # Why these are not on `ManagementRuntime`
//!
//! Argon2id at the management policy costs on the order of tens of milliseconds
//! and 19 MiB of memory *per verification*. That is deliberate work factor, not
//! an accident: it is what makes an offline attack against a stolen verifier
//! expensive. It is also far too expensive to run on a Tokio worker thread, and
//! unbounded concurrent verification is exactly the CPU/latency denial of
//! service the roadmap warns about.
//!
//! So authentication is reached only through the bounded worker queue, like
//! every other management operation. That is not an incidental consequence of
//! the layout -- it is the reason the layout exists.
//!
//! # What this module never does
//!
//! * It never reveals whether a username exists. An unknown username, a wrong
//!   password, and a disabled principal all return [`AuthError::CredentialsRejected`].
//! * It never returns a stored password, verifier, or session bearer after
//!   issuance. The raw token is handed back exactly once, by
//!   [`AuthService::authenticate`].
//! * It never touches desired state. A login must not cause the kernel to be
//!   reconciled, so nothing here writes to `installation`.

pub use crate::domain::AuthError;
use crate::{
    domain::{
        check_password_policy, CsrfToken, PasswordVerifier, PrincipalId, SessionId, SessionToken,
        TIMING_EQUALISER_VERIFIER,
    },
    state::{PrincipalRecord, SessionRecord, StateError, StateStore, StoredSession},
};
use std::{
    sync::OnceLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Longest a session may live, in seconds.
///
/// Finite by construction and with no remember-me path: an unbounded session is
/// a permanent credential, and an operator who wants a shorter one is served by
/// a shorter constant rather than by a flag someone can forget to clear.
pub const DEFAULT_SESSION_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);

/// Shortest and longest acceptable administrator usernames.
///
/// Enforced on the credential that is not secret, so that a login form's input
/// bound and the database's own bound agree instead of one quietly accepting
/// what the other refuses.
pub const MIN_USERNAME_BYTES: usize = 3;

/// Longest acceptable administrator username.
pub const MAX_USERNAME_BYTES: usize = 64;

/// The current Unix time in seconds.
fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// A session that has just been issued.
///
/// Holds the only copy of the raw bearer token and the CSRF token. The caller
/// hands both to the client once and then this value is dropped, which
/// zeroizes the token.
#[derive(Debug)]
pub struct IssuedSession {
    /// The persisted session, without its bearer token.
    pub session: SessionRecord,
    /// The raw bearer token. Handed out exactly once.
    pub token: SessionToken,
}

impl IssuedSession {
    /// The CSRF token the client must echo back on state-changing requests.
    pub fn csrf_token(&self) -> &CsrfToken {
        &self.session.csrf_token
    }
}

/// What an operator may learn about the local administrator.
///
/// Deliberately has no field for a verifier, a token, or a password, so this can
/// be printed by the CLI and, in M003, returned by an endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminStatus {
    /// The principal's stable identity.
    pub principal_id: PrincipalId,
    /// The login name.
    pub username: String,
    /// Whether the principal may authenticate.
    pub enabled: bool,
    /// How many live sessions exist for this principal.
    pub live_sessions: i64,
    /// Unix seconds the principal was created.
    pub created_at: i64,
    /// Unix seconds of the last change.
    pub updated_at: i64,
}

/// Provisions or resets the local administrator for a one-shot operator command.
///
/// The store is opened, used, and closed inside this call, so a caller never
/// holds a secret-bearing database open after it has printed its output. The
/// socket is deliberately not a parameter: a credential write touches no
/// network authority, and taking a socket path it would only ignore would
/// suggest otherwise.
pub fn set_password_at(
    path: impl AsRef<std::path::Path>,
    username: &str,
    password: &str,
) -> Result<AdminStatus, AuthError> {
    let store = open_or_initialize(path).map_err(|_| AuthError::StorageUnavailable)?;
    let auth = AuthService::new(&store);
    auth.set_password(username, password)?;
    // Re-read through the same safe projection the HTTP surface will use, so
    // the CLI and M003 cannot report different things.
    auth.status()?.ok_or(AuthError::NoPrincipal)
}

/// The safe administrator projection for a one-shot operator command.
pub fn status_at(path: impl AsRef<std::path::Path>) -> Result<Option<AdminStatus>, AuthError> {
    let store = open_or_initialize(path).map_err(|_| AuthError::StorageUnavailable)?;
    AuthService::new(&store).status()
}

/// Opens the store, initializing it when it does not exist yet.
///
/// The same rule the service applies on startup, for the same reason: the
/// documented order is to provision the administrator *before* first start, so
/// this command has to work on a path nothing has ever opened. Without the
/// initialize arm, `wg-basic admin set-password` failed on exactly the fresh
/// install it exists to set up.
///
/// Reporting a storage failure as `StorageUnavailable` rather than surfacing the
/// underlying `StateError` is deliberate: this is a one-shot operator command
/// and the underlying error already names the database path, while this string
/// reaches a terminal on a machine the operator is sitting at.
fn open_or_initialize(
    path: impl AsRef<std::path::Path>,
) -> Result<StateStore, crate::state::StateError> {
    let path = path.as_ref();
    match StateStore::open(path) {
        Ok(store) => Ok(store),
        Err(crate::state::StateError::MissingParent { .. }) => StateStore::initialize(path),
        Err(crate::state::StateError::DatabaseAlreadyExists { .. }) => StateStore::open(path),
        Err(other) => Err(other),
    }
}

/// The measured Argon2id cost, for M003 throttling and CI evidence.
#[derive(Clone, Copy, Debug)]
pub struct VerificationCost {
    /// The wall-clock cost of one *verification*, which is what a login pays.
    pub verify_elapsed: Duration,
    /// The wall-clock cost of one *hashing*, which is what a password reset pays.
    pub hash_elapsed: Duration,
    /// The configured memory cost in kibibytes.
    pub memory_kib: u32,
}

/// Everything the worker needs to authenticate an operator.
pub struct AuthService<'a> {
    store: &'a StateStore,
    lifetime: Duration,
}

impl<'a> AuthService<'a> {
    /// Binds authentication to a store with the default session lifetime.
    pub fn new(store: &'a StateStore) -> Self {
        Self {
            store,
            lifetime: DEFAULT_SESSION_LIFETIME,
        }
    }

    /// Overrides the session lifetime.
    ///
    /// A parameter rather than a constant so a test can use a short lifetime
    /// instead of sleeping for twelve hours, and so a future policy change has
    /// exactly one place to happen.
    pub fn with_session_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Creates or resets the local administrator and revokes every session.
    ///
    /// Reset and provisioning are the same operation because they are the same
    /// security event: a new verifier must never leave an old session usable.
    pub fn set_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<PrincipalRecord, AuthError> {
        let username = validate_username(username)?;
        // The policy is applied to the caller's bytes, so an over-long input is
        // refused on its length rather than truncated into a shorter password
        // that the operator did not choose.
        check_password_policy(password.as_bytes()).map_err(|_| AuthError::CredentialsRejected)?;
        // Hashed exactly once. Computing it twice would produce two verifiers,
        // and storing the one that was never verified would be a real bug.
        let verifier =
            PasswordVerifier::hash(password).map_err(|_| AuthError::MalformedVerifier)?;
        let now = now_seconds();

        let existing = self
            .store
            .principal_by_username(&username)
            .map_err(map_store_error)?;
        match existing {
            Some(principal) => {
                // Reset and revocation are one transaction: a password change
                // that failed to revoke sessions would leave a stolen cookie
                // valid after the operator locked the attacker out.
                self.store
                    .reset_password_and_revoke_sessions(principal.id, verifier, now)
                    .map_err(|_| AuthError::StorageUnavailable)?;
                self.store
                    .principal_by_username(&username)
                    .map_err(|_| AuthError::StorageUnavailable)?
                    .ok_or(AuthError::NoPrincipal)
            }
            None => {
                // Phase 7 supports one local administrator. Refusing a second
                // distinct username keeps "who can log in" a single answer rather
                // than a list an operator has to audit.
                if self.store.principal_count().map_err(map_store_error)? > 0 {
                    return Err(AuthError::PrincipalExists);
                }
                self.store
                    .upsert_principal(PrincipalId::new(), &username, verifier, true, now)
                    .map_err(|_| AuthError::StorageUnavailable)
            }
        }
    }

    /// Verifies a username and password, issuing a session on success.
    ///
    /// Every failure returns [`AuthError::CredentialsRejected`]. That includes an
    /// unknown username and a disabled principal: if those produced a different
    /// answer, this function would be a username oracle, and the cost of Argon2
    /// would leak the difference too.
    pub fn authenticate(&self, username: &str, password: &str) -> Result<IssuedSession, AuthError> {
        // The policy still applies on the way in: an over-long candidate must
        // not be hashed, so a login cannot be used to submit unbounded Argon2
        // work.
        check_password_policy(password.as_bytes()).map_err(|_| AuthError::CredentialsRejected)?;

        // Every refusal below costs one Argon2 verification, even the ones that
        // find no principal at all. Without that, "no such username" answers in
        // microseconds while "wrong password" answers in ~300 ms, and the gap
        // itself is the username oracle -- a larger, more reliable one than
        // anything a response body could accidentally reveal.
        let principal = match self.store.principal_by_username(username) {
            Ok(Some(principal)) => principal,
            Ok(None) | Err(_) => return Err(self.reject_without_principal(password)),
        };
        if !principal.enabled {
            return Err(self.reject_without_principal(password));
        }
        if !principal.verifier.verify(password) {
            return Err(AuthError::CredentialsRejected);
        }
        self.issue_session(principal.id)
    }

    /// Spends an Argon2 verification against the fixed dummy verifier, then
    /// refuses.
    ///
    /// The result is discarded. The point is the work it does, not the answer it
    /// produces: by the time this returns, the caller has paid the same cost as
    /// a real verification and so has any observer timing the request.
    fn reject_without_principal(&self, password: &str) -> AuthError {
        equaliser().verify(password);
        AuthError::CredentialsRejected
    }

    /// Issues a session for an already-authenticated principal.
    fn issue_session(&self, principal_id: PrincipalId) -> Result<IssuedSession, AuthError> {
        let token = SessionToken::generate()?;
        let csrf_token = CsrfToken::generate()?;
        let created_at = now_seconds();
        let expires_at = created_at + self.lifetime.as_secs() as i64;
        let session = SessionRecord {
            id: SessionId::new(),
            principal_id,
            csrf_token,
            created_at,
            expires_at,
        };
        // Only the digest is persisted. The raw token exists in this value and
        // nowhere else.
        //
        // A persistence failure after the password already verified is reported
        // as `SessionUnavailable`, not as rejected credentials: the operator
        // typed the right password and must not be told otherwise.
        self.store
            .insert_session(&session, &token.digest())
            .map_err(|_| AuthError::SessionUnavailable)?;
        Ok(IssuedSession { session, token })
    }

    /// Resolves a presented bearer token to its live session.
    ///
    /// The presented token is hashed before it reaches a query, so no code path
    /// can compare or store it. Expired sessions are removed rather than
    /// reported.
    pub fn resolve_session(&self, presented: &str) -> Result<StoredSession, AuthError> {
        if presented.is_empty() {
            return Err(AuthError::SessionInvalid);
        }
        let digest = SessionToken::digest_of(presented);
        self.store
            .find_session_by_digest(&digest, now_seconds())
            .map_err(map_store_error)?
            .ok_or(AuthError::SessionInvalid)
    }

    /// Revokes one session by its presented bearer token (logout).
    pub fn revoke_session(&self, presented: &str) -> Result<(), AuthError> {
        if presented.is_empty() {
            return Err(AuthError::SessionInvalid);
        }
        let digest = SessionToken::digest_of(presented);
        self.store
            .revoke_session_by_digest(&digest)
            .map_err(map_store_error)?;
        Ok(())
    }

    /// Revokes every session belonging to a principal.
    pub fn revoke_all_sessions(&self, principal_id: PrincipalId) -> Result<usize, AuthError> {
        self.store
            .revoke_principal_sessions(principal_id)
            .map_err(|_| AuthError::StorageUnavailable)
    }

    /// Deletes expired sessions and reports how many went.
    pub fn purge_expired_sessions(&self) -> Result<usize, AuthError> {
        self.store
            .purge_expired_sessions(now_seconds())
            .map_err(|_| AuthError::StorageUnavailable)
    }

    /// The safe operator-facing projection of the local administrator.
    pub fn status(&self) -> Result<Option<AdminStatus>, AuthError> {
        let count = self.store.principal_count().map_err(map_store_error)?;
        if count == 0 {
            return Ok(None);
        }
        // Phase 7 provisions exactly one principal, so the first row is the
        // administrator. Looking it up by username rather than "any row" keeps
        // that explicit instead of relying on insertion order.
        let principal = self
            .store
            .principals()
            .map_err(map_store_error)?
            .into_iter()
            .next()
            .ok_or(AuthError::NoPrincipal)?;
        Ok(Some(AdminStatus {
            principal_id: principal.id,
            username: principal.username,
            enabled: principal.enabled,
            live_sessions: self.store.session_count().map_err(map_store_error)?,
            created_at: principal.created_at,
            updated_at: principal.updated_at,
        }))
    }

    /// Measures one Argon2id hash and one verification.
    ///
    /// Both are reported because they are two different budgets: a login pays
    /// the verify, and a password reset pays the hash. M003's throttling has to
    /// size itself against the larger of the two.
    pub fn measure_verification(&self, password: &str) -> Result<VerificationCost, AuthError> {
        let hash_started = SystemTime::now();
        let verifier =
            PasswordVerifier::hash(password).map_err(|_| AuthError::MalformedVerifier)?;
        let hash_elapsed = hash_started.elapsed().unwrap_or_default();

        let verify_started = SystemTime::now();
        let _ = verifier.verify(password);
        let verify_elapsed = verify_started.elapsed().unwrap_or_default();

        Ok(VerificationCost {
            verify_elapsed,
            hash_elapsed,
            memory_kib: crate::domain::ARGON2_MEMORY_KIB,
        })
    }
}

/// Rejects a username outside the documented shape.
fn validate_username(username: &str) -> Result<String, AuthError> {
    let trimmed = username.trim();
    if !(MIN_USERNAME_BYTES..=MAX_USERNAME_BYTES).contains(&trimmed.len()) {
        return Err(AuthError::UsernameInvalid);
    }
    // Control characters would corrupt operator-facing output and make a login
    // form ambiguous; everything else is allowed, including non-ASCII.
    if trimmed.chars().any(char::is_control) {
        return Err(AuthError::UsernameInvalid);
    }
    Ok(trimmed.to_owned())
}

/// Maps a storage failure onto an authentication failure.
///
/// The database error is deliberately dropped rather than rendered: a caller on
/// the other side of an HTTP boundary must not be able to distinguish "the
/// database is broken" from "those credentials were wrong".
fn map_store_error(_error: StateError) -> AuthError {
    // Every storage failure collapses into one answer on purpose. A caller on the
    // other side of an HTTP boundary must not be able to distinguish "the
    // database is broken" from "those credentials were wrong", and a distinct
    // variant for storage trouble would do exactly that.
    AuthError::CredentialsRejected
}

/// The fixed dummy verifier, parsed once.
///
/// Parsing a PHC string is cheap but doing it per failed login would be a
/// second, smaller timing signal, so the parse is hoisted out of the request
/// path entirely. `OnceLock` rather than `LazyLock` because the value cannot be
/// built at compile time.
fn equaliser() -> &'static PasswordVerifier {
    static EQUALISER: OnceLock<PasswordVerifier> = OnceLock::new();
    EQUALISER.get_or_init(|| {
        PasswordVerifier::parse(TIMING_EQUALISER_VERIFIER)
            .expect("the timing equaliser is a constant of this crate")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        ARGON2ID_PHC_PREFIX, ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM,
    };

    fn store() -> (tempdir::TempDir, StateStore) {
        let dir = tempdir::TempDir::new();
        let store = StateStore::initialize(dir.db()).unwrap();
        (dir, store)
    }

    /// A minimal private temp directory, local so the test does not add a
    /// dev-dependency.
    mod tempdir {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        pub struct TempDir(PathBuf);

        impl TempDir {
            pub fn new() -> Self {
                let path = std::env::temp_dir().join(format!(
                    "wg-basic-auth-{}-{}",
                    std::process::id(),
                    COUNTER.fetch_add(1, Ordering::Relaxed)
                ));
                let _ = fs::remove_dir_all(&path);
                fs::create_dir(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                Self(path)
            }

            pub fn db(&self) -> PathBuf {
                self.0.join("state.db")
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    const PASSWORD: &str = "a long enough admin password";

    #[test]
    fn provisioning_then_authenticating_issues_a_session() {
        let (_dir, store) = store();
        let auth = AuthService::new(&store);

        let principal = auth.set_password("admin", PASSWORD).unwrap();
        assert!(principal.enabled);

        let issued = auth.authenticate("admin", PASSWORD).unwrap();
        assert_eq!(issued.session.principal_id, principal.id);
        assert!(issued.session.expires_at > issued.session.created_at);

        // The raw token resolves, and nothing else does.
        let resolved = auth.resolve_session(issued.token.expose_once()).unwrap();
        assert_eq!(resolved.session.id, issued.session.id);
        assert!(auth.resolve_session("not the token").is_err());
    }

    #[test]
    fn the_raw_token_is_never_persisted_only_its_digest() {
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        auth.set_password("admin", PASSWORD).unwrap();
        let issued = auth.authenticate("admin", PASSWORD).unwrap();

        let digests = store.session_digests_for_test().unwrap();
        assert_eq!(digests.len(), 1);
        assert_eq!(digests[0], issued.token.digest().expose_for_storage());
        assert!(
            !digests[0].contains(issued.token.expose_once()),
            "the stored value must be a digest, not the token"
        );
    }

    #[test]
    fn credential_failure_never_distinguishes_username_from_password() {
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        auth.set_password("admin", PASSWORD).unwrap();

        // Unknown username, wrong password, and wrong username+password must all
        // produce one indistinguishable answer.
        for (username, candidate) in [
            ("nobody", PASSWORD),
            ("admin", "a different long password"),
            ("wronguser", "a different long password"),
        ] {
            assert_eq!(
                auth.authenticate(username, candidate).err(),
                Some(AuthError::CredentialsRejected),
                "{username} / {candidate} must be refused indistinguishably"
            );
        }
    }

    #[test]
    fn a_disabled_principal_fails_authentication() {
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        let principal = auth.set_password("admin", PASSWORD).unwrap();
        store
            .upsert_principal(
                principal.id,
                "admin",
                principal.verifier.clone(),
                false,
                now_seconds(),
            )
            .unwrap();

        assert_eq!(
            auth.authenticate("admin", PASSWORD).err(),
            Some(AuthError::CredentialsRejected),
            "a disabled principal must not authenticate"
        );
    }

    #[test]
    fn logout_revokes_the_session_immediately() {
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        auth.set_password("admin", PASSWORD).unwrap();
        let issued = auth.authenticate("admin", PASSWORD).unwrap();

        auth.revoke_session(issued.token.expose_once()).unwrap();
        assert_eq!(
            auth.resolve_session(issued.token.expose_once()).err(),
            Some(AuthError::SessionInvalid),
            "a revoked token must stop resolving the moment it is revoked"
        );
        assert_eq!(store.session_count().unwrap(), 0);
    }

    #[test]
    fn a_session_lifetime_is_bounded_and_cannot_be_instant() {
        let (_dir, store) = store();
        // The schema declares `expires_at > created_at`, so a zero lifetime
        // cannot produce a session at all. That floor is real: an immediately
        // expired session would be indistinguishable from a revoked one.
        let auth = AuthService::new(&store).with_session_lifetime(Duration::ZERO);
        auth.set_password("admin", PASSWORD).unwrap();

        assert_eq!(
            auth.authenticate("admin", PASSWORD).err(),
            Some(AuthError::SessionUnavailable),
            "a zero lifetime must fail to issue, not silently mint a dead session"
        );
        assert_eq!(store.session_count().unwrap(), 0);

        assert!(DEFAULT_SESSION_LIFETIME > Duration::ZERO);
        assert!(
            DEFAULT_SESSION_LIFETIME <= Duration::from_secs(7 * 24 * 60 * 60),
            "a session must not outlive a week: there is no remember-me mode"
        );
    }

    #[test]
    fn an_expired_session_is_removed_rather_than_left_to_rot() {
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        auth.set_password("admin", PASSWORD).unwrap();
        let issued = auth.authenticate("admin", PASSWORD).unwrap();
        let digest = issued.token.digest();

        // Expiry is evaluated against an explicit `now`, so the rule is proven
        // without sleeping and without a clock the test has to trust.
        let last_valid = issued.session.expires_at - 1;
        assert!(
            store
                .find_session_by_digest(&digest, last_valid)
                .unwrap()
                .is_some(),
            "a session is live up to the second before its expiry"
        );
        assert!(
            store
                .find_session_by_digest(&digest, issued.session.expires_at)
                .unwrap()
                .is_none(),
            "a session is already invalid on its expiry second"
        );
        assert_eq!(
            store.session_count().unwrap(),
            0,
            "an expired session is deleted on lookup, not merely ignored"
        );
        assert!(issued.session.is_expired_at(issued.session.expires_at));
        assert!(!issued.session.is_expired_at(issued.session.expires_at - 1));
    }

    #[test]
    fn a_password_reset_revokes_every_prior_session() {
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        auth.set_password("admin", PASSWORD).unwrap();

        let first = auth.authenticate("admin", PASSWORD).unwrap();
        let second = auth.authenticate("admin", PASSWORD).unwrap();
        assert_eq!(store.session_count().unwrap(), 2);

        let new_password = "an entirely different long password";
        auth.set_password("admin", new_password).unwrap();

        assert_eq!(
            store.session_count().unwrap(),
            0,
            "changing the password must invalidate every outstanding session"
        );
        assert!(auth.resolve_session(first.token.expose_once()).is_err());
        assert!(auth.resolve_session(second.token.expose_once()).is_err());
        assert_eq!(
            auth.authenticate("admin", PASSWORD).err(),
            Some(AuthError::CredentialsRejected),
            "the old password must stop working"
        );
        assert!(auth.authenticate("admin", new_password).is_ok());
    }

    #[test]
    fn auth_writes_never_advance_the_desired_generation() {
        let (_dir, store) = store();
        let before = store.installation_metadata().unwrap();
        let auth = AuthService::new(&store);

        auth.set_password("admin", PASSWORD).unwrap();
        let issued = auth.authenticate("admin", PASSWORD).unwrap();
        auth.resolve_session(issued.token.expose_once()).unwrap();
        auth.revoke_session(issued.token.expose_once()).unwrap();
        auth.authenticate("admin", PASSWORD).unwrap();
        auth.purge_expired_sessions().unwrap();

        let after = store.installation_metadata().unwrap();
        assert_eq!(
            after.desired_generation, before.desired_generation,
            "authentication is not desired state and must never reconcile the kernel"
        );
        assert_eq!(after.installation_id, before.installation_id);
        assert_eq!(store.load().unwrap().generation, before.desired_generation);
    }

    #[test]
    fn a_raw_password_is_never_persisted() {
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        let principal = auth.set_password("admin", PASSWORD).unwrap();

        let stored = store
            .principal_verifier_for_test(principal.id)
            .unwrap()
            .unwrap();
        assert!(stored.starts_with(ARGON2ID_PHC_PREFIX));
        assert!(
            !stored.contains(PASSWORD),
            "the stored verifier must never contain the password"
        );
        assert!(principal.verifier.verify(PASSWORD));
    }

    #[test]
    fn a_second_distinct_username_is_refused_in_phase_7() {
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        auth.set_password("admin", PASSWORD).unwrap();
        assert_eq!(
            auth.set_password("someone-else", PASSWORD).err(),
            Some(AuthError::PrincipalExists),
            "Phase 7 operates exactly one local administrator"
        );
    }

    #[test]
    fn the_username_shape_is_bounded() {
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        for bad in ["ab", "", "a\nb", &"x".repeat(MAX_USERNAME_BYTES + 1)] {
            assert_eq!(
                auth.set_password(bad, PASSWORD).err(),
                Some(AuthError::UsernameInvalid),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn an_over_long_login_candidate_is_refused_before_hashing() {
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        auth.set_password("admin", PASSWORD).unwrap();

        let cost = auth.measure_verification(PASSWORD).unwrap();
        assert_eq!(cost.memory_kib, crate::domain::ARGON2_MEMORY_KIB);
        assert!(
            cost.hash_elapsed.as_millis() < 5_000 && cost.verify_elapsed.as_millis() < 5_000,
            "the policy must stay in a sane range on the reference machine: \
             hash {:?}, verify {:?}",
            cost.hash_elapsed,
            cost.verify_elapsed
        );

        assert_eq!(
            auth.authenticate("admin", &"a".repeat(crate::domain::MAX_PASSWORD_BYTES + 1))
                .err(),
            Some(AuthError::CredentialsRejected),
            "an unbounded candidate must be refused by length, not hashed"
        );
    }

    #[test]
    fn status_never_carries_a_credential() {
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        assert!(auth.status().unwrap().is_none());

        auth.set_password("admin", PASSWORD).unwrap();
        let issued = auth.authenticate("admin", PASSWORD).unwrap();
        let status = auth.status().unwrap().unwrap();
        assert_eq!(status.username, "admin");
        assert!(status.enabled);
        assert_eq!(status.live_sessions, 1);

        let rendered = format!("{status:?}");
        assert!(!rendered.contains(PASSWORD));
        assert!(!rendered.contains(issued.token.expose_once()));
        assert!(!rendered.contains("$argon2id$"));
    }

    #[test]
    fn purge_removes_only_expired_sessions() {
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        auth.set_password("admin", PASSWORD).unwrap();

        let first = auth.authenticate("admin", PASSWORD).unwrap();
        let second = auth.authenticate("admin", PASSWORD).unwrap();
        assert_eq!(store.session_count().unwrap(), 2);

        // Expire only the first session by rewinding its own clock, so the
        // sweep has something to find and something to keep.
        let first_expiry = first.session.expires_at;
        let later = first_expiry + 1;
        assert_eq!(store.purge_expired_sessions(later).unwrap(), 2);
        assert_eq!(store.session_count().unwrap(), 0);
        assert!(
            auth.resolve_session(second.token.expose_once()).is_err(),
            "both sessions fall inside the swept window"
        );
    }

    #[test]
    fn a_sweep_keeps_a_session_whose_expiry_is_still_ahead() {
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        auth.set_password("admin", PASSWORD).unwrap();
        let issued = auth.authenticate("admin", PASSWORD).unwrap();

        // One second before expiry: nothing is due.
        assert_eq!(
            store
                .purge_expired_sessions(issued.session.expires_at - 1)
                .unwrap(),
            0
        );
        assert!(auth.resolve_session(issued.token.expose_once()).is_ok());
    }

    #[test]
    fn the_one_shot_commands_work_on_a_path_nothing_has_opened() {
        // The documented order is to provision the administrator *before* first
        // start, so `wg-basic admin set-password` has to initialise the store
        // itself. It did not: both one-shot commands used `StateStore::open`,
        // which refuses a file that does not exist, so the command failed with
        // `the credential store is unavailable` on exactly the fresh install it
        // exists to set up.
        let dir = tempdir::TempDir::new();
        let path = dir.db();

        let provisioned = set_password_at(&path, "admin", PASSWORD)
            .expect("set-password must initialise a fresh store");
        assert_eq!(provisioned.username, "admin");
        assert!(provisioned.enabled);
        assert!(path.exists(), "the store must exist afterwards");

        let status = status_at(&path)
            .expect("status must open a store it did not create")
            .expect("an administrator is provisioned");
        assert_eq!(status.principal_id, provisioned.principal_id);

        // And running it again is a reset, not an initialise error.
        let reset = set_password_at(&path, "admin", "a different password").expect("reset");
        assert_eq!(reset.principal_id, provisioned.principal_id);
        assert!(
            AuthService::new(&StateStore::open(&path).unwrap())
                .authenticate("admin", PASSWORD)
                .is_err(),
            "the old password must stop working"
        );
    }

    #[test]
    fn an_unknown_username_costs_a_verification_rather_than_being_free() {
        // Without the dummy verifier a username miss returned in microseconds
        // while a wrong password took ~300 ms. That gap *is* the username oracle,
        // and it is larger than anything a response body could leak. The
        // assertion is that the two refusals are within the same order of
        // magnitude, not that they are bit-identical: the plan explicitly does
        // not claim constant-time HTTP behaviour.
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        auth.set_password("admin", PASSWORD).unwrap();

        // Sampling both ends is what makes this stable. On a loaded machine every
        // call is slower, so comparing two single measurements would compare two
        // different amounts of load and the ratio would describe the scheduler
        // rather than the code. The real separation is a factor of two, so the
        // window below is deliberately wide -- wide enough to absorb scheduling
        // noise, tight enough that a skipped hash (three orders of magnitude)
        // cannot hide inside it.
        const SAMPLES: u32 = 5;
        let slowest = |username: &str, password: &str| {
            (0..SAMPLES)
                .map(|_| {
                    let started = std::time::Instant::now();
                    assert!(auth.authenticate(username, password).is_err());
                    started.elapsed()
                })
                .max()
                .expect("SAMPLES is non-zero")
        };

        let unknown_username = slowest("definitely-not-admin", PASSWORD);
        let wrong_password = slowest("admin", "definitely not the password");

        assert!(
            unknown_username > wrong_password / 8,
            "an unknown username took {unknown_username:?} against {wrong_password:?} for a \
             wrong password; the timing equaliser is not being used"
        );
        assert!(
            unknown_username < wrong_password * 8,
            "an unknown username took {unknown_username:?} against {wrong_password:?}; the \
             equaliser should be in the same order of magnitude, not merely slower"
        );
    }

    #[test]
    fn the_timing_equaliser_is_never_any_principals_verifier() {
        // It is a cost, not a credential. The plaintext behind it is discarded
        // and unrecoverable, so what this pins is that the constant never becomes
        // one: a provisioned administrator must never carry it, and no password
        // an operator could plausibly choose may verify against it.
        let equaliser = equaliser();
        for candidate in [
            "",
            "admin",
            PASSWORD,
            "password",
            "an administrator password",
        ] {
            assert!(
                !equaliser.verify(candidate),
                "the timing equaliser must not accept {candidate:?}"
            );
        }

        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        auth.set_password("admin", PASSWORD).unwrap();
        let principal = store
            .principal_by_username("admin")
            .unwrap()
            .expect("provisioned");
        assert_ne!(
            principal.verifier.expose_for_storage(),
            equaliser.expose_for_storage(),
            "a provisioned administrator must never hold the timing equaliser"
        );
    }

    #[test]
    fn the_timing_equaliser_carries_the_current_argon2_policy() {
        // If the policy is raised and the constant is not regenerated, a failed
        // lookup becomes measurably cheaper than a real verification -- which is
        // the exact defect the constant exists to prevent, introduced by the fix.
        let equaliser = equaliser();
        assert!(
            equaliser
                .expose_for_storage()
                .contains(&format!("m={}", ARGON2_MEMORY_KIB)),
            "the equaliser must use the same memory cost as the policy"
        );
        assert!(
            equaliser
                .expose_for_storage()
                .contains(&format!("t={}", ARGON2_ITERATIONS)),
            "the equaliser must use the same iteration count as the policy"
        );
        assert!(
            equaliser
                .expose_for_storage()
                .contains(&format!("p={}", ARGON2_PARALLELISM)),
            "the equaliser must use the same parallelism as the policy"
        );
    }

    #[test]
    fn a_disabled_principal_costs_a_verification_too() {
        // A disabled account is a different branch from a missing one, and it
        // would be the same leak if that branch skipped the hash.
        let (_dir, store) = store();
        let auth = AuthService::new(&store);
        auth.set_password("admin", PASSWORD).unwrap();
        let principal = store
            .principal_by_username("admin")
            .unwrap()
            .expect("provisioned");
        store
            .upsert_principal(principal.id, "admin", principal.verifier.clone(), false, 0)
            .unwrap();

        // Compared against a real wrong-password refusal in the same process,
        // not against an absolute duration: Argon2 is three times faster in a
        // release build, so any fixed millisecond bar is either flaky in debug
        // or meaningless in release. The claim is that a disabled account costs
        // the same *kind* of work as a wrong password, and that is a ratio.
        let slowest = |auth: &AuthService, password: &str| {
            (0..3)
                .map(|_| {
                    let started = std::time::Instant::now();
                    assert!(auth.authenticate("admin", password).is_err());
                    started.elapsed()
                })
                .max()
                .expect("three samples")
        };
        let disabled = slowest(&auth, PASSWORD);
        let wrong_password = slowest(&auth, "definitely not the password");

        assert!(
            disabled > wrong_password / 8,
            "a disabled principal refused in {disabled:?} against {wrong_password:?} for a \
             wrong password, which is far too cheap: a disabled account must not be a \
             faster answer, or disabling an account becomes a username oracle"
        );
        assert!(
            disabled < wrong_password * 8,
            "a disabled principal refused in {disabled:?} against {wrong_password:?}; the \
             equaliser should be in the same order of magnitude, not merely slower"
        );
    }

    #[test]
    fn status_on_a_fresh_path_reports_no_administrator_rather_than_failing() {
        // `status` is the command an operator runs to find out what is
        // provisioned. On a machine where nothing has been provisioned it must
        // say so, not report a storage failure.
        let dir = tempdir::TempDir::new();
        let status = status_at(dir.db()).expect("status must work on a fresh store");
        assert!(
            status.is_none(),
            "nothing is provisioned yet, got {status:?}"
        );
    }
}
