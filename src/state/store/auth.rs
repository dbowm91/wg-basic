//! Local administrator principals and server-side sessions.
//!
//! # This module stores credentials; it never evaluates them
//!
//! Argon2 hashing and password-policy checks live in [`crate::domain::auth`]. This
//! module only moves an already-computed verifier and an already-hashed token in
//! and out of SQLite, so a slow hash can never be triggered from inside a
//! database transaction and the credential *rules* stay testable without a
//! store.
//!
//! # The raw session token never reaches SQLite
//!
//! [`StateStore::insert_session`] takes a [`SessionTokenDigest`], not a
//! [`SessionToken`]. The type system is what enforces this: a caller cannot pass
//! a raw token to this module, because there is no parameter that accepts one.
//! Lookup takes the raw token, hashes it, and matches the digest.
//!
//! # Nothing here touches desired state
//!
//! Authentication is not desired state. No method in this module writes to
//! `installation`, and none of them advances `desired_generation`; a login must
//! not cause the kernel to be reconciled. `auth_writes_never_advance_the_desired_generation`
//! pins that.

use super::StateStore;
use crate::{
    domain::{CsrfToken, PasswordVerifier, PrincipalId, SessionId, SessionTokenDigest},
    state::error::StateError,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

/// Maximum concurrently valid browser sessions for one local administrator.
pub const MAX_LIVE_SESSIONS_PER_PRINCIPAL: i64 = 32;

/// One persisted local administrator.
///
/// `Debug` is written out by hand rather than derived: a derived `Debug` would
/// print the verifier, and a `{:?}` of a row must never be able to reach a
/// credential. `PasswordVerifier` redacts itself anyway, so the derived form
/// would be safe *today* — the hand-written impl is what keeps it safe if that
/// type is ever replaced.
#[derive(Clone, Eq, PartialEq)]
pub struct PrincipalRecord {
    /// Stable identity of this principal.
    pub id: PrincipalId,
    /// The login name. Unique, and not secret.
    pub username: String,
    /// The Argon2id PHC verifier. Never printed.
    pub verifier: PasswordVerifier,
    /// Whether this principal may authenticate at all.
    pub enabled: bool,
    /// Unix seconds when the row was created.
    pub created_at: i64,
    /// Unix seconds of the last change to this row.
    pub updated_at: i64,
}

impl std::fmt::Debug for PrincipalRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrincipalRecord")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("verifier", &self.verifier)
            .field("enabled", &self.enabled)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// One persisted session, without its bearer token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    /// Stable identity of this session.
    pub id: SessionId,
    /// Which principal the session authenticates.
    pub principal_id: PrincipalId,
    /// The double-submit CSRF token for this session.
    pub csrf_token: CsrfToken,
    /// Unix seconds when the session was issued.
    pub created_at: i64,
    /// Unix seconds after which the session is no longer valid.
    pub expires_at: i64,
}

impl SessionRecord {
    /// Whether `now` (Unix seconds) is at or past this session's expiry.
    ///
    /// The comparison is inclusive: a session is already invalid on its expiry
    /// second, so there is never a one-second window where an expired session
    /// still works.
    pub fn is_expired_at(&self, now: i64) -> bool {
        now >= self.expires_at
    }
}

/// The session row as stored, including the digest used for lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSession {
    /// The session's identity.
    pub session: SessionRecord,
    /// The SHA-256 digest that identifies this session.
    pub digest: SessionTokenDigest,
}

impl StateStore {
    /// Creates or replaces the local administrator.
    ///
    /// Provisioning and password reset are the same write on purpose: both set a
    /// new verifier for a username, and both must leave exactly one enabled
    /// principal behind. Reset additionally revokes every session, which the
    /// caller does explicitly in one transaction (see
    /// `reset_password_and_revoke_sessions`) so the revocation cannot be
    /// forgotten.
    pub fn upsert_principal(
        &self,
        id: PrincipalId,
        username: &str,
        verifier: PasswordVerifier,
        enabled: bool,
        now: i64,
    ) -> Result<PrincipalRecord, StateError> {
        let connection = self.lock()?;
        connection
            .execute(
                "INSERT INTO admin_principals (id, username, verifier, enabled, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT (username) DO UPDATE SET
                     verifier = excluded.verifier,
                     enabled = excluded.enabled,
                     updated_at = excluded.updated_at",
                params![
                    id.to_string(),
                    username,
                    verifier.expose_for_storage(),
                    enabled as i64,
                    now
                ],
            )
            .map_err(StateError::database)?;
        Self::read_principal_by_username(&connection, username)?.ok_or(StateError::Corrupt(
            "the administrator row vanished immediately after being written",
        ))
    }

    /// Sets a new password and revokes every session in one transaction.
    ///
    /// The two must be atomic: a password reset that failed to revoke sessions
    /// would leave a stolen cookie valid after the operator changed the password
    /// in order to lock the attacker out.
    pub fn reset_password_and_revoke_sessions(
        &self,
        principal_id: PrincipalId,
        verifier: PasswordVerifier,
        now: i64,
    ) -> Result<usize, StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        transaction
            .execute(
                "UPDATE admin_principals SET verifier = ?2, updated_at = ?3 WHERE id = ?1",
                params![principal_id.to_string(), verifier.expose_for_storage(), now],
            )
            .map_err(StateError::database)?;
        let revoked = transaction
            .execute(
                "DELETE FROM admin_sessions WHERE principal_id = ?1",
                [principal_id.to_string()],
            )
            .map_err(StateError::database)?;
        transaction.commit().map_err(StateError::database)?;
        Ok(revoked)
    }

    /// Looks up a principal by username.
    ///
    /// The caller must turn `None` into [`AuthError::CredentialsRejected`], the
    /// same answer a wrong password produces, so this method's existence is not
    /// itself a username oracle.
    pub fn principal_by_username(
        &self,
        username: &str,
    ) -> Result<Option<PrincipalRecord>, StateError> {
        let connection = self.lock()?;
        Self::read_principal_by_username(&connection, username)
    }

    fn read_principal_by_username(
        connection: &rusqlite::Connection,
        username: &str,
    ) -> Result<Option<PrincipalRecord>, StateError> {
        let row = connection
            .query_row(
                "SELECT id, verifier, enabled, created_at, updated_at
                 FROM admin_principals WHERE username = ?1",
                [username],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(StateError::database)?;
        let Some((id, verifier, enabled, created_at, updated_at)) = row else {
            return Ok(None);
        };
        Ok(Some(PrincipalRecord {
            id: id
                .parse()
                .map_err(|_| StateError::Corrupt("stored principal id is invalid"))?,
            username: username.to_owned(),
            // A malformed stored verifier is reported as a missing principal to
            // the caller, so a corrupt row cannot become a distinguishable
            // failure mode at the HTTP layer.
            verifier: PasswordVerifier::parse(verifier).map_err(|_| {
                StateError::Corrupt("stored credential verifier is not a usable PHC string")
            })?,
            enabled: enabled == 1,
            created_at,
            updated_at,
        }))
    }

    /// Every persisted principal.
    ///
    /// Phase 7 provisions exactly one, so this is normally a single row; it
    /// exists so the status projection reads a named set rather than reaching
    /// for "some row" and depending on insertion order.
    pub fn principals(&self) -> Result<Vec<PrincipalRecord>, StateError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare(
                "SELECT id, username, verifier, enabled, created_at, updated_at
                 FROM admin_principals ORDER BY created_at, id",
            )
            .map_err(StateError::database)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .map_err(StateError::database)?;
        let mut principals = Vec::new();
        for row in rows {
            let (id, username, verifier, enabled, created_at, updated_at) =
                row.map_err(StateError::database)?;
            principals.push(PrincipalRecord {
                id: id
                    .parse()
                    .map_err(|_| StateError::Corrupt("stored principal id is invalid"))?,
                username,
                verifier: PasswordVerifier::parse(verifier).map_err(|_| {
                    StateError::Corrupt("stored credential verifier is not a usable PHC string")
                })?,
                enabled: enabled == 1,
                created_at,
                updated_at,
            });
        }
        Ok(principals)
    }

    /// How many local administrators exist.
    pub fn principal_count(&self) -> Result<i64, StateError> {
        let connection = self.lock()?;
        connection
            .query_row("SELECT COUNT(*) FROM admin_principals", [], |row| {
                row.get(0)
            })
            .map_err(StateError::database)
    }

    /// Persists a newly issued session.
    ///
    /// Takes a digest, never a raw token: there is deliberately no parameter
    /// here that could accept one.
    pub fn insert_session(
        &self,
        session: &SessionRecord,
        digest: &SessionTokenDigest,
    ) -> Result<(), StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        transaction
            .execute(
                "DELETE FROM admin_sessions WHERE expires_at <= ?1",
                [session.created_at],
            )
            .map_err(StateError::database)?;
        let live: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM admin_sessions WHERE principal_id = ?1 AND expires_at > ?2",
                params![session.principal_id.to_string(), session.created_at],
                |row| row.get(0),
            )
            .map_err(StateError::database)?;
        let evict = live.saturating_sub(MAX_LIVE_SESSIONS_PER_PRINCIPAL - 1);
        if evict > 0 {
            transaction
                .execute(
                    "DELETE FROM admin_sessions WHERE id IN (
                        SELECT id FROM admin_sessions WHERE principal_id = ?1
                        ORDER BY created_at ASC, id ASC LIMIT ?2
                    )",
                    params![session.principal_id.to_string(), evict],
                )
                .map_err(StateError::database)?;
        }
        transaction
            .execute(
                "INSERT INTO admin_sessions
                     (id, principal_id, token_digest, csrf_token, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    session.id.to_string(),
                    session.principal_id.to_string(),
                    digest.expose_for_storage(),
                    session.csrf_token.expose_once(),
                    session.created_at,
                    session.expires_at,
                ],
            )
            .map_err(StateError::database)?;
        transaction.commit().map_err(StateError::database)
    }

    /// Resolves a session by the digest of a presented bearer token.
    ///
    /// Returns `None` for an unknown digest. Expiry is *not* applied here: the
    /// caller deletes expired rows as part of resolving, so a lookup never
    /// resurrects an expired session and never leaves it lingering.
    pub fn find_session_by_digest(
        &self,
        digest: &SessionTokenDigest,
        now: i64,
    ) -> Result<Option<StoredSession>, StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        let row = transaction
            .query_row(
                "SELECT id, principal_id, csrf_token, created_at, expires_at
                 FROM admin_sessions WHERE token_digest = ?1",
                [digest.expose_for_storage()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(StateError::database)?;
        let Some((id, principal_id, csrf_token, created_at, expires_at)) = row else {
            transaction.commit().map_err(StateError::database)?;
            return Ok(None);
        };
        let session = SessionRecord {
            id: id
                .parse()
                .map_err(|_| StateError::Corrupt("stored session id is invalid"))?,
            principal_id: principal_id
                .parse()
                .map_err(|_| StateError::Corrupt("stored session principal id is invalid"))?,
            csrf_token: CsrfToken::parse(csrf_token)
                .map_err(|_| StateError::Corrupt("stored csrf token is invalid"))?,
            created_at,
            expires_at,
        };
        let expired = session.is_expired_at(now);
        if expired {
            // Removing rather than ignoring keeps the table bounded by real
            // sessions, so cleanup is not a growing maintenance obligation.
            transaction
                .execute(
                    "DELETE FROM admin_sessions WHERE id = ?1",
                    [session.id.to_string()],
                )
                .map_err(StateError::database)?;
        }
        transaction.commit().map_err(StateError::database)?;
        if expired {
            return Ok(None);
        }
        Ok(Some(StoredSession {
            session,
            digest: digest.clone(),
        }))
    }

    /// Revokes one session by digest, for logout.
    pub fn revoke_session_by_digest(
        &self,
        digest: &SessionTokenDigest,
    ) -> Result<bool, StateError> {
        let connection = self.lock()?;
        let removed = connection
            .execute(
                "DELETE FROM admin_sessions WHERE token_digest = ?1",
                [digest.expose_for_storage()],
            )
            .map_err(StateError::database)?;
        Ok(removed > 0)
    }

    /// Revokes every session belonging to one principal.
    pub fn revoke_principal_sessions(
        &self,
        principal_id: PrincipalId,
    ) -> Result<usize, StateError> {
        let connection = self.lock()?;
        connection
            .execute(
                "DELETE FROM admin_sessions WHERE principal_id = ?1",
                [principal_id.to_string()],
            )
            .map_err(StateError::database)
    }

    /// Deletes every expired session and reports how many went.
    pub fn purge_expired_sessions(&self, now: i64) -> Result<usize, StateError> {
        let connection = self.lock()?;
        connection
            .execute("DELETE FROM admin_sessions WHERE expires_at <= ?1", [now])
            .map_err(StateError::database)
    }

    /// How many sessions are currently persisted.
    pub fn session_count(&self) -> Result<i64, StateError> {
        let connection = self.lock()?;
        connection
            .query_row("SELECT COUNT(*) FROM admin_sessions", [], |row| row.get(0))
            .map_err(StateError::database)
    }

    /// The stored digest of every persisted session, for tests that must prove
    /// what is and is not on disk.
    ///
    /// Deliberately returns digests rather than tokens: there is no code path in
    /// this crate that could turn this list back into a usable cookie.
    pub fn session_digests_for_test(&self) -> Result<Vec<String>, StateError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT token_digest FROM admin_sessions ORDER BY token_digest")
            .map_err(StateError::database)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(StateError::database)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StateError::database)
    }

    /// The stored verifier of a principal, for tests that must prove no
    /// plaintext is on disk.
    pub fn principal_verifier_for_test(
        &self,
        principal_id: PrincipalId,
    ) -> Result<Option<String>, StateError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT verifier FROM admin_principals WHERE id = ?1",
                [principal_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(StateError::database)
    }
}
