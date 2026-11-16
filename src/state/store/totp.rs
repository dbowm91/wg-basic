//! TOTP enrollment state and login pre-sessions.
//!
//! Pre-session bearer tokens are digest-stored exactly like product sessions.
//! TOTP secrets are raw Base32 in SQLite and must never be projected into audit
//! rows or ordinary account reads.

use super::StateStore;
use crate::{
    domain::{PrincipalId, SessionId, SessionTokenDigest, TotpSecret},
    state::error::StateError,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

/// Longest a TOTP login challenge may live, in seconds.
pub const TOTP_PRE_SESSION_LIFETIME_SECONDS: i64 = 5 * 60;

/// Persisted TOTP settings for one principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpRecord {
    pub enabled: bool,
    pub secret: Option<TotpSecret>,
    pub pending_secret: Option<TotpSecret>,
    pub updated_at: i64,
}

impl StateStore {
    pub fn totp_record(&self, principal_id: PrincipalId) -> Result<Option<TotpRecord>, StateError> {
        let connection = self.lock()?;
        Self::read_totp_record(&connection, principal_id)
    }

    pub fn totp_enabled(&self, principal_id: PrincipalId) -> Result<bool, StateError> {
        Ok(self
            .totp_record(principal_id)?
            .map(|record| record.enabled)
            .unwrap_or(false))
    }

    pub fn set_totp_pending_secret(
        &self,
        principal_id: PrincipalId,
        secret: &TotpSecret,
        now: i64,
    ) -> Result<(), StateError> {
        let connection = self.lock()?;
        connection
            .execute(
                "INSERT INTO admin_principal_totp
                     (principal_id, secret, enabled, pending_secret, updated_at)
                 VALUES (?1, NULL, 0, ?2, ?3)
                 ON CONFLICT (principal_id) DO UPDATE SET
                     pending_secret = excluded.pending_secret,
                     updated_at = excluded.updated_at",
                params![principal_id.to_string(), secret.expose_for_storage(), now],
            )
            .map_err(StateError::database)?;
        Ok(())
    }

    pub fn confirm_totp_enrollment(
        &self,
        principal_id: PrincipalId,
        now: i64,
    ) -> Result<(), StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        let row = transaction
            .query_row(
                "SELECT pending_secret FROM admin_principal_totp WHERE principal_id = ?1",
                [principal_id.to_string()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(StateError::database)?;
        let Some(Some(pending)) = row else {
            return Err(StateError::Corrupt("no pending TOTP enrollment"));
        };
        transaction
            .execute(
                "UPDATE admin_principal_totp
                 SET secret = ?2, enabled = 1, pending_secret = NULL, updated_at = ?3
                 WHERE principal_id = ?1",
                params![principal_id.to_string(), pending, now],
            )
            .map_err(StateError::database)?;
        transaction.commit().map_err(StateError::database)
    }

    pub fn disable_totp(&self, principal_id: PrincipalId, now: i64) -> Result<(), StateError> {
        let connection = self.lock()?;
        connection
            .execute(
                "UPDATE admin_principal_totp
                 SET secret = NULL, enabled = 0, pending_secret = NULL, updated_at = ?2
                 WHERE principal_id = ?1",
                params![principal_id.to_string(), now],
            )
            .map_err(StateError::database)?;
        Ok(())
    }

    pub fn totp_secret_for_verification(
        &self,
        principal_id: PrincipalId,
    ) -> Result<Option<TotpSecret>, StateError> {
        let record = self.totp_record(principal_id)?;
        Ok(record.and_then(|row| if row.enabled { row.secret } else { None }))
    }

    pub fn totp_pending_secret(
        &self,
        principal_id: PrincipalId,
    ) -> Result<Option<TotpSecret>, StateError> {
        Ok(self
            .totp_record(principal_id)?
            .and_then(|row| row.pending_secret))
    }

    pub fn insert_totp_pre_session(
        &self,
        principal_id: PrincipalId,
        digest: &SessionTokenDigest,
        created_at: i64,
        expires_at: i64,
    ) -> Result<SessionId, StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        transaction
            .execute(
                "DELETE FROM admin_totp_pre_sessions WHERE expires_at <= ?1",
                [created_at],
            )
            .map_err(StateError::database)?;
        let id = SessionId::new();
        transaction
            .execute(
                "INSERT INTO admin_totp_pre_sessions
                     (id, principal_id, token_digest, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    id.to_string(),
                    principal_id.to_string(),
                    digest.expose_for_storage(),
                    created_at,
                    expires_at
                ],
            )
            .map_err(StateError::database)?;
        transaction.commit().map_err(StateError::database)?;
        Ok(id)
    }

    /// Resolves a live pre-session by digest without consuming it.
    pub fn resolve_totp_pre_session(
        &self,
        digest: &SessionTokenDigest,
        now: i64,
    ) -> Result<Option<PrincipalId>, StateError> {
        let connection = self.lock()?;
        let row = connection
            .query_row(
                "SELECT principal_id, expires_at
                 FROM admin_totp_pre_sessions WHERE token_digest = ?1",
                [digest.expose_for_storage()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(StateError::database)?;
        let Some((principal_id, expires_at)) = row else {
            return Ok(None);
        };
        if now >= expires_at {
            connection
                .execute(
                    "DELETE FROM admin_totp_pre_sessions WHERE token_digest = ?1",
                    [digest.expose_for_storage()],
                )
                .map_err(StateError::database)?;
            return Ok(None);
        }
        principal_id
            .parse()
            .map(Some)
            .map_err(|_| StateError::Corrupt("stored pre-session principal id is invalid"))
    }

    /// Deletes one pre-session after TOTP succeeds (single-use completion).
    pub fn revoke_totp_pre_session(&self, digest: &SessionTokenDigest) -> Result<bool, StateError> {
        let connection = self.lock()?;
        let removed = connection
            .execute(
                "DELETE FROM admin_totp_pre_sessions WHERE token_digest = ?1",
                [digest.expose_for_storage()],
            )
            .map_err(StateError::database)?;
        Ok(removed > 0)
    }

    pub fn totp_pre_session_digests_for_test(&self) -> Result<Vec<String>, StateError> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT token_digest FROM admin_totp_pre_sessions ORDER BY token_digest")
            .map_err(StateError::database)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(StateError::database)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StateError::database)
    }

    fn read_totp_record(
        connection: &rusqlite::Connection,
        principal_id: PrincipalId,
    ) -> Result<Option<TotpRecord>, StateError> {
        let row = connection
            .query_row(
                "SELECT enabled, secret, pending_secret, updated_at
                 FROM admin_principal_totp WHERE principal_id = ?1",
                [principal_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(StateError::database)?;
        let Some((enabled, secret, pending_secret, updated_at)) = row else {
            return Ok(None);
        };
        Ok(Some(TotpRecord {
            enabled: enabled == 1,
            secret: secret
                .map(|value| {
                    TotpSecret::parse(value)
                        .map_err(|_| StateError::Corrupt("stored TOTP secret is invalid"))
                })
                .transpose()?,
            pending_secret: pending_secret
                .map(|value| {
                    TotpSecret::parse(value)
                        .map_err(|_| StateError::Corrupt("stored pending TOTP secret is invalid"))
                })
                .transpose()?,
            updated_at,
        }))
    }
}
