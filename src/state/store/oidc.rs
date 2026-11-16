//! Generic OIDC settings, IdP subject links, and in-flight authorization rows.

use super::StateStore;
use crate::{
    domain::{OidcClientSecret, PrincipalId, SessionTokenDigest},
    state::error::StateError,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use std::str::FromStr;
use uuid::Uuid;

/// How long an OIDC transient (state/PKCE) may live, in seconds.
pub const OIDC_TRANSIENT_LIFETIME_SECONDS: i64 = 10 * 60;

/// How long a login-completion token may live, in seconds.
pub const OIDC_COMPLETION_LIFETIME_SECONDS: i64 = 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcProviderRecord {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: OidcClientSecret,
    pub display_name: String,
    pub enabled: bool,
    pub updated_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcTransientKind {
    Login,
    Link,
}

impl OidcTransientKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Link => "link",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "login" => Some(Self::Login),
            "link" => Some(Self::Link),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcTransientRecord {
    pub id: String,
    pub kind: OidcTransientKind,
    pub provider: String,
    pub state_digest: SessionTokenDigest,
    pub pkce_verifier: String,
    pub principal_id: Option<PrincipalId>,
    pub nonce: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdPSubjectLink {
    pub principal_id: PrincipalId,
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub linked_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcCompletionRecord {
    pub principal_id: PrincipalId,
    pub totp_required: bool,
    pub pre_session_id: Option<String>,
    pub expires_at: i64,
}

impl StateStore {
    pub fn oidc_provider(&self) -> Result<OidcProviderRecord, StateError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT issuer, client_id, client_secret, display_name, enabled, updated_at
                 FROM oidc_provider_settings WHERE singleton = 1",
                [],
                |row| {
                    Ok(OidcProviderRecord {
                        issuer: row.get(0)?,
                        client_id: row.get(1)?,
                        client_secret: OidcClientSecret::new(row.get::<_, String>(2)?),
                        display_name: row.get(3)?,
                        enabled: row.get::<_, i64>(4)? != 0,
                        updated_at: row.get(5)?,
                    })
                },
            )
            .map_err(|_| StateError::Corrupt("oidc provider settings row is missing"))
    }

    pub fn update_oidc_provider(
        &self,
        issuer: &str,
        client_id: &str,
        client_secret: Option<&OidcClientSecret>,
        display_name: &str,
        enabled: bool,
        now: i64,
    ) -> Result<(), StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        if let Some(secret) = client_secret {
            transaction
                .execute(
                    "UPDATE oidc_provider_settings
                     SET issuer = ?1, client_id = ?2, client_secret = ?3,
                         display_name = ?4, enabled = ?5, updated_at = ?6
                     WHERE singleton = 1",
                    params![
                        issuer,
                        client_id,
                        secret.expose(),
                        display_name,
                        i64::from(enabled),
                        now
                    ],
                )
                .map_err(StateError::database)?;
        } else {
            transaction
                .execute(
                    "UPDATE oidc_provider_settings
                     SET issuer = ?1, client_id = ?2, display_name = ?3,
                         enabled = ?4, updated_at = ?5
                     WHERE singleton = 1",
                    params![issuer, client_id, display_name, i64::from(enabled), now],
                )
                .map_err(StateError::database)?;
        }
        transaction.commit().map_err(StateError::database)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_oidc_transient(
        &self,
        kind: OidcTransientKind,
        provider: &str,
        state_digest: &SessionTokenDigest,
        pkce_verifier: &str,
        principal_id: Option<PrincipalId>,
        nonce: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), StateError> {
        let connection = self.lock()?;
        let id = Uuid::new_v4().to_string();
        connection
            .execute(
                "INSERT INTO oidc_auth_transients
                     (id, kind, provider, state_digest, pkce_verifier, principal_id, nonce, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    id,
                    kind.as_str(),
                    provider,
                    state_digest.expose_for_storage(),
                    pkce_verifier,
                    principal_id.map(|id| id.to_string()),
                    nonce,
                    created_at,
                    expires_at
                ],
            )
            .map_err(StateError::database)?;
        Ok(())
    }

    pub fn take_oidc_transient_by_state(
        &self,
        state_digest: &SessionTokenDigest,
        now: i64,
    ) -> Result<Option<OidcTransientRecord>, StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        let row = transaction
            .query_row(
                "SELECT id, kind, provider, state_digest, pkce_verifier, principal_id, nonce, expires_at
                 FROM oidc_auth_transients
                 WHERE state_digest = ?1 AND expires_at > ?2",
                params![state_digest.expose_for_storage(), now],
                |row| {
                    let kind: String = row.get(1)?;
                    Ok(OidcTransientRecord {
                        id: row.get(0)?,
                        kind: OidcTransientKind::parse(&kind)
                            .ok_or_else(|| rusqlite::Error::InvalidQuery)?,
                        provider: row.get(2)?,
                        state_digest: SessionTokenDigest::parse(row.get::<_, String>(3)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        pkce_verifier: row.get(4)?,
                        principal_id: row
                            .get::<_, Option<String>>(5)?
                            .and_then(|raw| PrincipalId::from_str(&raw).ok()),
                        nonce: row.get(6)?,
                        expires_at: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(StateError::database)?;
        if let Some(ref record) = row {
            transaction
                .execute(
                    "DELETE FROM oidc_auth_transients WHERE id = ?1",
                    params![record.id],
                )
                .map_err(StateError::database)?;
        }
        transaction.commit().map_err(StateError::database)?;
        Ok(row)
    }

    pub fn purge_expired_oidc_transients(&self, now: i64) -> Result<usize, StateError> {
        let connection = self.lock()?;
        connection
            .execute(
                "DELETE FROM oidc_auth_transients WHERE expires_at <= ?1",
                params![now],
            )
            .map_err(StateError::database)
    }

    pub fn upsert_idp_link(
        &self,
        principal_id: PrincipalId,
        issuer: &str,
        subject: &str,
        email: &str,
        linked_at: i64,
    ) -> Result<(), StateError> {
        let connection = self.lock()?;
        connection
            .execute(
                "INSERT INTO admin_idp_subject_links
                     (principal_id, issuer, subject, email, linked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (issuer, subject) DO UPDATE SET
                     principal_id = excluded.principal_id,
                     email = excluded.email,
                     linked_at = excluded.linked_at",
                params![principal_id.to_string(), issuer, subject, email, linked_at],
            )
            .map_err(StateError::database)?;
        Ok(())
    }

    pub fn idp_link_by_subject(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<IdPSubjectLink>, StateError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT principal_id, issuer, subject, email, linked_at
                 FROM admin_idp_subject_links WHERE issuer = ?1 AND subject = ?2",
                params![issuer, subject],
                |row| {
                    Ok(IdPSubjectLink {
                        principal_id: PrincipalId::from_str(&row.get::<_, String>(0)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        issuer: row.get(1)?,
                        subject: row.get(2)?,
                        email: row.get(3)?,
                        linked_at: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(StateError::database)
    }

    pub fn insert_oidc_completion(
        &self,
        token_digest: &SessionTokenDigest,
        principal_id: PrincipalId,
        totp_required: bool,
        pre_session_id: Option<&str>,
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), StateError> {
        let connection = self.lock()?;
        let id = Uuid::new_v4().to_string();
        connection
            .execute(
                "INSERT INTO oidc_login_completions
                     (id, token_digest, principal_id, totp_required, pre_session_id, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id,
                    token_digest.expose_for_storage(),
                    principal_id.to_string(),
                    i64::from(totp_required),
                    pre_session_id,
                    created_at,
                    expires_at
                ],
            )
            .map_err(StateError::database)?;
        Ok(())
    }

    pub fn take_oidc_completion(
        &self,
        token_digest: &SessionTokenDigest,
        now: i64,
    ) -> Result<Option<OidcCompletionRecord>, StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        let row = transaction
            .query_row(
                "SELECT principal_id, totp_required, pre_session_id, expires_at
                 FROM oidc_login_completions
                 WHERE token_digest = ?1 AND expires_at > ?2",
                params![token_digest.expose_for_storage(), now],
                |row| {
                    Ok(OidcCompletionRecord {
                        principal_id: PrincipalId::from_str(&row.get::<_, String>(0)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        totp_required: row.get::<_, i64>(1)? != 0,
                        pre_session_id: row.get(2)?,
                        expires_at: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(StateError::database)?;
        if row.is_some() {
            transaction
                .execute(
                    "DELETE FROM oidc_login_completions WHERE token_digest = ?1",
                    params![token_digest.expose_for_storage()],
                )
                .map_err(StateError::database)?;
        }
        transaction.commit().map_err(StateError::database)?;
        Ok(row)
    }

    pub fn purge_expired_oidc_completions(&self, now: i64) -> Result<usize, StateError> {
        let connection = self.lock()?;
        connection
            .execute(
                "DELETE FROM oidc_login_completions WHERE expires_at <= ?1",
                params![now],
            )
            .map_err(StateError::database)
    }
}
