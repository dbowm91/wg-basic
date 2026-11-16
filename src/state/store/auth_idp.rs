//! IdP policy, branded OAuth providers, and principal linkage queries.

use super::StateStore;
use crate::{
    domain::{OidcClientSecret, PrincipalId},
    state::error::StateError,
};
use rusqlite::{params, TransactionBehavior};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthIdpPolicyRecord {
    pub auto_register: bool,
    pub allowed_domains: String,
    pub auto_launch: String,
    pub password_auth_enabled: bool,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrandedOAuthProviderRecord {
    pub provider: String,
    pub client_id: String,
    pub client_secret: OidcClientSecret,
    pub display_name: String,
    pub enabled: bool,
    pub issuer: String,
    pub oauth_host: String,
    pub updated_at: i64,
}

impl StateStore {
    pub fn auth_idp_policy(&self) -> Result<AuthIdpPolicyRecord, StateError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT auto_register, allowed_domains, auto_launch, password_auth_enabled, updated_at
                 FROM auth_idp_policy WHERE singleton = 1",
                [],
                |row| {
                    Ok(AuthIdpPolicyRecord {
                        auto_register: row.get::<_, i64>(0)? != 0,
                        allowed_domains: row.get(1)?,
                        auto_launch: row.get(2)?,
                        password_auth_enabled: row.get::<_, i64>(3)? != 0,
                        updated_at: row.get(4)?,
                    })
                },
            )
            .map_err(|_| StateError::Corrupt("auth idp policy row is missing"))
    }

    pub fn update_auth_idp_policy(
        &self,
        auto_register: bool,
        allowed_domains: &str,
        auto_launch: &str,
        password_auth_enabled: bool,
        now: i64,
    ) -> Result<(), StateError> {
        let connection = self.lock()?;
        connection
            .execute(
                "UPDATE auth_idp_policy
                 SET auto_register = ?1, allowed_domains = ?2, auto_launch = ?3,
                     password_auth_enabled = ?4, updated_at = ?5
                 WHERE singleton = 1",
                params![
                    i64::from(auto_register),
                    allowed_domains,
                    auto_launch,
                    i64::from(password_auth_enabled),
                    now
                ],
            )
            .map_err(StateError::database)?;
        Ok(())
    }

    pub fn set_password_auth_enabled(&self, enabled: bool, now: i64) -> Result<(), StateError> {
        let connection = self.lock()?;
        connection
            .execute(
                "UPDATE auth_idp_policy SET password_auth_enabled = ?1, updated_at = ?2 WHERE singleton = 1",
                params![i64::from(enabled), now],
            )
            .map_err(StateError::database)?;
        Ok(())
    }

    pub fn branded_oauth_provider(
        &self,
        provider: &str,
    ) -> Result<BrandedOAuthProviderRecord, StateError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT provider, client_id, client_secret, display_name, enabled, issuer, oauth_host, updated_at
                 FROM oauth_branded_providers WHERE provider = ?1",
                [provider],
                |row| {
                    Ok(BrandedOAuthProviderRecord {
                        provider: row.get(0)?,
                        client_id: row.get(1)?,
                        client_secret: OidcClientSecret::new(row.get::<_, String>(2)?),
                        display_name: row.get(3)?,
                        enabled: row.get::<_, i64>(4)? != 0,
                        issuer: row.get(5)?,
                        oauth_host: row.get(6)?,
                        updated_at: row.get(7)?,
                    })
                },
            )
            .map_err(|_| StateError::Corrupt("branded oauth provider row is missing"))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_branded_oauth_provider(
        &self,
        provider: &str,
        client_id: &str,
        client_secret: Option<&OidcClientSecret>,
        display_name: &str,
        enabled: bool,
        issuer: &str,
        oauth_host: &str,
        now: i64,
    ) -> Result<(), StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        if let Some(secret) = client_secret {
            transaction
                .execute(
                    "UPDATE oauth_branded_providers
                     SET client_id = ?2, client_secret = ?3, display_name = ?4,
                         enabled = ?5, issuer = ?6, oauth_host = ?7, updated_at = ?8
                     WHERE provider = ?1",
                    params![
                        provider,
                        client_id,
                        secret.expose(),
                        display_name,
                        i64::from(enabled),
                        issuer,
                        oauth_host,
                        now
                    ],
                )
                .map_err(StateError::database)?;
        } else {
            transaction
                .execute(
                    "UPDATE oauth_branded_providers
                     SET client_id = ?2, display_name = ?3, enabled = ?4,
                         issuer = ?5, oauth_host = ?6, updated_at = ?7
                     WHERE provider = ?1",
                    params![
                        provider,
                        client_id,
                        display_name,
                        i64::from(enabled),
                        issuer,
                        oauth_host,
                        now
                    ],
                )
                .map_err(StateError::database)?;
        }
        transaction.commit().map_err(StateError::database)
    }

    /// Enabled principals that have at least one IdP subject link.
    pub fn count_enabled_principals_with_idp_links(&self) -> Result<i64, StateError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT COUNT(DISTINCT p.id)
                 FROM admin_principals p
                 INNER JOIN admin_idp_subject_links l ON l.principal_id = p.id
                 WHERE p.enabled = 1",
                [],
                |row| row.get(0),
            )
            .map_err(StateError::database)
    }

    pub fn principal_id_by_idp_email(
        &self,
        email: &str,
    ) -> Result<Option<PrincipalId>, StateError> {
        if let Some(principal) = self.principal_by_username(email)? {
            return Ok(Some(principal.id));
        }
        if let Some(local) = email.split('@').next() {
            if let Some(principal) = self.principal_by_username(local)? {
                return Ok(Some(principal.id));
            }
        }
        Ok(None)
    }

    pub fn insert_idp_principal(
        &self,
        username: &str,
        verifier: crate::domain::PasswordVerifier,
        now: i64,
    ) -> Result<PrincipalId, StateError> {
        let id = PrincipalId::new();
        let connection = self.lock()?;
        connection
            .execute(
                "INSERT INTO admin_principals (id, username, verifier, enabled, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 1, ?4, ?4)",
                params![
                    id.to_string(),
                    username,
                    verifier.expose_for_storage(),
                    now
                ],
            )
            .map_err(StateError::database)?;
        Ok(id)
    }

    pub fn idp_link_exists_for_principal(
        &self,
        principal_id: PrincipalId,
    ) -> Result<bool, StateError> {
        let connection = self.lock()?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM admin_idp_subject_links WHERE principal_id = ?1",
                [principal_id.to_string()],
                |row| row.get(0),
            )
            .map_err(StateError::database)?;
        Ok(count > 0)
    }

    pub fn any_idp_provider_enabled(&self) -> Result<bool, StateError> {
        let connection = self.lock()?;
        let oidc: i64 = connection
            .query_row(
                "SELECT enabled FROM oidc_provider_settings WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let branded: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM oauth_branded_providers WHERE enabled = 1",
                [],
                |row| row.get(0),
            )
            .map_err(StateError::database)?;
        Ok(oidc != 0 || branded > 0)
    }
}
