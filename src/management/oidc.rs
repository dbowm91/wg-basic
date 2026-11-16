//! Generic OIDC provider settings and login/link flows.
//!
//! Runs on the worker thread. Token exchange uses a blocking HTTP client so the
//! Tokio runtime is not blocked; only this module performs external HTTP for IdP
//! callbacks.

use crate::{
    domain::{OidcClientSecret, PrincipalId, SessionToken},
    management::auth::{AuthService, LoginOutcome},
    state::{
        OidcProviderRecord, OidcTransientKind, StateStore, OIDC_COMPLETION_LIFETIME_SECONDS,
        OIDC_TRANSIENT_LIFETIME_SECONDS,
    },
};
use oauth2::AuthType;
use openidconnect::{
    core::{
        CoreAuthenticationFlow, CoreClient, CoreIdTokenClaims, CoreProviderMetadata,
        CoreTokenResponse,
    },
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};

pub(crate) type ConfiguredOidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;
use serde::Serialize;
use std::{
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) const OIDC_SCOPES: &[&str] = &["openid", "email", "profile"];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OidcPublicView {
    pub login_enabled: bool,
    pub display_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OidcSettingsView {
    pub issuer: String,
    pub client_id: String,
    pub client_secret_configured: bool,
    pub display_name: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub struct OidcSettingsUpdate {
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub set_client_secret: Option<String>,
    pub clear_client_secret: bool,
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcError {
    StorageUnavailable,
    NotConfigured,
    HttpsOriginRequired,
    InvalidUpdate,
    FlowRejected,
    IdPUnavailable,
}

#[derive(Clone, Debug)]
pub struct OidcAuthorizeStart {
    pub authorize_url: String,
}

#[derive(Clone, Debug)]
pub struct OidcCallbackSuccess {
    /// Raw completion bearer for the Lax one-shot cookie.
    pub completion_token: SessionToken,
}

#[derive(Clone, Debug)]
pub struct OidcLinkStart {
    pub authorize_url: String,
}

pub struct OidcService<'a> {
    store: &'a StateStore,
    auth: AuthService<'a>,
    canonical_origin: String,
}

impl<'a> OidcService<'a> {
    pub fn new(store: &'a StateStore, canonical_origin: impl Into<String>) -> Self {
        Self {
            store,
            auth: AuthService::new(store),
            canonical_origin: canonical_origin.into(),
        }
    }

    fn now_seconds() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0)
    }

    fn origin_is_https(&self) -> bool {
        self.canonical_origin.starts_with("https://")
    }

    pub fn public_view(&self) -> Result<OidcPublicView, OidcError> {
        let record = self
            .store
            .oidc_provider()
            .map_err(|_| OidcError::StorageUnavailable)?;
        let login_enabled = record.enabled && self.origin_is_https() && provider_ready(&record);
        Ok(OidcPublicView {
            login_enabled,
            display_name: if record.display_name.is_empty() {
                "Sign in with OIDC".to_owned()
            } else {
                record.display_name
            },
        })
    }

    pub fn settings_view(&self) -> Result<OidcSettingsView, OidcError> {
        let record = self
            .store
            .oidc_provider()
            .map_err(|_| OidcError::StorageUnavailable)?;
        Ok(project_settings(&record))
    }

    pub fn update_settings(
        &self,
        patch: OidcSettingsUpdate,
    ) -> Result<OidcSettingsView, OidcError> {
        if patch.set_client_secret.is_some() && patch.clear_client_secret {
            return Err(OidcError::InvalidUpdate);
        }
        let current = self
            .store
            .oidc_provider()
            .map_err(|_| OidcError::StorageUnavailable)?;
        let enabled = patch.enabled.unwrap_or(current.enabled);
        if enabled && !self.origin_is_https() {
            return Err(OidcError::HttpsOriginRequired);
        }
        let issuer = patch.issuer.unwrap_or(current.issuer);
        let client_id = patch.client_id.unwrap_or(current.client_id);
        let display_name = patch.display_name.unwrap_or(current.display_name.clone());
        let secret_patch = if let Some(secret) = patch.set_client_secret {
            if secret.is_empty() {
                return Err(OidcError::InvalidUpdate);
            }
            Some(OidcClientSecret::new(secret))
        } else if patch.clear_client_secret {
            return Err(OidcError::InvalidUpdate);
        } else {
            None
        };
        if enabled
            && !provider_fields_ready(
                &issuer,
                &client_id,
                secret_patch.as_ref(),
                current.client_secret.is_empty(),
            )
        {
            return Err(OidcError::InvalidUpdate);
        }
        let now = Self::now_seconds();
        self.store
            .update_oidc_provider(
                &issuer,
                &client_id,
                secret_patch.as_ref(),
                &display_name,
                enabled,
                now,
            )
            .map_err(|_| OidcError::StorageUnavailable)?;
        self.settings_view()
    }

    pub fn begin_login(&self) -> Result<OidcAuthorizeStart, OidcError> {
        // IdP HTTP must not run inside the worker's Tokio `block_on` loop.
        std::thread::scope(|scope| scope.spawn(|| self.begin_login_impl()).join().unwrap())
    }

    fn begin_login_impl(&self) -> Result<OidcAuthorizeStart, OidcError> {
        let record = active_provider(self.store, self.origin_is_https())?;
        let (client, redirect) = build_client(&record, &self.canonical_origin, "callback")?;
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let mut authorize = client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in OIDC_SCOPES {
            authorize = authorize.add_scope(Scope::new(scope.to_string()));
        }
        let (auth_url, csrf_state, nonce) = authorize.set_pkce_challenge(pkce_challenge).url();
        let state_digest = SessionToken::digest_of(csrf_state.secret());
        let created = Self::now_seconds();
        self.store
            .insert_oidc_transient(
                OidcTransientKind::Login,
                "oidc",
                &state_digest,
                pkce_verifier.secret(),
                None,
                nonce.secret(),
                created,
                created + OIDC_TRANSIENT_LIFETIME_SECONDS,
            )
            .map_err(|_| OidcError::StorageUnavailable)?;
        let _ = redirect;
        Ok(OidcAuthorizeStart {
            authorize_url: auth_url.to_string(),
        })
    }

    pub fn begin_link(&self, principal_id: PrincipalId) -> Result<OidcLinkStart, OidcError> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.begin_link_impl(principal_id))
                .join()
                .unwrap()
        })
    }

    fn begin_link_impl(&self, principal_id: PrincipalId) -> Result<OidcLinkStart, OidcError> {
        let record = active_provider(self.store, self.origin_is_https())?;
        let (client, _) = build_client(&record, &self.canonical_origin, "link/callback")?;
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let mut authorize = client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in OIDC_SCOPES {
            authorize = authorize.add_scope(Scope::new(scope.to_string()));
        }
        let (auth_url, csrf_state, nonce) = authorize.set_pkce_challenge(pkce_challenge).url();
        let state_digest = SessionToken::digest_of(csrf_state.secret());
        let created = Self::now_seconds();
        self.store
            .insert_oidc_transient(
                OidcTransientKind::Link,
                "oidc",
                &state_digest,
                pkce_verifier.secret(),
                Some(principal_id),
                nonce.secret(),
                created,
                created + OIDC_TRANSIENT_LIFETIME_SECONDS,
            )
            .map_err(|_| OidcError::StorageUnavailable)?;
        Ok(OidcLinkStart {
            authorize_url: auth_url.to_string(),
        })
    }

    pub fn complete_login_callback(
        &self,
        state: &str,
        code: &str,
    ) -> Result<OidcCallbackSuccess, OidcError> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.finish_login_callback(state, code))
                .join()
                .unwrap()
        })
    }

    pub fn complete_link_callback(&self, state: &str, code: &str) -> Result<(), OidcError> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.complete_link_callback_impl(state, code))
                .join()
                .unwrap()
        })
    }

    fn complete_link_callback_impl(&self, state: &str, code: &str) -> Result<(), OidcError> {
        let claims = self.exchange_callback(state, code, OidcTransientKind::Link)?;
        let principal_id = claims.principal_id.ok_or(OidcError::FlowRejected)?;
        self.store
            .upsert_idp_link(
                principal_id,
                &claims.issuer,
                &claims.subject,
                &claims.email,
                claims.now,
            )
            .map_err(|_| OidcError::StorageUnavailable)?;
        let audit = crate::state::ProductAudit::principal(
            crate::product::AuditAction::AdminIdpLinked,
            principal_id,
        );
        let _ = self.store.append_audit_event(Some(principal_id), audit);
        Ok(())
    }

    fn exchange_callback(
        &self,
        state: &str,
        code: &str,
        expected_kind: OidcTransientKind,
    ) -> Result<CallbackClaims, OidcError> {
        let state_digest = SessionToken::digest_of(state);
        let now = Self::now_seconds();
        let transient = self
            .store
            .take_oidc_transient_by_state(&state_digest, now)
            .map_err(|_| OidcError::StorageUnavailable)?
            .ok_or(OidcError::FlowRejected)?;
        if transient.kind != expected_kind {
            return Err(OidcError::FlowRejected);
        }
        let record = active_provider(self.store, self.origin_is_https())?;
        let redirect_suffix = match expected_kind {
            OidcTransientKind::Login => "callback",
            OidcTransientKind::Link => "link/callback",
        };
        let (client, _) = build_client(&record, &self.canonical_origin, redirect_suffix)?;
        let token_request = client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|_| OidcError::FlowRejected)?;
        let token_response = token_request
            .set_pkce_verifier(PkceCodeVerifier::new(transient.pkce_verifier.clone()))
            .request(http_client())
            .map_err(|_| OidcError::IdPUnavailable)?;
        let token_response: CoreTokenResponse = token_response;
        let id_token = token_response
            .id_token()
            .ok_or(OidcError::FlowRejected)?
            .to_owned();
        let verifier = client.id_token_verifier();
        let claims = id_token
            .claims(&verifier, &Nonce::new(transient.nonce.clone()))
            .map_err(|_| OidcError::FlowRejected)?;
        validate_claims(claims, now)?;
        let email = claims
            .email()
            .map(|m| m.as_str().to_owned())
            .filter(|e| !e.is_empty())
            .ok_or(OidcError::FlowRejected)?;
        Ok(CallbackClaims {
            issuer: record.issuer.clone(),
            subject: claims.subject().as_str().to_owned(),
            email,
            principal_id: transient.principal_id,
            now,
        })
    }

    fn finish_login_callback(
        &self,
        state: &str,
        code: &str,
    ) -> Result<OidcCallbackSuccess, OidcError> {
        let claims = self.exchange_callback(state, code, OidcTransientKind::Login)?;
        let principal_id = super::idp_auth::resolve_login_principal_oidc(
            self.store,
            &claims.issuer,
            &claims.subject,
            &claims.email,
            claims.now,
        )?;
        mint_completion(self.store, principal_id, claims.now)
    }

    pub fn exchange_completion(
        &self,
        presented_completion: &str,
    ) -> Result<LoginOutcome, OidcError> {
        if presented_completion.is_empty() {
            return Err(OidcError::FlowRejected);
        }
        let digest = SessionToken::digest_of(presented_completion);
        let now = Self::now_seconds();
        let completion = self
            .store
            .take_oidc_completion(&digest, now)
            .map_err(|_| OidcError::StorageUnavailable)?
            .ok_or(OidcError::FlowRejected)?;
        if completion.totp_required {
            let principal_id = completion.principal_id;
            let pre = self
                .auth
                .issue_pre_session_for_principal(principal_id)
                .map_err(|_| OidcError::StorageUnavailable)?;
            return Ok(LoginOutcome::TotpChallenge(pre));
        }
        let session = self
            .auth
            .issue_session_for_principal(completion.principal_id)
            .map_err(|_| OidcError::StorageUnavailable)?;
        Ok(LoginOutcome::Session(session))
    }
}

pub struct CallbackClaims {
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub principal_id: Option<PrincipalId>,
    pub now: i64,
}

pub(crate) fn mint_completion(
    store: &StateStore,
    principal_id: PrincipalId,
    now: i64,
) -> Result<OidcCallbackSuccess, OidcError> {
    let totp_required = store
        .totp_enabled(principal_id)
        .map_err(|_| OidcError::StorageUnavailable)?;
    let token = SessionToken::generate().map_err(|_| OidcError::FlowRejected)?;
    let digest = token.digest();
    store
        .insert_oidc_completion(
            &digest,
            principal_id,
            totp_required,
            None,
            now,
            now + OIDC_COMPLETION_LIFETIME_SECONDS,
        )
        .map_err(|_| OidcError::StorageUnavailable)?;
    Ok(OidcCallbackSuccess {
        completion_token: token,
    })
}

pub(crate) fn validate_claims(claims: &CoreIdTokenClaims, now: i64) -> Result<(), OidcError> {
    if claims.expiration().timestamp() <= now {
        return Err(OidcError::FlowRejected);
    }
    Ok(())
}

fn provider_ready(record: &OidcProviderRecord) -> bool {
    provider_fields_ready(
        &record.issuer,
        &record.client_id,
        None,
        record.client_secret.is_empty(),
    )
}

fn provider_fields_ready(
    issuer: &str,
    client_id: &str,
    secret_patch: Option<&OidcClientSecret>,
    secret_empty: bool,
) -> bool {
    !issuer.is_empty()
        && !client_id.is_empty()
        && (secret_patch.is_some_and(|s| !s.is_empty()) || !secret_empty)
}

fn active_provider(store: &StateStore, https: bool) -> Result<OidcProviderRecord, OidcError> {
    if !https {
        return Err(OidcError::HttpsOriginRequired);
    }
    let record = store
        .oidc_provider()
        .map_err(|_| OidcError::StorageUnavailable)?;
    if !record.enabled || !provider_ready(&record) {
        return Err(OidcError::NotConfigured);
    }
    Ok(record)
}

fn project_settings(record: &OidcProviderRecord) -> OidcSettingsView {
    OidcSettingsView {
        issuer: record.issuer.clone(),
        client_id: record.client_id.clone(),
        client_secret_configured: !record.client_secret.is_empty(),
        display_name: record.display_name.clone(),
        enabled: record.enabled,
    }
}

fn build_client(
    record: &OidcProviderRecord,
    canonical_origin: &str,
    callback_suffix: &str,
) -> Result<(ConfiguredOidcClient, RedirectUrl), OidcError> {
    let issuer = IssuerUrl::new(record.issuer.clone()).map_err(|_| OidcError::InvalidUpdate)?;
    let metadata = CoreProviderMetadata::discover(&issuer, http_client())
        .map_err(|_| OidcError::IdPUnavailable)?;
    let redirect = RedirectUrl::new(format!(
        "{canonical_origin}/api/v1/auth/oidc/{callback_suffix}"
    ))
    .map_err(|_| OidcError::InvalidUpdate)?;
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(record.client_id.clone()),
        Some(ClientSecret::new(record.client_secret.expose().to_owned())),
    )
    .set_auth_type(AuthType::RequestBody)
    .set_redirect_uri(redirect.clone());
    Ok((client, redirect))
}

fn http_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("OIDC HTTP client")
    })
}
