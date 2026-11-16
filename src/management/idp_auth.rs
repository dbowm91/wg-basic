//! Multi-provider IdP login, policy, and branded OAuth (M004).

use super::auth::LoginOutcome;
use super::oidc::{
    mint_completion, validate_claims, CallbackClaims, ConfiguredOidcClient, OidcAuthorizeStart,
    OidcCallbackSuccess, OidcError, OidcLinkStart, OidcService, OIDC_SCOPES,
};
use crate::{
    domain::{
        email_allowed_by_domain_list, format_allowed_domains, parse_allowed_domains,
        username_from_idp_email, OidcClientSecret, PasswordVerifier, PrincipalId, SessionToken,
    },
    product::AuditAction,
    state::{
        AuthIdpPolicyRecord, BrandedOAuthProviderRecord, OidcTransientKind, OidcTransientRecord,
        ProductAudit, StateStore, OIDC_TRANSIENT_LIFETIME_SECONDS,
    },
};
use oauth2::AuthType;
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreTokenResponse},
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::Serialize;
use std::{
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum IdpProviderKey {
    Oidc,
    Google,
    Github,
}

impl IdpProviderKey {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Google => "google",
            Self::Github => "github",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "oidc" => Some(Self::Oidc),
            "google" => Some(Self::Google),
            "github" => Some(Self::Github),
            _ => None,
        }
    }

    pub fn login_path(self) -> &'static str {
        match self {
            Self::Oidc => "/api/v1/auth/oidc/login",
            Self::Google => "/api/v1/auth/google/login",
            Self::Github => "/api/v1/auth/github/login",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdpProviderPublicEntry {
    pub key: String,
    pub login_enabled: bool,
    pub display_name: String,
    pub login_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdpLoginPublicView {
    pub password_auth_enabled: bool,
    pub providers: Vec<IdpProviderPublicEntry>,
    pub auto_launch: Option<String>,
    pub recovery_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthIdpPolicyView {
    pub auto_register: bool,
    pub allowed_domains: Vec<String>,
    pub auto_launch: String,
    pub password_auth_enabled: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub struct AuthIdpPolicyUpdate {
    pub auto_register: Option<bool>,
    pub allowed_domains: Option<Vec<String>>,
    pub auto_launch: Option<String>,
    pub password_auth_enabled: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BrandedProviderSettingsView {
    pub client_id: String,
    pub client_secret_configured: bool,
    pub display_name: String,
    pub enabled: bool,
    pub issuer: String,
    pub oauth_host: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub struct BrandedProviderSettingsUpdate {
    pub client_id: Option<String>,
    pub set_client_secret: Option<String>,
    pub clear_client_secret: bool,
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
    pub issuer: Option<String>,
    pub oauth_host: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdpAuthError {
    StorageUnavailable,
    NotConfigured,
    HttpsOriginRequired,
    InvalidUpdate,
    FlowRejected,
    IdPUnavailable,
    Conflict,
}

pub struct IdpAuthService<'a> {
    store: &'a StateStore,
    canonical_origin: String,
    oidc: OidcService<'a>,
}

impl<'a> IdpAuthService<'a> {
    pub fn new(store: &'a StateStore, canonical_origin: impl Into<String>) -> Self {
        let origin = canonical_origin.into();
        Self {
            store,
            oidc: OidcService::new(store, origin.clone()),
            canonical_origin: origin,
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

    pub fn login_public_view(&self) -> Result<IdpLoginPublicView, IdpAuthError> {
        let policy = self
            .store
            .auth_idp_policy()
            .map_err(|_| IdpAuthError::StorageUnavailable)?;
        let https = self.origin_is_https();
        let mut providers = Vec::new();
        if let Ok(oidc) = self.oidc.public_view() {
            providers.push(IdpProviderPublicEntry {
                key: IdpProviderKey::Oidc.as_str().to_owned(),
                login_enabled: oidc.login_enabled,
                display_name: oidc.display_name,
                login_path: IdpProviderKey::Oidc.login_path().to_owned(),
            });
        }
        for key in [IdpProviderKey::Google, IdpProviderKey::Github] {
            if let Some(entry) = self.branded_public(key, https) {
                providers.push(entry);
            }
        }
        let any_login = providers.iter().any(|entry| entry.login_enabled);
        let recovery_only = !policy.password_auth_enabled && !any_login;
        Ok(IdpLoginPublicView {
            password_auth_enabled: policy.password_auth_enabled,
            providers,
            auto_launch: if policy.auto_launch.is_empty() {
                None
            } else {
                Some(policy.auto_launch.clone())
            },
            recovery_only,
        })
    }

    fn branded_public(&self, key: IdpProviderKey, https: bool) -> Option<IdpProviderPublicEntry> {
        let record = self.store.branded_oauth_provider(key.as_str()).ok()?;
        let ready = branded_ready(&record);
        Some(IdpProviderPublicEntry {
            key: key.as_str().to_owned(),
            login_enabled: record.enabled && https && ready,
            display_name: if record.display_name.is_empty() {
                match key {
                    IdpProviderKey::Google => "Sign in with Google".to_owned(),
                    IdpProviderKey::Github => "Sign in with GitHub".to_owned(),
                    IdpProviderKey::Oidc => "Sign in".to_owned(),
                }
            } else {
                record.display_name
            },
            login_path: key.login_path().to_owned(),
        })
    }

    pub fn policy_view(&self) -> Result<AuthIdpPolicyView, IdpAuthError> {
        let record = self
            .store
            .auth_idp_policy()
            .map_err(|_| IdpAuthError::StorageUnavailable)?;
        Ok(project_policy(&record))
    }

    pub fn update_policy(
        &self,
        patch: AuthIdpPolicyUpdate,
    ) -> Result<AuthIdpPolicyView, IdpAuthError> {
        let current = self
            .store
            .auth_idp_policy()
            .map_err(|_| IdpAuthError::StorageUnavailable)?;
        let auto_register = patch.auto_register.unwrap_or(current.auto_register);
        let allowed_domains = patch
            .allowed_domains
            .map(|list| format_allowed_domains(&list))
            .unwrap_or(current.allowed_domains.clone());
        let auto_launch = if let Some(ref key) = patch.auto_launch {
            if !key.is_empty() && IdpProviderKey::parse(key).is_none() {
                return Err(IdpAuthError::InvalidUpdate);
            }
            key.clone()
        } else {
            current.auto_launch.clone()
        };
        let password_auth_enabled = patch
            .password_auth_enabled
            .unwrap_or(current.password_auth_enabled);
        if patch.password_auth_enabled == Some(false) && !current.password_auth_enabled {
            // no-op when already disabled
        } else if patch.password_auth_enabled == Some(false) {
            let linked = self
                .store
                .count_enabled_principals_with_idp_links()
                .map_err(|_| IdpAuthError::StorageUnavailable)?;
            if linked < 1 {
                return Err(IdpAuthError::Conflict);
            }
        }
        let now = Self::now_seconds();
        self.store
            .update_auth_idp_policy(
                auto_register,
                &allowed_domains,
                &auto_launch,
                password_auth_enabled,
                now,
            )
            .map_err(|_| IdpAuthError::StorageUnavailable)?;
        self.policy_view()
    }

    pub fn branded_settings(
        &self,
        key: IdpProviderKey,
    ) -> Result<BrandedProviderSettingsView, IdpAuthError> {
        let record = self
            .store
            .branded_oauth_provider(key.as_str())
            .map_err(|_| IdpAuthError::StorageUnavailable)?;
        Ok(project_branded(&record))
    }

    pub fn update_branded(
        &self,
        key: IdpProviderKey,
        patch: BrandedProviderSettingsUpdate,
    ) -> Result<BrandedProviderSettingsView, IdpAuthError> {
        if patch.set_client_secret.is_some() && patch.clear_client_secret {
            return Err(IdpAuthError::InvalidUpdate);
        }
        let current = self
            .store
            .branded_oauth_provider(key.as_str())
            .map_err(|_| IdpAuthError::StorageUnavailable)?;
        let enabled = patch.enabled.unwrap_or(current.enabled);
        if enabled && !self.origin_is_https() {
            return Err(IdpAuthError::HttpsOriginRequired);
        }
        let client_id = patch.client_id.unwrap_or(current.client_id);
        let display_name = patch.display_name.unwrap_or(current.display_name);
        let issuer = patch.issuer.unwrap_or(current.issuer);
        let oauth_host = patch.oauth_host.unwrap_or(current.oauth_host);
        let secret_patch = if let Some(secret) = patch.set_client_secret {
            if secret.is_empty() {
                return Err(IdpAuthError::InvalidUpdate);
            }
            Some(OidcClientSecret::new(secret))
        } else if patch.clear_client_secret {
            return Err(IdpAuthError::InvalidUpdate);
        } else {
            None
        };
        if enabled
            && !branded_fields_ready(
                &client_id,
                secret_patch.as_ref(),
                current.client_secret.is_empty(),
            )
        {
            return Err(IdpAuthError::InvalidUpdate);
        }
        let now = Self::now_seconds();
        self.store
            .update_branded_oauth_provider(
                key.as_str(),
                &client_id,
                secret_patch.as_ref(),
                &display_name,
                enabled,
                &issuer,
                &oauth_host,
                now,
            )
            .map_err(|_| IdpAuthError::StorageUnavailable)?;
        self.branded_settings(key)
    }

    pub fn begin_login(
        &self,
        provider: IdpProviderKey,
    ) -> Result<OidcAuthorizeStart, IdpAuthError> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.begin_login_impl(provider))
                .join()
                .unwrap()
        })
    }

    fn begin_login_impl(
        &self,
        provider: IdpProviderKey,
    ) -> Result<OidcAuthorizeStart, IdpAuthError> {
        if provider == IdpProviderKey::Oidc {
            return self.oidc.begin_login().map_err(map_oidc_error);
        }
        if provider == IdpProviderKey::Github {
            return self.begin_github_login();
        }
        self.begin_oidc_style_login(provider)
    }

    pub fn begin_link(
        &self,
        provider: IdpProviderKey,
        principal_id: PrincipalId,
    ) -> Result<OidcLinkStart, IdpAuthError> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.begin_link_impl(provider, principal_id))
                .join()
                .unwrap()
        })
    }

    fn begin_link_impl(
        &self,
        provider: IdpProviderKey,
        principal_id: PrincipalId,
    ) -> Result<OidcLinkStart, IdpAuthError> {
        if provider == IdpProviderKey::Oidc {
            return self.oidc.begin_link(principal_id).map_err(map_oidc_error);
        }
        if provider == IdpProviderKey::Github {
            return self.begin_github_link(principal_id);
        }
        self.begin_oidc_style_link(provider, principal_id)
    }

    pub fn complete_login_callback(
        &self,
        provider: IdpProviderKey,
        state: &str,
        code: &str,
    ) -> Result<OidcCallbackSuccess, IdpAuthError> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.finish_login_callback(provider, state, code))
                .join()
                .unwrap()
        })
    }

    pub fn complete_link_callback(
        &self,
        provider: IdpProviderKey,
        state: &str,
        code: &str,
    ) -> Result<(), IdpAuthError> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.complete_link_callback_impl(provider, state, code))
                .join()
                .unwrap()
        })
    }

    fn complete_link_callback_impl(
        &self,
        provider: IdpProviderKey,
        state: &str,
        code: &str,
    ) -> Result<(), IdpAuthError> {
        let claims = self.exchange_callback(provider, state, code, OidcTransientKind::Link)?;
        let principal_id = claims.principal_id.ok_or(IdpAuthError::FlowRejected)?;
        self.store
            .upsert_idp_link(
                principal_id,
                &claims.issuer,
                &claims.subject,
                &claims.email,
                claims.now,
            )
            .map_err(|_| IdpAuthError::StorageUnavailable)?;
        let audit = ProductAudit::principal(AuditAction::AdminIdpLinked, principal_id);
        let _ = self.store.append_audit_event(Some(principal_id), audit);
        Ok(())
    }

    fn finish_login_callback(
        &self,
        provider: IdpProviderKey,
        state: &str,
        code: &str,
    ) -> Result<OidcCallbackSuccess, IdpAuthError> {
        if provider == IdpProviderKey::Oidc {
            return self
                .oidc
                .complete_login_callback(state, code)
                .map_err(map_oidc_error);
        }
        let claims = self.exchange_callback(provider, state, code, OidcTransientKind::Login)?;
        let principal_id = resolve_login_principal(self.store, &claims, provider)?;
        mint_completion(self.store, principal_id, claims.now).map_err(map_oidc_error)
    }

    pub fn exchange_completion(&self, presented: &str) -> Result<LoginOutcome, IdpAuthError> {
        self.oidc
            .exchange_completion(presented)
            .map_err(map_oidc_error)
    }

    fn begin_oidc_style_login(
        &self,
        provider: IdpProviderKey,
    ) -> Result<OidcAuthorizeStart, IdpAuthError> {
        let record = active_branded(self.store, provider, self.origin_is_https())?;
        let (client, _) = build_google_client(&record, &self.canonical_origin, "callback")?;
        start_authorize(self.store, provider, &client, None)
    }

    fn begin_oidc_style_link(
        &self,
        provider: IdpProviderKey,
        principal_id: PrincipalId,
    ) -> Result<OidcLinkStart, IdpAuthError> {
        let record = active_branded(self.store, provider, self.origin_is_https())?;
        let (client, _) = build_google_client(&record, &self.canonical_origin, "link/callback")?;
        let start = start_authorize(self.store, provider, &client, Some(principal_id))?;
        Ok(OidcLinkStart {
            authorize_url: start.authorize_url,
        })
    }

    fn begin_github_login(&self) -> Result<OidcAuthorizeStart, IdpAuthError> {
        let record = active_branded(self.store, IdpProviderKey::Github, self.origin_is_https())?;
        start_github_authorize(
            self.store,
            &record,
            &self.canonical_origin,
            "callback",
            None,
        )
    }

    fn begin_github_link(&self, principal_id: PrincipalId) -> Result<OidcLinkStart, IdpAuthError> {
        let record = active_branded(self.store, IdpProviderKey::Github, self.origin_is_https())?;
        let start = start_github_authorize(
            self.store,
            &record,
            &self.canonical_origin,
            "link/callback",
            Some(principal_id),
        )?;
        Ok(OidcLinkStart {
            authorize_url: start.authorize_url,
        })
    }

    fn exchange_callback(
        &self,
        provider: IdpProviderKey,
        state: &str,
        code: &str,
        expected_kind: OidcTransientKind,
    ) -> Result<CallbackClaims, IdpAuthError> {
        let state_digest = SessionToken::digest_of(state);
        let now = Self::now_seconds();
        let transient = self
            .store
            .take_oidc_transient_by_state(&state_digest, now)
            .map_err(|_| IdpAuthError::StorageUnavailable)?
            .ok_or(IdpAuthError::FlowRejected)?;
        if transient.kind != expected_kind || transient.provider != provider.as_str() {
            return Err(IdpAuthError::FlowRejected);
        }
        if provider == IdpProviderKey::Github {
            return exchange_github_callback(
                self.store,
                &transient,
                &self.canonical_origin,
                code,
                expected_kind,
                now,
            );
        }
        let record = active_branded(self.store, provider, self.origin_is_https())?;
        let redirect_suffix = match expected_kind {
            OidcTransientKind::Login => "callback",
            OidcTransientKind::Link => "link/callback",
        };
        let (client, _) = build_google_client(&record, &self.canonical_origin, redirect_suffix)?;
        let token_request = client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|_| IdpAuthError::FlowRejected)?;
        let token_response = token_request
            .set_pkce_verifier(PkceCodeVerifier::new(transient.pkce_verifier.clone()))
            .request(idp_http_client())
            .map_err(|_| IdpAuthError::IdPUnavailable)?;
        let token_response: CoreTokenResponse = token_response;
        let id_token = token_response
            .id_token()
            .ok_or(IdpAuthError::FlowRejected)?
            .to_owned();
        let verifier = client.id_token_verifier();
        let claims = id_token
            .claims(&verifier, &Nonce::new(transient.nonce.clone()))
            .map_err(|_| IdpAuthError::FlowRejected)?;
        validate_claims(claims, now).map_err(|_| IdpAuthError::FlowRejected)?;
        let email = claims
            .email()
            .map(|m| m.as_str().to_owned())
            .filter(|e| !e.is_empty())
            .ok_or(IdpAuthError::FlowRejected)?;
        Ok(CallbackClaims {
            issuer: record.issuer.clone(),
            subject: claims.subject().as_str().to_owned(),
            email,
            principal_id: transient.principal_id,
            now,
        })
    }
}

pub fn resolve_login_principal(
    store: &StateStore,
    claims: &CallbackClaims,
    _provider: IdpProviderKey,
) -> Result<PrincipalId, IdpAuthError> {
    let policy = store
        .auth_idp_policy()
        .map_err(|_| IdpAuthError::StorageUnavailable)?;
    let allowed_domains = parse_allowed_domains(&policy.allowed_domains);
    if !email_allowed_by_domain_list(&claims.email, &allowed_domains) {
        return Err(IdpAuthError::FlowRejected);
    }
    if let Some(link) = store
        .idp_link_by_subject(&claims.issuer, &claims.subject)
        .map_err(|_| IdpAuthError::StorageUnavailable)?
    {
        return Ok(link.principal_id);
    }
    if let Some(id) = store
        .principal_id_by_idp_email(&claims.email)
        .map_err(|_| IdpAuthError::StorageUnavailable)?
    {
        store
            .upsert_idp_link(
                id,
                &claims.issuer,
                &claims.subject,
                &claims.email,
                claims.now,
            )
            .map_err(|_| IdpAuthError::StorageUnavailable)?;
        let audit = ProductAudit::principal(AuditAction::AdminIdpLinked, id);
        let _ = store.append_audit_event(Some(id), audit);
        return Ok(id);
    }
    if !policy.auto_register {
        return Err(IdpAuthError::FlowRejected);
    }
    let username = username_from_idp_email(&claims.email).ok_or(IdpAuthError::FlowRejected)?;
    let random = SessionToken::generate().map_err(|_| IdpAuthError::FlowRejected)?;
    let verifier =
        PasswordVerifier::hash(random.expose_once()).map_err(|_| IdpAuthError::FlowRejected)?;
    let principal_id = store
        .insert_idp_principal(&username, verifier, claims.now)
        .map_err(|_| IdpAuthError::StorageUnavailable)?;
    store
        .upsert_idp_link(
            principal_id,
            &claims.issuer,
            &claims.subject,
            &claims.email,
            claims.now,
        )
        .map_err(|_| IdpAuthError::StorageUnavailable)?;
    let audit = ProductAudit::principal(AuditAction::AdminIdpAutoRegistered, principal_id);
    let _ = store.append_audit_event(Some(principal_id), audit);
    Ok(principal_id)
}

pub(crate) fn resolve_login_principal_oidc(
    store: &StateStore,
    issuer: &str,
    subject: &str,
    email: &str,
    now: i64,
) -> Result<PrincipalId, OidcError> {
    let claims = CallbackClaims {
        issuer: issuer.to_owned(),
        subject: subject.to_owned(),
        email: email.to_owned(),
        principal_id: None,
        now,
    };
    resolve_login_principal(store, &claims, IdpProviderKey::Oidc).map_err(|error| match error {
        IdpAuthError::FlowRejected => OidcError::FlowRejected,
        _ => OidcError::StorageUnavailable,
    })
}

fn start_authorize(
    store: &StateStore,
    provider: IdpProviderKey,
    client: &ConfiguredOidcClient,
    principal_id: Option<PrincipalId>,
) -> Result<OidcAuthorizeStart, IdpAuthError> {
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
    let created = IdpAuthService::now_seconds();
    store
        .insert_oidc_transient(
            if principal_id.is_some() {
                OidcTransientKind::Link
            } else {
                OidcTransientKind::Login
            },
            provider.as_str(),
            &state_digest,
            pkce_verifier.secret(),
            principal_id,
            nonce.secret(),
            created,
            created + OIDC_TRANSIENT_LIFETIME_SECONDS,
        )
        .map_err(|_| IdpAuthError::StorageUnavailable)?;
    Ok(OidcAuthorizeStart {
        authorize_url: auth_url.to_string(),
    })
}

fn start_github_authorize(
    store: &StateStore,
    record: &BrandedOAuthProviderRecord,
    canonical_origin: &str,
    callback_suffix: &str,
    principal_id: Option<PrincipalId>,
) -> Result<OidcAuthorizeStart, IdpAuthError> {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let csrf_state = CsrfToken::new_random();
    let state_digest = SessionToken::digest_of(csrf_state.secret());
    let created = IdpAuthService::now_seconds();
    store
        .insert_oidc_transient(
            if principal_id.is_some() {
                OidcTransientKind::Link
            } else {
                OidcTransientKind::Login
            },
            IdpProviderKey::Github.as_str(),
            &state_digest,
            pkce_verifier.secret(),
            principal_id,
            "",
            created,
            created + OIDC_TRANSIENT_LIFETIME_SECONDS,
        )
        .map_err(|_| IdpAuthError::StorageUnavailable)?;
    let redirect = format!("{canonical_origin}/api/v1/auth/github/{callback_suffix}");
    let authorize_url = format!(
        "{}/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope=read:user%20user:email&code_challenge={}&code_challenge_method=S256",
        record.oauth_host.trim_end_matches('/'),
        percent_encode(&record.client_id),
        percent_encode(&redirect),
        percent_encode(csrf_state.secret()),
        percent_encode(pkce_challenge.as_str()),
    );
    Ok(OidcAuthorizeStart { authorize_url })
}

fn exchange_github_callback(
    store: &StateStore,
    transient: &OidcTransientRecord,
    canonical_origin: &str,
    code: &str,
    expected_kind: OidcTransientKind,
    now: i64,
) -> Result<CallbackClaims, IdpAuthError> {
    let record = active_branded(store, IdpProviderKey::Github, true)?;
    let redirect_suffix = match expected_kind {
        OidcTransientKind::Login => "callback",
        OidcTransientKind::Link => "link/callback",
    };
    let redirect = format!("{canonical_origin}/api/v1/auth/github/{redirect_suffix}");
    let token_url = format!(
        "{}/login/oauth/access_token",
        record.oauth_host.trim_end_matches('/')
    );
    let body = format!(
        "client_id={}&client_secret={}&code={}&redirect_uri={}&grant_type=authorization_code&code_verifier={}",
        percent_encode(&record.client_id),
        percent_encode(record.client_secret.expose()),
        percent_encode(code),
        percent_encode(&redirect),
        percent_encode(&transient.pkce_verifier),
    );
    let response = idp_http_client()
        .post(&token_url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .map_err(|_| IdpAuthError::IdPUnavailable)?;
    let status = response.status();
    let payload: serde_json::Value = response.json().map_err(|_| IdpAuthError::IdPUnavailable)?;
    if !status.is_success() {
        return Err(IdpAuthError::FlowRejected);
    }
    let access_token = payload
        .get("access_token")
        .and_then(|value| value.as_str())
        .ok_or(IdpAuthError::FlowRejected)?;
    let api_base = record.oauth_host.trim_end_matches('/');
    let user: serde_json::Value = idp_http_client()
        .get(format!("{api_base}/user"))
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Accept", "application/json")
        .send()
        .map_err(|_| IdpAuthError::IdPUnavailable)?
        .json()
        .map_err(|_| IdpAuthError::IdPUnavailable)?;
    let subject = user
        .get("id")
        .map(|value| value.to_string())
        .ok_or(IdpAuthError::FlowRejected)?;
    let mut email = user
        .get("email")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_owned();
    if email.is_empty() {
        let emails: Vec<serde_json::Value> = idp_http_client()
            .get(format!("{api_base}/user/emails"))
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Accept", "application/json")
            .send()
            .map_err(|_| IdpAuthError::IdPUnavailable)?
            .json()
            .map_err(|_| IdpAuthError::IdPUnavailable)?;
        email = emails
            .iter()
            .find(|entry| entry.get("primary").and_then(|v| v.as_bool()) == Some(true))
            .or_else(|| emails.first())
            .and_then(|entry| entry.get("email"))
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_owned();
    }
    if email.is_empty() {
        return Err(IdpAuthError::FlowRejected);
    }
    Ok(CallbackClaims {
        issuer: format!("{api_base}#oauth"),
        subject,
        email,
        principal_id: transient.principal_id,
        now,
    })
}

fn build_google_client(
    record: &BrandedOAuthProviderRecord,
    canonical_origin: &str,
    callback_suffix: &str,
) -> Result<(ConfiguredOidcClient, RedirectUrl), IdpAuthError> {
    let issuer = IssuerUrl::new(record.issuer.clone()).map_err(|_| IdpAuthError::InvalidUpdate)?;
    let metadata = CoreProviderMetadata::discover(&issuer, idp_http_client())
        .map_err(|_| IdpAuthError::IdPUnavailable)?;
    let redirect = RedirectUrl::new(format!(
        "{canonical_origin}/api/v1/auth/google/{callback_suffix}"
    ))
    .map_err(|_| IdpAuthError::InvalidUpdate)?;
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(record.client_id.clone()),
        Some(ClientSecret::new(record.client_secret.expose().to_owned())),
    )
    .set_auth_type(AuthType::RequestBody)
    .set_redirect_uri(redirect.clone());
    Ok((client, redirect))
}

fn project_policy(record: &AuthIdpPolicyRecord) -> AuthIdpPolicyView {
    AuthIdpPolicyView {
        auto_register: record.auto_register,
        allowed_domains: parse_allowed_domains(&record.allowed_domains),
        auto_launch: record.auto_launch.clone(),
        password_auth_enabled: record.password_auth_enabled,
    }
}

fn project_branded(record: &BrandedOAuthProviderRecord) -> BrandedProviderSettingsView {
    BrandedProviderSettingsView {
        client_id: record.client_id.clone(),
        client_secret_configured: !record.client_secret.is_empty(),
        display_name: record.display_name.clone(),
        enabled: record.enabled,
        issuer: record.issuer.clone(),
        oauth_host: record.oauth_host.clone(),
    }
}

fn branded_ready(record: &BrandedOAuthProviderRecord) -> bool {
    branded_fields_ready(&record.client_id, None, record.client_secret.is_empty())
}

fn branded_fields_ready(
    client_id: &str,
    secret_patch: Option<&OidcClientSecret>,
    secret_empty: bool,
) -> bool {
    !client_id.is_empty() && (secret_patch.is_some_and(|s| !s.is_empty()) || !secret_empty)
}

fn active_branded(
    store: &StateStore,
    provider: IdpProviderKey,
    https: bool,
) -> Result<BrandedOAuthProviderRecord, IdpAuthError> {
    if !https {
        return Err(IdpAuthError::HttpsOriginRequired);
    }
    let record = store
        .branded_oauth_provider(provider.as_str())
        .map_err(|_| IdpAuthError::StorageUnavailable)?;
    if !record.enabled || !branded_ready(&record) {
        return Err(IdpAuthError::NotConfigured);
    }
    Ok(record)
}

fn map_oidc_error(error: OidcError) -> IdpAuthError {
    match error {
        OidcError::StorageUnavailable => IdpAuthError::StorageUnavailable,
        OidcError::HttpsOriginRequired => IdpAuthError::HttpsOriginRequired,
        OidcError::NotConfigured => IdpAuthError::NotConfigured,
        OidcError::InvalidUpdate => IdpAuthError::InvalidUpdate,
        OidcError::FlowRejected | OidcError::IdPUnavailable => IdpAuthError::FlowRejected,
    }
}

fn percent_encode(input: &str) -> String {
    let mut out = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

pub fn idp_http_client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("IdP HTTP client")
    })
}
