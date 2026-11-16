//! IdP policy and branded provider worker commands (M004).

use super::worker::{WorkerClient, WorkerCommand, WorkerError};
use super::{
    AuthIdpPolicyUpdate, AuthIdpPolicyView, BrandedProviderSettingsUpdate,
    BrandedProviderSettingsView, IdpAuthError, IdpAuthService, IdpLoginPublicView, IdpProviderKey,
    LoginOutcome, OidcAuthorizeStart, OidcCallbackSuccess, OidcLinkStart,
};
use crate::domain::PrincipalId;
use crate::product::AuditAction;
use crate::state::ProductAudit;
use tokio::sync::oneshot;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdpFailure {
    #[error("idp flow rejected")]
    Rejected,
    #[error("idp storage unavailable")]
    Storage,
    #[error("https canonical origin required")]
    HttpsRequired,
    #[error("idp not configured")]
    NotConfigured,
    #[error("idp conflict")]
    Conflict,
}

fn idp_failure(error: IdpAuthError) -> IdpFailure {
    match error {
        IdpAuthError::StorageUnavailable => IdpFailure::Storage,
        IdpAuthError::HttpsOriginRequired => IdpFailure::HttpsRequired,
        IdpAuthError::NotConfigured => IdpFailure::NotConfigured,
        IdpAuthError::Conflict => IdpFailure::Conflict,
        IdpAuthError::InvalidUpdate => IdpFailure::Rejected,
        IdpAuthError::FlowRejected | IdpAuthError::IdPUnavailable => IdpFailure::Rejected,
    }
}

impl WorkerClient {
    async fn idp_reply<T>(
        answer: oneshot::Receiver<Result<T, IdpFailure>>,
    ) -> Result<T, WorkerError> {
        match answer.await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(IdpFailure::Storage)) => Err(WorkerError::Unavailable),
            Ok(Err(IdpFailure::Conflict)) => Err(WorkerError::Rejected),
            Ok(Err(IdpFailure::HttpsRequired | IdpFailure::NotConfigured)) => {
                Err(WorkerError::Rejected)
            }
            Ok(Err(IdpFailure::Rejected)) => Err(WorkerError::Rejected),
            Err(_) => Err(WorkerError::Stopped),
        }
    }

    pub async fn idp_login_public(
        &self,
        canonical_origin: String,
    ) -> Result<IdpLoginPublicView, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::IdpLoginPublicView {
            canonical_origin,
            reply,
        })
        .await?;
        Self::idp_reply(answer).await
    }

    pub async fn idp_policy_view(&self) -> Result<AuthIdpPolicyView, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::IdpPolicyView { reply }).await?;
        Self::idp_reply(answer).await
    }

    pub async fn update_idp_policy(
        &self,
        principal_id: PrincipalId,
        patch: AuthIdpPolicyUpdate,
    ) -> Result<AuthIdpPolicyView, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::UpdateIdpPolicy {
            principal_id,
            patch,
            reply,
        })
        .await?;
        Self::idp_reply(answer).await
    }

    pub async fn branded_settings(
        &self,
        provider: IdpProviderKey,
    ) -> Result<BrandedProviderSettingsView, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::BrandedProviderSettingsView { provider, reply })
            .await?;
        Self::idp_reply(answer).await
    }

    pub async fn update_branded_settings(
        &self,
        provider: IdpProviderKey,
        patch: BrandedProviderSettingsUpdate,
        canonical_origin: String,
    ) -> Result<BrandedProviderSettingsView, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::UpdateBrandedProviderSettings {
            provider,
            patch,
            canonical_origin,
            reply,
        })
        .await?;
        Self::idp_reply(answer).await
    }

    pub async fn idp_begin_login(
        &self,
        provider: IdpProviderKey,
        canonical_origin: String,
    ) -> Result<OidcAuthorizeStart, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::IdpBeginLogin {
            provider,
            canonical_origin,
            reply,
        })
        .await?;
        Self::idp_reply(answer).await
    }

    pub async fn idp_begin_link(
        &self,
        provider: IdpProviderKey,
        principal_id: PrincipalId,
        canonical_origin: String,
    ) -> Result<OidcLinkStart, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::IdpBeginLink {
            provider,
            principal_id,
            canonical_origin,
            reply,
        })
        .await?;
        Self::idp_reply(answer).await
    }

    pub async fn idp_login_callback(
        &self,
        provider: IdpProviderKey,
        state: String,
        code: String,
        canonical_origin: String,
    ) -> Result<OidcCallbackSuccess, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::IdpLoginCallback {
            provider,
            state,
            code,
            canonical_origin,
            reply,
        })
        .await?;
        Self::idp_reply(answer).await
    }

    pub async fn idp_link_callback(
        &self,
        provider: IdpProviderKey,
        state: String,
        code: String,
        canonical_origin: String,
    ) -> Result<(), WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::IdpLinkCallback {
            provider,
            state,
            code,
            canonical_origin,
            reply,
        })
        .await?;
        Self::idp_reply(answer).await
    }

    pub async fn idp_exchange_completion(
        &self,
        token: String,
    ) -> Result<LoginOutcome, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::IdpExchangeCompletion { token, reply })
            .await?;
        Self::idp_reply(answer).await
    }
}

pub(crate) fn dispatch_idp(
    runtime: &super::runtime::ManagementRuntime,
    command: WorkerCommand,
) -> bool {
    use WorkerCommand::*;
    match command {
        IdpLoginPublicView {
            canonical_origin,
            reply,
        } => {
            let service = IdpAuthService::new(runtime.store(), canonical_origin);
            let _ = reply.send(service.login_public_view().map_err(idp_failure));
            true
        }
        IdpPolicyView { reply } => {
            let service = IdpAuthService::new(runtime.store(), "http://localhost");
            let _ = reply.send(service.policy_view().map_err(idp_failure));
            true
        }
        UpdateIdpPolicy {
            principal_id,
            patch,
            reply,
        } => {
            let toggled = patch.password_auth_enabled.is_some();
            let service = IdpAuthService::new(runtime.store(), "http://localhost");
            let result = service.update_policy(patch).map_err(idp_failure);
            if result.is_ok() && toggled {
                let audit =
                    ProductAudit::principal(AuditAction::AdminPasswordAuthToggled, principal_id);
                let _ = runtime
                    .store()
                    .append_audit_event(Some(principal_id), audit);
            }
            let _ = reply.send(result);
            true
        }
        BrandedProviderSettingsView { provider, reply } => {
            let service = IdpAuthService::new(runtime.store(), "http://localhost");
            let _ = reply.send(service.branded_settings(provider).map_err(idp_failure));
            true
        }
        UpdateBrandedProviderSettings {
            provider,
            patch,
            canonical_origin,
            reply,
        } => {
            let service = IdpAuthService::new(runtime.store(), canonical_origin);
            let _ = reply.send(service.update_branded(provider, patch).map_err(idp_failure));
            true
        }
        IdpBeginLogin {
            provider,
            canonical_origin,
            reply,
        } => {
            let service = IdpAuthService::new(runtime.store(), canonical_origin);
            let _ = reply.send(service.begin_login(provider).map_err(idp_failure));
            true
        }
        IdpBeginLink {
            provider,
            principal_id,
            canonical_origin,
            reply,
        } => {
            let service = IdpAuthService::new(runtime.store(), canonical_origin);
            let _ = reply.send(
                service
                    .begin_link(provider, principal_id)
                    .map_err(idp_failure),
            );
            true
        }
        IdpLoginCallback {
            provider,
            state,
            code,
            canonical_origin,
            reply,
        } => {
            let service = IdpAuthService::new(runtime.store(), canonical_origin);
            let _ = reply.send(
                service
                    .complete_login_callback(provider, &state, &code)
                    .map_err(idp_failure),
            );
            true
        }
        IdpLinkCallback {
            provider,
            state,
            code,
            canonical_origin,
            reply,
        } => {
            let service = IdpAuthService::new(runtime.store(), canonical_origin);
            let _ = reply.send(
                service
                    .complete_link_callback(provider, &state, &code)
                    .map_err(idp_failure),
            );
            true
        }
        IdpExchangeCompletion { token, reply } => {
            let service = IdpAuthService::new(runtime.store(), "http://localhost");
            let _ = reply.send(service.exchange_completion(&token).map_err(idp_failure));
            true
        }
        _ => false,
    }
}
