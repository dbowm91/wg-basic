//! OIDC worker commands (Phase 12 M003).

use super::worker::{WorkerClient, WorkerCommand, WorkerError};
use super::{
    LoginOutcome, OidcAuthorizeStart, OidcCallbackSuccess, OidcError, OidcLinkStart,
    OidcPublicView, OidcService, OidcSettingsUpdate, OidcSettingsView,
};
use crate::domain::PrincipalId;
use tokio::sync::oneshot;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OidcFailure {
    #[error("oidc flow rejected")]
    Rejected,
    #[error("oidc storage unavailable")]
    Storage,
    #[error("https canonical origin required")]
    HttpsRequired,
    #[error("oidc not configured")]
    NotConfigured,
}

fn oidc_failure(error: OidcError) -> OidcFailure {
    match error {
        OidcError::StorageUnavailable => OidcFailure::Storage,
        OidcError::HttpsOriginRequired => OidcFailure::HttpsRequired,
        OidcError::NotConfigured => OidcFailure::NotConfigured,
        OidcError::InvalidUpdate => OidcFailure::Rejected,
        OidcError::FlowRejected | OidcError::IdPUnavailable => OidcFailure::Rejected,
    }
}

impl WorkerClient {
    async fn oidc_reply<T>(
        answer: oneshot::Receiver<Result<T, OidcFailure>>,
    ) -> Result<T, WorkerError> {
        match answer.await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(OidcFailure::Storage)) => Err(WorkerError::Unavailable),
            Ok(Err(OidcFailure::HttpsRequired | OidcFailure::NotConfigured)) => {
                Err(WorkerError::Rejected)
            }
            Ok(Err(OidcFailure::Rejected)) => Err(WorkerError::Rejected),
            Err(_) => Err(WorkerError::Stopped),
        }
    }

    pub async fn oidc_public(
        &self,
        canonical_origin: String,
    ) -> Result<OidcPublicView, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::OidcPublicView {
            canonical_origin,
            reply,
        })
        .await?;
        Self::oidc_reply(answer).await
    }

    pub async fn oidc_settings(&self) -> Result<OidcSettingsView, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::OidcSettingsView { reply })
            .await?;
        Self::oidc_reply(answer).await
    }

    pub async fn update_oidc_settings(
        &self,
        patch: OidcSettingsUpdate,
        canonical_origin: String,
    ) -> Result<OidcSettingsView, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::UpdateOidcSettings {
            patch,
            canonical_origin,
            reply,
        })
        .await?;
        Self::oidc_reply(answer).await
    }

    pub async fn oidc_begin_login(
        &self,
        canonical_origin: String,
    ) -> Result<OidcAuthorizeStart, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::OidcBeginLogin {
            canonical_origin,
            reply,
        })
        .await?;
        Self::oidc_reply(answer).await
    }

    pub async fn oidc_begin_link(
        &self,
        principal_id: PrincipalId,
        canonical_origin: String,
    ) -> Result<OidcLinkStart, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::OidcBeginLink {
            principal_id,
            canonical_origin,
            reply,
        })
        .await?;
        Self::oidc_reply(answer).await
    }

    pub async fn oidc_login_callback(
        &self,
        state: String,
        code: String,
        canonical_origin: String,
    ) -> Result<OidcCallbackSuccess, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::OidcLoginCallback {
            state,
            code,
            canonical_origin,
            reply,
        })
        .await?;
        Self::oidc_reply(answer).await
    }

    pub async fn oidc_link_callback(
        &self,
        state: String,
        code: String,
        canonical_origin: String,
    ) -> Result<(), WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::OidcLinkCallback {
            state,
            code,
            canonical_origin,
            reply,
        })
        .await?;
        Self::oidc_reply(answer).await
    }

    pub async fn oidc_exchange_completion(
        &self,
        token: String,
    ) -> Result<LoginOutcome, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::OidcExchangeCompletion { token, reply })
            .await?;
        Self::oidc_reply(answer).await
    }
}

pub(crate) fn dispatch_oidc(
    runtime: &super::runtime::ManagementRuntime,
    command: WorkerCommand,
) -> bool {
    use WorkerCommand::*;
    match command {
        OidcPublicView {
            canonical_origin,
            reply,
        } => {
            let service = OidcService::new(runtime.store(), canonical_origin);
            let _ = reply.send(service.public_view().map_err(oidc_failure));
            true
        }
        OidcSettingsView { reply } => {
            let service = OidcService::new(runtime.store(), "http://localhost");
            let _ = reply.send(service.settings_view().map_err(oidc_failure));
            true
        }
        UpdateOidcSettings {
            patch,
            canonical_origin,
            reply,
        } => {
            let service = OidcService::new(runtime.store(), canonical_origin);
            let _ = reply.send(service.update_settings(patch).map_err(oidc_failure));
            true
        }
        OidcBeginLogin {
            canonical_origin,
            reply,
        } => {
            let service = OidcService::new(runtime.store(), canonical_origin);
            let _ = reply.send(service.begin_login().map_err(oidc_failure));
            true
        }
        OidcBeginLink {
            principal_id,
            canonical_origin,
            reply,
        } => {
            let service = OidcService::new(runtime.store(), canonical_origin);
            let _ = reply.send(service.begin_link(principal_id).map_err(oidc_failure));
            true
        }
        OidcLoginCallback {
            state,
            code,
            canonical_origin,
            reply,
        } => {
            let service = OidcService::new(runtime.store(), canonical_origin);
            let _ = reply.send(
                service
                    .complete_login_callback(&state, &code)
                    .map_err(oidc_failure),
            );
            true
        }
        OidcLinkCallback {
            state,
            code,
            canonical_origin,
            reply,
        } => {
            let service = OidcService::new(runtime.store(), canonical_origin);
            let _ = reply.send(
                service
                    .complete_link_callback(&state, &code)
                    .map_err(oidc_failure),
            );
            true
        }
        OidcExchangeCompletion { token, reply } => {
            let service = OidcService::new(runtime.store(), "http://localhost");
            let _ = reply.send(service.exchange_completion(&token).map_err(oidc_failure));
            true
        }
        _ => false,
    }
}
