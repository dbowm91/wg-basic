//! Metrics scrape settings on the worker thread.

use crate::{
    domain::{check_password_policy, PasswordVerifier, TIMING_EQUALISER_VERIFIER},
    state::StateStore,
};
use serde::Serialize;
use std::sync::OnceLock;

/// Operator-facing metrics settings (no secrets).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MetricsSettingsView {
    pub prometheus_enabled: bool,
    pub json_metrics_enabled: bool,
    pub bearer_password_configured: bool,
}

/// Patch body semantics for metrics settings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MetricsSettingsUpdate {
    pub prometheus_enabled: Option<bool>,
    pub json_metrics_enabled: Option<bool>,
    pub set_bearer_password: Option<String>,
    pub clear_bearer_password: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricsSettingsError {
    StorageUnavailable,
    PasswordRejected,
    InvalidUpdate,
}

pub struct MetricsSettingsService<'a> {
    store: &'a StateStore,
}

impl<'a> MetricsSettingsService<'a> {
    pub fn new(store: &'a StateStore) -> Self {
        Self { store }
    }

    pub fn view(&self) -> Result<MetricsSettingsView, MetricsSettingsError> {
        let record = self
            .store
            .metrics_settings()
            .map_err(|_| MetricsSettingsError::StorageUnavailable)?;
        Ok(MetricsSettingsView {
            prometheus_enabled: record.prometheus_enabled,
            json_metrics_enabled: record.json_metrics_enabled,
            bearer_password_configured: record.bearer_verifier.is_some(),
        })
    }

    pub fn update(
        &self,
        patch: MetricsSettingsUpdate,
    ) -> Result<MetricsSettingsView, MetricsSettingsError> {
        if patch.set_bearer_password.is_some() && patch.clear_bearer_password {
            return Err(MetricsSettingsError::InvalidUpdate);
        }
        let current = self
            .store
            .metrics_settings()
            .map_err(|_| MetricsSettingsError::StorageUnavailable)?;
        let enabled = patch
            .prometheus_enabled
            .unwrap_or(current.prometheus_enabled);
        let json_enabled = patch
            .json_metrics_enabled
            .unwrap_or(current.json_metrics_enabled);
        let verifier_patch = if let Some(password) = patch.set_bearer_password {
            check_password_policy(password.as_bytes())
                .map_err(|_| MetricsSettingsError::PasswordRejected)?;
            let verifier = PasswordVerifier::hash(&password)
                .map_err(|_| MetricsSettingsError::PasswordRejected)?;
            Some(Some(verifier))
        } else if patch.clear_bearer_password {
            Some(None)
        } else {
            None
        };
        self.store
            .update_metrics_settings(enabled, json_enabled, verifier_patch)
            .map_err(|_| MetricsSettingsError::StorageUnavailable)?;
        self.view()
    }

    /// Verifies the metrics Bearer password when a verifier is configured.
    pub fn verify_bearer(&self, password: &str) -> bool {
        let Ok(record) = self.store.metrics_settings() else {
            equaliser().verify(password);
            return false;
        };
        let Some(verifier) = record.bearer_verifier.as_ref() else {
            equaliser().verify(password);
            return false;
        };
        verifier.verify(password)
    }
}

fn equaliser() -> &'static PasswordVerifier {
    static EQUALISER: OnceLock<PasswordVerifier> = OnceLock::new();
    EQUALISER.get_or_init(|| {
        PasswordVerifier::parse(TIMING_EQUALISER_VERIFIER)
            .expect("the timing equaliser verifier is valid")
    })
}
