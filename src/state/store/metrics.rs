//! Durable metrics scrape settings. Not desired state.

use super::StateStore;
use crate::{domain::PasswordVerifier, state::error::StateError};
use rusqlite::{params, TransactionBehavior};

/// In-memory metrics settings row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MetricsSettingsRecord {
    pub prometheus_enabled: bool,
    pub json_metrics_enabled: bool,
    pub bearer_verifier: Option<PasswordVerifier>,
}

impl StateStore {
    pub(crate) fn metrics_settings(&self) -> Result<MetricsSettingsRecord, StateError> {
        let connection = self.lock()?;
        let row = connection
            .query_row(
                "SELECT prometheus_enabled, json_metrics_enabled, bearer_verifier FROM metrics_settings WHERE singleton = 1",
                [],
                |row| {
                    let prometheus_enabled: i64 = row.get(0)?;
                    let json_metrics_enabled: i64 = row.get(1)?;
                    let verifier: Option<String> = row.get(2)?;
                    Ok((prometheus_enabled, json_metrics_enabled, verifier))
                },
            )
            .map_err(|_| StateError::Corrupt("metrics settings row is missing"))?;
        let prometheus_enabled = match row.0 {
            0 => false,
            1 => true,
            _ => return Err(StateError::Corrupt("invalid prometheus_enabled")),
        };
        let json_metrics_enabled = match row.1 {
            0 => false,
            1 => true,
            _ => return Err(StateError::Corrupt("invalid json_metrics_enabled")),
        };
        let bearer_verifier = row
            .2
            .map(|stored| PasswordVerifier::parse(&stored))
            .transpose()
            .map_err(|_| StateError::Corrupt("invalid metrics bearer verifier"))?;
        Ok(MetricsSettingsRecord {
            prometheus_enabled,
            json_metrics_enabled,
            bearer_verifier,
        })
    }

    pub(crate) fn update_metrics_settings(
        &self,
        prometheus_enabled: bool,
        json_metrics_enabled: bool,
        bearer_verifier: Option<Option<PasswordVerifier>>,
    ) -> Result<(), StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        if let Some(next) = bearer_verifier {
            match next {
                Some(verifier) => {
                    transaction
                        .execute(
                            "UPDATE metrics_settings
                             SET prometheus_enabled = ?1, json_metrics_enabled = ?2, bearer_verifier = ?3
                             WHERE singleton = 1",
                            params![
                                i64::from(prometheus_enabled),
                                i64::from(json_metrics_enabled),
                                verifier.expose_for_storage()
                            ],
                        )
                        .map_err(StateError::database)?;
                }
                None => {
                    transaction
                        .execute(
                            "UPDATE metrics_settings
                             SET prometheus_enabled = ?1, json_metrics_enabled = ?2, bearer_verifier = NULL
                             WHERE singleton = 1",
                            params![
                                i64::from(prometheus_enabled),
                                i64::from(json_metrics_enabled)
                            ],
                        )
                        .map_err(StateError::database)?;
                }
            }
        } else {
            transaction
                .execute(
                    "UPDATE metrics_settings
                     SET prometheus_enabled = ?1, json_metrics_enabled = ?2
                     WHERE singleton = 1",
                    params![
                        i64::from(prometheus_enabled),
                        i64::from(json_metrics_enabled)
                    ],
                )
                .map_err(StateError::database)?;
        }
        transaction.commit().map_err(StateError::database)
    }
}
