//! Bounded per-client telemetry samples. Operational cache, not desired state.

use super::StateStore;
use crate::{
    domain::ClientId,
    observability::{
        TelemetryHistoryClient, TelemetryHistoryPoint, TelemetryHistorySnapshot,
        TELEMETRY_SAMPLES_PER_CLIENT,
    },
    state::error::StateError,
};
use rusqlite::{params, TransactionBehavior};
use std::{collections::BTreeMap, str::FromStr};

/// One insert row from a live telemetry join.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetrySampleInsert {
    pub client_id: ClientId,
    pub observed_at_unix: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub handshake_age_seconds: Option<u64>,
}

impl StateStore {
    /// Inserts samples and prunes each affected client to the retention cap.
    pub fn insert_telemetry_samples(
        &self,
        samples: &[TelemetrySampleInsert],
    ) -> Result<(), StateError> {
        if samples.is_empty() {
            return Ok(());
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        for sample in samples {
            transaction
                .execute(
                    "INSERT OR REPLACE INTO telemetry_samples
                     (client_id, observed_at_unix, rx_bytes, tx_bytes, handshake_age_seconds)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        sample.client_id.to_string(),
                        i64::try_from(sample.observed_at_unix)
                            .map_err(|_| StateError::Corrupt("telemetry timestamp overflow"))?,
                        i64::try_from(sample.rx_bytes)
                            .map_err(|_| StateError::Corrupt("telemetry rx overflow"))?,
                        i64::try_from(sample.tx_bytes)
                            .map_err(|_| StateError::Corrupt("telemetry tx overflow"))?,
                        sample
                            .handshake_age_seconds
                            .map(i64::try_from)
                            .transpose()
                            .map_err(|_| StateError::Corrupt("telemetry handshake overflow"))?,
                    ],
                )
                .map_err(StateError::database)?;
            prune_client_samples(&transaction, &sample.client_id)?;
        }
        transaction.commit().map_err(StateError::database)
    }

    /// Drops excess samples for every client row still present.
    pub fn prune_all_telemetry_samples(&self) -> Result<(), StateError> {
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StateError::database)?;
        let mut statement = transaction
            .prepare("SELECT DISTINCT client_id FROM telemetry_samples")
            .map_err(StateError::database)?;
        let client_ids: Vec<String> = statement
            .query_map([], |row| row.get(0))
            .map_err(StateError::database)?
            .collect::<Result<_, _>>()
            .map_err(StateError::database)?;
        drop(statement);
        for client_id in client_ids {
            let parsed = ClientId::from_str(&client_id)
                .map_err(|_| StateError::Corrupt("invalid telemetry client id"))?;
            prune_client_samples(&transaction, &parsed)?;
        }
        transaction.commit().map_err(StateError::database)
    }

    /// Reads chronological history for the given clients, or every client with rows.
    pub fn telemetry_history(
        &self,
        client_ids: Option<&[ClientId]>,
    ) -> Result<TelemetryHistorySnapshot, StateError> {
        let connection = self.lock()?;
        let filter: Vec<String> = client_ids
            .map(|ids| ids.iter().map(|id| id.to_string()).collect())
            .unwrap_or_default();
        let mut by_client: BTreeMap<ClientId, Vec<TelemetryHistoryPoint>> = BTreeMap::new();
        if let Some(ids) = client_ids {
            for client_id in ids {
                let mut rows = list_client_history(&connection, client_id)?;
                rows.sort_by_key(|point| point.observed_at_unix);
                if !rows.is_empty() {
                    by_client.insert(*client_id, rows);
                }
            }
        } else {
            let mut statement = connection
                .prepare(
                    "SELECT client_id, observed_at_unix, rx_bytes, tx_bytes, handshake_age_seconds
                     FROM telemetry_samples
                     ORDER BY client_id ASC, observed_at_unix ASC",
                )
                .map_err(StateError::database)?;
            let rows = statement
                .query_map([], decode_history_row)
                .map_err(StateError::database)?;
            for row in rows {
                let (client_id, point) = row.map_err(StateError::database)?;
                if !filter.is_empty() && !filter.iter().any(|id| id == &client_id.to_string()) {
                    continue;
                }
                by_client.entry(client_id).or_default().push(point);
            }
        }
        Ok(TelemetryHistorySnapshot {
            clients: by_client
                .into_iter()
                .map(|(client_id, points)| TelemetryHistoryClient { client_id, points })
                .collect(),
        })
    }
}

fn list_client_history(
    connection: &rusqlite::Connection,
    client_id: &ClientId,
) -> Result<Vec<TelemetryHistoryPoint>, StateError> {
    let mut statement = connection
        .prepare(
            "SELECT observed_at_unix, rx_bytes, tx_bytes, handshake_age_seconds
             FROM telemetry_samples
             WHERE client_id = ?1
             ORDER BY observed_at_unix ASC
             LIMIT ?2",
        )
        .map_err(StateError::database)?;
    let rows = statement
        .query_map(
            params![client_id.to_string(), TELEMETRY_SAMPLES_PER_CLIENT as i64],
            |row| {
                Ok(TelemetryHistoryPoint {
                    observed_at_unix: row.get::<_, i64>(0)? as u64,
                    rx_bytes: row.get::<_, i64>(1)? as u64,
                    tx_bytes: row.get::<_, i64>(2)? as u64,
                    handshake_age_seconds: row.get::<_, Option<i64>>(3)?.map(|value| value as u64),
                })
            },
        )
        .map_err(StateError::database)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StateError::database)
}

fn decode_history_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(ClientId, TelemetryHistoryPoint)> {
    let client_id: String = row.get(0)?;
    let client_id = ClientId::from_str(&client_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok((
        client_id,
        TelemetryHistoryPoint {
            observed_at_unix: row.get::<_, i64>(1)? as u64,
            rx_bytes: row.get::<_, i64>(2)? as u64,
            tx_bytes: row.get::<_, i64>(3)? as u64,
            handshake_age_seconds: row.get::<_, Option<i64>>(4)?.map(|value| value as u64),
        },
    ))
}

fn prune_client_samples(
    transaction: &rusqlite::Transaction<'_>,
    client_id: &ClientId,
) -> Result<(), StateError> {
    transaction
        .execute(
            "DELETE FROM telemetry_samples
             WHERE client_id = ?1
             AND observed_at_unix IN (
                 SELECT observed_at_unix FROM telemetry_samples
                 WHERE client_id = ?1
                 ORDER BY observed_at_unix DESC
                 LIMIT -1 OFFSET ?2
             )",
            params![client_id.to_string(), TELEMETRY_SAMPLES_PER_CLIENT as i64],
        )
        .map_err(StateError::database)?;
    Ok(())
}
