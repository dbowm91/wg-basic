//! Bounded telemetry history types and constants (ADR-013 §2.5).

use crate::domain::ClientId;
use serde::Serialize;

/// Default interval between worker-owned telemetry samples.
pub const TELEMETRY_SAMPLE_INTERVAL_SECONDS: u64 = 30;

/// Newest samples retained per client (~1 hour at the default interval).
pub const TELEMETRY_SAMPLES_PER_CLIENT: usize = 120;

/// One stored observation point suitable for sparkline rendering.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TelemetryHistoryPoint {
    pub observed_at_unix: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_age_seconds: Option<u64>,
}

/// Bounded chronological points for one client.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TelemetryHistoryClient {
    pub client_id: ClientId,
    pub points: Vec<TelemetryHistoryPoint>,
}

/// Batch history read for the embedded UI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TelemetryHistorySnapshot {
    pub clients: Vec<TelemetryHistoryClient>,
}
