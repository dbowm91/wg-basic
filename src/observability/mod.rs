//! Observability exposition helpers (Prometheus text in M001; JSON in M002).

mod history;
mod json;
mod prometheus;
mod snapshot;

pub use history::{
    TelemetryHistoryClient, TelemetryHistoryPoint, TelemetryHistorySnapshot,
    TELEMETRY_SAMPLES_PER_CLIENT, TELEMETRY_SAMPLE_INTERVAL_SECONDS,
};
pub use json::{json_metrics_from_telemetry, JsonMetricsClient, JsonMetricsSnapshot};
pub use prometheus::{prometheus_text_from_telemetry, CONNECTED_HANDSHAKE_MAX_AGE_SECONDS};
