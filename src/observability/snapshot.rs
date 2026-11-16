//! Shared peer counts and connected semantics for metrics exposition.

use crate::product::{ClientObservationStatus, ClientTelemetry};

use super::CONNECTED_HANDSHAKE_MAX_AGE_SECONDS;

/// Aggregate peer counts from one bounded client telemetry list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerAggregateCounts {
    pub configured: u64,
    pub enabled: u64,
    pub connected: u64,
}

pub fn peer_aggregate_counts(clients: &[ClientTelemetry]) -> PeerAggregateCounts {
    PeerAggregateCounts {
        configured: clients.len() as u64,
        enabled: clients.iter().filter(|c| c.enabled).count() as u64,
        connected: clients.iter().filter(|c| is_client_connected(c)).count() as u64,
    }
}

/// wg-easy parity: enabled, present in kernel, handshake younger than 10 minutes.
pub fn is_client_connected(client: &ClientTelemetry) -> bool {
    if !client.enabled || client.observation != ClientObservationStatus::Present {
        return false;
    }
    client
        .latest_handshake_age_seconds
        .is_some_and(|age| age < CONNECTED_HANDSHAKE_MAX_AGE_SECONDS)
}
