//! JSON metrics exposition from a telemetry snapshot (ADR-013 §2.4).

use crate::{
    domain::PublicKey,
    product::{ClientTelemetry, ClientTelemetrySnapshot},
};

use serde::Serialize;

use super::snapshot::peer_aggregate_counts;

/// Wire shape for `GET /metrics/json`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JsonMetricsSnapshot {
    pub wireguard_configured_peers: u64,
    pub wireguard_enabled_peers: u64,
    pub wireguard_connected_peers: u64,
    pub clients: Vec<JsonMetricsClient>,
    pub truncated: bool,
}

/// One client row in the JSON metrics list.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JsonMetricsClient {
    pub name: String,
    pub enabled: bool,
    pub addresses: Vec<String>,
    pub public_key: PublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_handshake_unix_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_bytes: Option<u64>,
}

/// Builds the JSON metrics document from one live telemetry snapshot.
pub fn json_metrics_from_telemetry(snapshot: &ClientTelemetrySnapshot) -> JsonMetricsSnapshot {
    let counts = peer_aggregate_counts(&snapshot.clients);
    let clients = snapshot
        .clients
        .iter()
        .map(json_client_from_telemetry)
        .collect();
    JsonMetricsSnapshot {
        wireguard_configured_peers: counts.configured,
        wireguard_enabled_peers: counts.enabled,
        wireguard_connected_peers: counts.connected,
        clients,
        truncated: snapshot.truncated,
    }
}

fn json_client_from_telemetry(client: &ClientTelemetry) -> JsonMetricsClient {
    let mut addresses = Vec::new();
    if let Some(addr) = &client.ipv4_address {
        addresses.push(addr.clone());
    }
    if let Some(addr) = &client.ipv6_address {
        addresses.push(addr.clone());
    }
    JsonMetricsClient {
        name: client.name.clone(),
        enabled: client.enabled,
        addresses,
        public_key: client.public_key.clone(),
        endpoint: client.endpoint.map(|addr| addr.to_string()),
        latest_handshake_unix_seconds: client.latest_handshake_unix_seconds,
        rx_bytes: client.rx_bytes,
        tx_bytes: client.tx_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{ClientId, InterfaceName, PeerId, PublicKey},
        product::{ClientObservationStatus, ClientTelemetry, ClientTelemetrySnapshot},
    };
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn sample_key() -> PublicKey {
        PublicKey::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()).unwrap()
    }

    #[test]
    fn json_shape_includes_public_key_and_endpoint() {
        let snapshot = ClientTelemetrySnapshot {
            observed_at_unix_seconds: 1_800_000_000,
            clients: vec![ClientTelemetry {
                client_id: ClientId::new(),
                peer_id: PeerId::new(),
                name: "laptop".to_owned(),
                interface: InterfaceName::new("wg0")
                    .expect("valid")
                    .as_str()
                    .to_owned(),
                enabled: true,
                observation: ClientObservationStatus::Present,
                drift: false,
                public_key: sample_key(),
                endpoint: Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(198, 51, 100, 9),
                    51820,
                ))),
                ipv4_address: Some("10.8.0.2".to_owned()),
                ipv6_address: None,
                latest_handshake_unix_seconds: Some(1_799_999_500),
                latest_handshake_age_seconds: Some(500),
                rx_bytes: Some(10),
                tx_bytes: Some(20),
            }],
            unassociated_peer_count: 0,
            truncated: false,
        };
        let doc = json_metrics_from_telemetry(&snapshot);
        assert_eq!(doc.wireguard_configured_peers, 1);
        assert_eq!(doc.wireguard_connected_peers, 1);
        assert_eq!(doc.clients.len(), 1);
        assert_eq!(doc.clients[0].name, "laptop");
        assert_eq!(doc.clients[0].public_key, sample_key());
        assert_eq!(
            doc.clients[0].endpoint.as_deref(),
            Some("198.51.100.9:51820")
        );
        let encoded = serde_json::to_value(&doc).expect("serialize");
        assert_eq!(encoded["clients"][0]["public_key"], sample_key().expose());
        assert!(encoded["clients"][0]["endpoint"].is_string());
    }

    #[test]
    fn truncated_flag_is_preserved() {
        let snapshot = ClientTelemetrySnapshot {
            observed_at_unix_seconds: 0,
            clients: vec![],
            unassociated_peer_count: 0,
            truncated: true,
        };
        let doc = json_metrics_from_telemetry(&snapshot);
        assert!(doc.truncated);
    }
}
