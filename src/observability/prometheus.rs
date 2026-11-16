//! Prometheus text exposition from a telemetry snapshot.

use crate::product::ClientTelemetrySnapshot;

use super::snapshot::peer_aggregate_counts;

/// wg-easy parity: peers with handshake younger than 10 minutes count as connected.
pub const CONNECTED_HANDSHAKE_MAX_AGE_SECONDS: u64 = 600;

/// Builds Prometheus text exposition from one live telemetry snapshot.
pub fn prometheus_text_from_telemetry(snapshot: &ClientTelemetrySnapshot) -> String {
    let clients = &snapshot.clients;
    let counts = peer_aggregate_counts(clients);
    let configured = counts.configured;
    let enabled = counts.enabled;
    let connected = counts.connected;

    let mut out = String::new();
    append_aggregate_gauge(
        &mut out,
        "wireguard_configured_peers",
        "Number of configured WireGuard peers",
        configured,
    );
    append_aggregate_gauge(
        &mut out,
        "wireguard_enabled_peers",
        "Number of enabled WireGuard peers",
        enabled,
    );
    append_aggregate_gauge(
        &mut out,
        "wireguard_connected_peers",
        "Number of connected WireGuard peers",
        connected,
    );

    for client in clients {
        let labels = client_label_set(client);
        append_labeled_counter(
            &mut out,
            "wireguard_sent_bytes",
            "Total bytes sent to peer",
            &labels,
            client.tx_bytes.unwrap_or(0),
        );
        append_labeled_counter(
            &mut out,
            "wireguard_received_bytes",
            "Total bytes received from peer",
            &labels,
            client.rx_bytes.unwrap_or(0),
        );
        let handshake = client.latest_handshake_unix_seconds.unwrap_or(0);
        append_labeled_gauge(
            &mut out,
            "wireguard_latest_handshake_seconds",
            "Unix seconds of latest handshake, or 0 when unknown",
            &labels,
            handshake,
        );
    }
    out
}

fn client_label_set(client: &crate::product::ClientTelemetry) -> Vec<(&'static str, String)> {
    let mut labels = vec![
        ("client_id", client.client_id.to_string()),
        ("name", client.name.clone()),
        ("interface", client.interface.clone()),
        (
            "enabled",
            if client.enabled { "true" } else { "false" }.to_owned(),
        ),
    ];
    if let Some(addr) = &client.ipv4_address {
        labels.push(("ipv4_address", addr.clone()));
    }
    if let Some(addr) = &client.ipv6_address {
        labels.push(("ipv6_address", addr.clone()));
    }
    labels
}

fn append_aggregate_gauge(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push_str(" gauge\n");
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

fn append_labeled_counter(
    out: &mut String,
    name: &str,
    help: &str,
    labels: &[(&str, String)],
    value: u64,
) {
    if !out.contains(&format!("# TYPE {name}")) {
        out.push_str("# HELP ");
        out.push_str(name);
        out.push(' ');
        out.push_str(help);
        out.push('\n');
        out.push_str("# TYPE ");
        out.push_str(name);
        out.push_str(" counter\n");
    }
    out.push_str(name);
    out.push('{');
    for (index, (key, value)) in labels.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(key);
        out.push_str("=\"");
        out.push_str(&escape_label_value(value));
        out.push('"');
    }
    out.push_str("} ");
    out.push_str(&value.to_string());
    out.push('\n');
}

fn append_labeled_gauge(
    out: &mut String,
    name: &str,
    help: &str,
    labels: &[(&str, String)],
    value: u64,
) {
    if !out.contains(&format!("# TYPE {name}")) {
        out.push_str("# HELP ");
        out.push_str(name);
        out.push(' ');
        out.push_str(help);
        out.push('\n');
        out.push_str("# TYPE ");
        out.push_str(name);
        out.push_str(" gauge\n");
    }
    out.push_str(name);
    out.push('{');
    for (index, (key, value)) in labels.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(key);
        out.push_str("=\"");
        out.push_str(&escape_label_value(value));
        out.push('"');
    }
    out.push_str("} ");
    out.push_str(&value.to_string());
    out.push('\n');
}

pub(crate) fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{ClientId, InterfaceName, PeerId, PublicKey},
        product::{ClientObservationStatus, ClientTelemetry, ClientTelemetrySnapshot},
    };

    #[test]
    fn label_values_are_prometheus_escaped() {
        assert_eq!(escape_label_value(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn exposition_includes_help_type_and_client_labels() {
        let client_id = ClientId::new();
        let snapshot = ClientTelemetrySnapshot {
            observed_at_unix_seconds: 1_800_000_000,
            clients: vec![ClientTelemetry {
                client_id,
                peer_id: PeerId::new(),
                name: "laptop".to_owned(),
                interface: InterfaceName::new("wg0")
                    .expect("valid")
                    .as_str()
                    .to_owned(),
                enabled: true,
                observation: ClientObservationStatus::Present,
                drift: false,
                public_key: PublicKey::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into())
                    .unwrap(),
                endpoint: None,
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
        let body = prometheus_text_from_telemetry(&snapshot);
        assert!(body.contains("# HELP wireguard_configured_peers"));
        assert!(body.contains("# TYPE wireguard_sent_bytes counter"));
        assert!(body.contains(&format!("client_id=\"{client_id}\"")));
        assert!(body.contains("name=\"laptop\""));
        assert!(!body.contains("endpoint"));
    }
}
