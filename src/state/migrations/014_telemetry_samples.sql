-- Migration 014: Bounded per-client telemetry history (observability M003).
--
-- Operational cache only: samples do not advance desired_generation and are not
-- authoritative configuration.

CREATE TABLE telemetry_samples (
    client_id                TEXT    NOT NULL
                             REFERENCES clients (id) ON DELETE CASCADE,
    observed_at_unix         INTEGER NOT NULL CHECK (observed_at_unix >= 0),
    rx_bytes                 INTEGER NOT NULL CHECK (rx_bytes >= 0),
    tx_bytes                 INTEGER NOT NULL CHECK (tx_bytes >= 0),
    handshake_age_seconds    INTEGER CHECK (
        handshake_age_seconds IS NULL OR handshake_age_seconds >= 0
    ),
    PRIMARY KEY (client_id, observed_at_unix)
) STRICT;

CREATE INDEX telemetry_samples_client_observed
    ON telemetry_samples (client_id, observed_at_unix);