-- Migration 011: Prometheus scrape settings (observability M001).
--
-- Immutable once shipped. Does not advance desired_generation or touch
-- reconciliation state.

CREATE TABLE metrics_settings (
    singleton            INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    prometheus_enabled   INTEGER NOT NULL DEFAULT 0 CHECK (prometheus_enabled IN (0, 1)),
    -- Argon2id PHC for the shared metrics Bearer secret (Prometheus and JSON).
    bearer_verifier    TEXT
) STRICT;

INSERT INTO metrics_settings (singleton, prometheus_enabled)
VALUES (1, 0);