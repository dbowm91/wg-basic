-- Migration 012: JSON metrics enable flag (observability M002).
--
-- Immutable once shipped. Independent from prometheus_enabled; shares bearer_verifier.

ALTER TABLE metrics_settings
    ADD COLUMN json_metrics_enabled INTEGER NOT NULL DEFAULT 0 CHECK (json_metrics_enabled IN (0, 1));