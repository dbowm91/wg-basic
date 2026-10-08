-- Migration 4: digest-only, expiring single-use enrollment capabilities.
-- This migration is additive; v3 desired and product rows are unchanged.
CREATE TABLE enrollment_capabilities (
    capability_id       TEXT NOT NULL PRIMARY KEY,
    client_id           TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    token_digest        TEXT NOT NULL UNIQUE CHECK (length(token_digest) = 64),
    creator_principal_id TEXT REFERENCES admin_principals (id) ON DELETE SET NULL,
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL CHECK (expires_at > created_at),
    consumed_at         INTEGER CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    revoked_at          INTEGER CHECK (revoked_at IS NULL OR revoked_at >= created_at)
) STRICT;

CREATE INDEX enrollment_capabilities_client
    ON enrollment_capabilities (client_id, created_at);
CREATE INDEX enrollment_capabilities_expiry
    ON enrollment_capabilities (expires_at);
