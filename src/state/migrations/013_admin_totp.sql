-- Migration 013: TOTP second factor and login pre-sessions.
--
-- Additive authentication state only: nothing here advances desired_generation
-- or touches product / reconciliation tables.
--
-- * `admin_principal_totp` holds the enrolled secret and a pending enroll
--   secret until confirmation. Raw secrets never belong in audit or logs.
-- * `admin_totp_pre_sessions` holds digest-only challenge tokens issued after
--   password success when TOTP is enabled. They are not product sessions.

CREATE TABLE admin_principal_totp (
    principal_id    TEXT    NOT NULL PRIMARY KEY
        REFERENCES admin_principals (id) ON DELETE CASCADE,
    -- Base32-encoded TOTP secret for the enrolled factor.
    secret          TEXT,
    enabled         INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    -- Pending enroll secret until a verification code succeeds.
    pending_secret  TEXT,
    updated_at      INTEGER NOT NULL
) STRICT;

CREATE TABLE admin_totp_pre_sessions (
    id              TEXT    NOT NULL PRIMARY KEY,
    principal_id    TEXT    NOT NULL
        REFERENCES admin_principals (id) ON DELETE CASCADE,
    token_digest    TEXT    NOT NULL UNIQUE,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX admin_totp_pre_sessions_expires_at ON admin_totp_pre_sessions (expires_at);