-- Migration 002: local administrator credentials and server-side sessions.
--
-- This file is immutable once shipped. Every subsequent schema change must be a
-- new numbered migration.
--
-- Scope notes that matter more than the DDL:
--
-- * This migration adds *authentication* state. It must never change desired
--   state semantics: no column here participates in projection, ownership, or
--   reconciliation, and nothing here advances `desired_generation`.
-- * Only the SHA-256 digest of a session bearer token is stored. A dump of this
--   database does not yield a usable session cookie, because the digest cannot
--   be inverted into the token.
-- * No password is stored in any form. `verifier` is an Argon2id PHC string,
--   which contains the algorithm, its parameters, and a random salt -- never
--   the password.
-- * The CSRF token is stored in the clear, unlike the session bearer. It is not
--   a credential: it is only ever echoed back by the browser in a header, and it
--   is useless without the bearer that accompanies it.

-- Local administrator principals.
--
-- Phase 7 operates exactly one enabled local administrator, but the table is
-- keyed rather than a singleton row so adding a second operator later is a
-- schema-compatible change and not another production migration.
CREATE TABLE admin_principals (
    id           TEXT    NOT NULL PRIMARY KEY,
    username     TEXT    NOT NULL UNIQUE,
    -- Argon2id PHC string. Self-describing: algorithm, parameters, and salt are
    -- all inside the value, so a future parameter change does not need a
    -- migration and an old verifier stays verifiable after an upgrade.
    verifier     TEXT    NOT NULL,
    enabled      INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
) STRICT;

-- Server-side sessions.
--
-- The bearer token is never stored. `token_digest` is SHA-256 over the raw
-- token; lookup hashes the presented token and compares, so a database copy is
-- not a session credential.
CREATE TABLE admin_sessions (
    id             TEXT    NOT NULL PRIMARY KEY,
    principal_id   TEXT    NOT NULL REFERENCES admin_principals (id) ON DELETE CASCADE,
    token_digest   TEXT    NOT NULL UNIQUE,
    csrf_token     TEXT    NOT NULL,
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    CHECK (expires_at > created_at)
) STRICT;

-- Expired-session cleanup is a bounded delete driven by `expires_at`, so the
-- index has to be on that column rather than on the primary key.
CREATE INDEX admin_sessions_expires_at ON admin_sessions (expires_at);

-- Session lookup is always by digest, which the UNIQUE constraint already
-- indexes; the principal-scoped revoke sweep additionally needs this ordering.
CREATE INDEX admin_sessions_principal_id ON admin_sessions (principal_id);