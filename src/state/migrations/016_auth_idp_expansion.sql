-- Migration 016: OAuth branded providers, IdP policy, transient provider key.
-- Additive authentication state only.

CREATE TABLE auth_idp_policy (
    singleton               INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    auto_register           INTEGER NOT NULL DEFAULT 0 CHECK (auto_register IN (0, 1)),
    -- Comma-separated domain list; empty means no domain filter.
    allowed_domains         TEXT    NOT NULL DEFAULT '',
    -- Provider key for login auto-redirect: oidc, google, github, or empty.
    auto_launch             TEXT    NOT NULL DEFAULT '',
    password_auth_enabled   INTEGER NOT NULL DEFAULT 1 CHECK (password_auth_enabled IN (0, 1)),
    updated_at              INTEGER NOT NULL DEFAULT 0
) STRICT;

INSERT INTO auth_idp_policy (singleton, auto_register, allowed_domains, auto_launch, password_auth_enabled, updated_at)
VALUES (1, 0, '', '', 1, 0);

CREATE TABLE oauth_branded_providers (
    provider                TEXT    NOT NULL PRIMARY KEY CHECK (provider IN ('google', 'github')),
    client_id               TEXT    NOT NULL DEFAULT '',
    client_secret           TEXT    NOT NULL DEFAULT '',
    display_name            TEXT    NOT NULL DEFAULT '',
    enabled                 INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    -- Google OIDC issuer (default Google; loopback fakes for qualification).
    issuer                  TEXT    NOT NULL DEFAULT 'https://accounts.google.com',
    -- GitHub OAuth host base (default github.com).
    oauth_host              TEXT    NOT NULL DEFAULT 'https://github.com',
    updated_at              INTEGER NOT NULL DEFAULT 0
) STRICT;

INSERT INTO oauth_branded_providers (provider, client_id, client_secret, display_name, enabled, issuer, oauth_host, updated_at)
VALUES
    ('google', '', '', 'Sign in with Google', 0, 'https://accounts.google.com', 'https://github.com', 0),
    ('github', '', '', 'Sign in with GitHub', 0, 'https://accounts.google.com', 'https://github.com', 0);

ALTER TABLE oidc_auth_transients ADD COLUMN provider TEXT NOT NULL DEFAULT 'oidc';