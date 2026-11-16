-- Migration 015: generic OIDC provider settings, IdP subject links, and
-- in-flight authorization state (state + PKCE verifier digests).
--
-- Additive authentication state only: nothing here advances desired_generation.

CREATE TABLE oidc_provider_settings (
    singleton         INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    issuer            TEXT    NOT NULL DEFAULT '',
    client_id         TEXT    NOT NULL DEFAULT '',
    client_secret     TEXT    NOT NULL DEFAULT '',
    display_name      TEXT    NOT NULL DEFAULT 'Sign in',
    enabled           INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    updated_at        INTEGER NOT NULL DEFAULT 0
) STRICT;

INSERT INTO oidc_provider_settings (singleton, issuer, client_id, client_secret, display_name, enabled, updated_at)
VALUES (1, '', '', '', 'Sign in', 0, 0);

CREATE TABLE admin_idp_subject_links (
    principal_id      TEXT    NOT NULL
        REFERENCES admin_principals (id) ON DELETE CASCADE,
    issuer            TEXT    NOT NULL,
    subject           TEXT    NOT NULL,
    email             TEXT    NOT NULL,
    linked_at         INTEGER NOT NULL,
    PRIMARY KEY (issuer, subject)
) STRICT;

CREATE UNIQUE INDEX admin_idp_subject_links_principal_issuer
    ON admin_idp_subject_links (principal_id, issuer);

CREATE TABLE oidc_auth_transients (
    id                TEXT    NOT NULL PRIMARY KEY,
    kind              TEXT    NOT NULL CHECK (kind IN ('login', 'link')),
    state_digest      TEXT    NOT NULL UNIQUE,
    pkce_verifier     TEXT    NOT NULL,
    principal_id      TEXT
        REFERENCES admin_principals (id) ON DELETE CASCADE,
    nonce             TEXT    NOT NULL,
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX oidc_auth_transients_expires_at ON oidc_auth_transients (expires_at);

CREATE TABLE oidc_login_completions (
    id                TEXT    NOT NULL PRIMARY KEY,
    token_digest      TEXT    NOT NULL UNIQUE,
    principal_id      TEXT    NOT NULL
        REFERENCES admin_principals (id) ON DELETE CASCADE,
    totp_required     INTEGER NOT NULL CHECK (totp_required IN (0, 1)),
    pre_session_id    TEXT,
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX oidc_login_completions_expires_at ON oidc_login_completions (expires_at);