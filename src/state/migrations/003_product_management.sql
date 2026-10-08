-- Migration 003: Phase 8 product management metadata.
--
-- This file is immutable once shipped. Every subsequent schema change must be a
-- new numbered migration.
--
-- Scope notes that matter more than the DDL:
--
-- * Everything here is *additive*. The proven network schema from migration 001
--   is not rewritten, renamed, or dropped. Product metadata lives in side
--   tables keyed by the existing `managed_interfaces` / `clients` identifiers,
--   so a rollback to v2 semantics is a table drop rather than a data rescue.
-- * No column here advances `desired_generation` on its own. Migrating the
--   schema changes no desired-state semantics and no kernel intent, so the
--   generation a v2 store carries into v3 is exactly the generation it had.
-- * No secret material is introduced or copied here. Product settings are
--   operator-visible presentation data: a label, an enable bit, an ordered
--   DNS list, and a keepalive. WireGuard keys stay exclusively in the `peers`
--   table where migration 001 put them.
-- * `audit_events` has no free-form payload or message column. Every row is a
--   bounded (action, resource kind, outcome) tuple plus the generation window
--   it spans, so an audit trail cannot become a covert channel for request
--   bodies, error strings, or credentials.

-- Operator-visible settings for the one managed WireGuard interface.
--
-- The advertised endpoint is what clients are told to dial. It is stored here
-- rather than on `managed_interfaces` because it is a *presentation* fact about
-- the server's public reachability, not kernel intent: changing it must not by
-- itself alter a single projected peer address, AllowedIP, or route.
CREATE TABLE interface_product_settings (
    interface_id   TEXT NOT NULL PRIMARY KEY
                   REFERENCES managed_interfaces (id) ON DELETE CASCADE,
    -- DNS name or literal address clients dial. Validated on the Rust side by
    -- `AdvertisedEndpoint`, which is what guarantees this column can never hold
    -- a scheme, path, query, or userinfo that a config renderer would emit.
    advertised_host TEXT NOT NULL,
    -- 1..65535.
    advertised_port INTEGER NOT NULL CHECK (advertised_port BETWEEN 1 AND 65535)
) STRICT;

-- Managed-client metadata that is product-facing rather than kernel-facing.
--
-- `enabled` is the switch between "this client's peer is projected" and "this
-- client's peer is withheld". A disabled client keeps its row, its address
-- reservation, and its keypair; only its presence in projected intent changes.
CREATE TABLE client_product_settings (
    client_id      TEXT NOT NULL PRIMARY KEY
                   REFERENCES clients (id) ON DELETE CASCADE,
    -- Operator-facing display text. Bounded UTF-8, never a config directive.
    label          TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
    enabled        INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    -- Client-side keepalive exported into the peer's own configuration. Kept
    -- distinct from `peers.persistent_keepalive_seconds`, which is the
    -- server-side value that authorizes the peer to send.
    client_keepalive_seconds INTEGER CHECK (
        client_keepalive_seconds IS NULL
        OR client_keepalive_seconds BETWEEN 0 AND 65535
    ),
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
) STRICT;

-- Ordered DNS servers exported into a client's configuration.
--
-- Position is part of the identity so that read-modify-write of the list is
-- order-preserving and idempotent; (client_id, position) is the primary key.
CREATE TABLE client_dns_servers (
    client_id      TEXT NOT NULL
                   REFERENCES clients (id) ON DELETE CASCADE,
    position       INTEGER NOT NULL CHECK (position >= 0),
    -- Validated IPv4/IPv6 literal text.
    address        TEXT NOT NULL,
    PRIMARY KEY (client_id, position)
) STRICT;

-- Secret-safe product audit trail.
--
-- Every column is a bounded category or an identifier. There is deliberately
-- no `message`, `detail`, or `payload` column: an audit trail is a record of
-- *that* a category of change happened to a resource across a generation
-- window, not a place to paste the request that caused it.
--
-- `outcome` distinguishes a committed product mutation from a rejected or
-- failed one. A row is appended in the same transaction as the desired-state
-- change it describes, so an audit row never exists without its mutation and a
-- mutation never commits without its row.
CREATE TABLE audit_events (
    event_id          TEXT NOT NULL PRIMARY KEY,
    -- Unix seconds, same clock as every other timestamp in this database.
    occurred_at       INTEGER NOT NULL,
    -- NULL for system-origin events that have no authenticated operator.
    principal_id      TEXT REFERENCES admin_principals (id) ON DELETE SET NULL,
    -- Bounded verb, e.g. 'server_setup', 'client_create', 'client_disable'.
    action            TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 64),
    -- Bounded resource kind, e.g. 'server', 'client'.
    resource_kind     TEXT NOT NULL CHECK (length(resource_kind) BETWEEN 1 AND 64),
    -- NULL for events about a resource that could not be identified.
    resource_id       TEXT,
    generation_before INTEGER,
    generation_after  INTEGER,
    -- Bounded category, e.g. 'committed', 'rejected'.
    outcome           TEXT NOT NULL CHECK (length(outcome) BETWEEN 1 AND 64),
    CHECK (
        (generation_before IS NULL AND generation_after IS NULL)
        OR (generation_before IS NOT NULL AND generation_after IS NOT NULL)
    )
) STRICT;

-- The audit surface reads newest-first over a bounded window.
CREATE INDEX audit_events_occurred_at ON audit_events (occurred_at);

-- Backfill: every client that exists in a v2 database gains a product metadata
-- row so the product model is total over existing state.
--
-- The label is derived from the stable `ClientId` rather than from a counter or
-- a display name, so the same client gets the same derived label on every host
-- that runs this migration, and re-running the backfill is a no-op. `enabled`
-- is 1 for all of them: a client that existed before product semantics existed
-- was, by definition, configured and working, and silently disabling one
-- during a schema migration would change kernel intent.
--
-- Timestamps come from the installation row so the backfill is deterministic
-- per database rather than per wall-clock instant.
INSERT INTO client_product_settings (client_id, label, enabled,
                                     client_keepalive_seconds,
                                     created_at, updated_at)
SELECT
    clients.id,
    'client-' || substr(clients.id, 1, 8),
    1,
    NULL,
    installation.created_at,
    installation.created_at
FROM clients
CROSS JOIN (SELECT created_at FROM installation WHERE singleton = 1) AS installation;

-- One materialized view is not created here on purpose: `read_desired` rebuilds
-- the product snapshot from the side tables in the same transaction that
-- validates it, which keeps a single writer and avoids a second authority for
-- the same fact.