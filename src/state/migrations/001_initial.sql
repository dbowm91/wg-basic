-- Migration 001: initial durable application-state schema.
--
-- This file is immutable once shipped. Every subsequent schema change must be a
-- new numbered migration.
--
-- There is deliberately no column for live telemetry: no latest handshake, no
-- observed endpoint, no RX/TX counters, no ifindex, no kernel route handle, and
-- no nftables handle or counter. Those values are observed from the kernel and
-- are never authoritative configuration.

-- Singleton installation row. `singleton` enforces the single-row structurally.
CREATE TABLE installation (
    singleton           INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    installation_id     TEXT    NOT NULL UNIQUE,
    desired_generation  INTEGER NOT NULL CHECK (desired_generation > 0),
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
) STRICT;

CREATE TABLE managed_interfaces (
    id                 TEXT    NOT NULL PRIMARY KEY,
    name               TEXT    NOT NULL UNIQUE,
    ownership          TEXT    NOT NULL CHECK (ownership IN ('managed', 'observe_only')),
    lifecycle          TEXT    NOT NULL CHECK (lifecycle IN ('present', 'absent')),
    admin_up           INTEGER          CHECK (admin_up IN (0, 1)),
    private_key        TEXT    NOT NULL,
    listen_port        INTEGER          CHECK (listen_port IS NULL OR listen_port BETWEEN 1 AND 65535),
    manage_all_peers   INTEGER NOT NULL CHECK (manage_all_peers IN (0, 1)),
    position           INTEGER NOT NULL,
    CHECK (
        (lifecycle = 'present' AND admin_up IS NOT NULL)
        OR (lifecycle = 'absent' AND admin_up IS NULL)
    )
) STRICT;

CREATE TABLE interface_tunnel_prefixes (
    interface_id   TEXT    NOT NULL REFERENCES managed_interfaces (id) ON DELETE CASCADE,
    prefix         TEXT    NOT NULL,
    position       INTEGER NOT NULL,
    PRIMARY KEY (interface_id, position)
) STRICT;

CREATE TABLE interface_addresses (
    interface_id   TEXT    NOT NULL REFERENCES managed_interfaces (id) ON DELETE CASCADE,
    address        TEXT    NOT NULL,
    presence       TEXT    NOT NULL CHECK (presence IN ('present', 'absent')),
    position       INTEGER NOT NULL,
    PRIMARY KEY (interface_id, position)
) STRICT;

CREATE TABLE managed_routes (
    interface_id   TEXT    NOT NULL REFERENCES managed_interfaces (id) ON DELETE CASCADE,
    destination    TEXT    NOT NULL,
    gateway        TEXT,
    presence       TEXT    NOT NULL CHECK (presence IN ('present', 'absent')),
    position       INTEGER NOT NULL,
    PRIMARY KEY (interface_id, position)
) STRICT;

CREATE TABLE peers (
    id                             TEXT    NOT NULL PRIMARY KEY,
    interface_id                   TEXT    NOT NULL REFERENCES managed_interfaces (id) ON DELETE CASCADE,
    public_key                     TEXT    NOT NULL,
    private_key                    TEXT,
    preshared_key                  TEXT,
    persistent_keepalive_seconds   INTEGER          CHECK (
                                        persistent_keepalive_seconds IS NULL
                                        OR persistent_keepalive_seconds BETWEEN 0 AND 65535
                                    ),
    endpoint                       TEXT,
    position                       INTEGER NOT NULL,
    UNIQUE (interface_id, public_key)
) STRICT;

-- Server-side WireGuard AllowedIPs only.
CREATE TABLE peer_allowed_ips (
    peer_id     TEXT    NOT NULL REFERENCES peers (id) ON DELETE CASCADE,
    prefix      TEXT    NOT NULL,
    position    INTEGER NOT NULL,
    PRIMARY KEY (peer_id, position)
) STRICT;

CREATE TABLE clients (
    id                TEXT    NOT NULL PRIMARY KEY,
    interface_id      TEXT    NOT NULL REFERENCES managed_interfaces (id) ON DELETE CASCADE,
    peer_id           TEXT    NOT NULL REFERENCES peers (id) ON DELETE CASCADE,
    assigned_address  TEXT    NOT NULL,
    position          INTEGER NOT NULL,
    UNIQUE (interface_id, assigned_address)
) STRICT;

-- Client-side route policy. This is deliberately a separate table from
-- peer_allowed_ips and must never be overloaded to store DNS servers.
CREATE TABLE client_route_prefixes (
    client_id  TEXT    NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    prefix     TEXT    NOT NULL,
    position   INTEGER NOT NULL,
    PRIMARY KEY (client_id, position)
) STRICT;

-- Global client route policy that is not attached to a single client.
CREATE TABLE client_global_route_prefixes (
    prefix     TEXT    NOT NULL,
    position   INTEGER NOT NULL,
    PRIMARY KEY (position)
) STRICT;

-- At most one row: a single network policy bound to one managed interface.
CREATE TABLE network_policy (
    singleton                 INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    wireguard_interface       TEXT    NOT NULL REFERENCES managed_interfaces (name) ON DELETE CASCADE,
    ipv4_forwarding_required  INTEGER NOT NULL CHECK (ipv4_forwarding_required IN (0, 1)),
    egress_interface          TEXT    NOT NULL,
    masquerade                INTEGER NOT NULL CHECK (masquerade IN (0, 1))
) STRICT;

CREATE TABLE network_policy_source_prefixes (
    position  INTEGER NOT NULL PRIMARY KEY,
    prefix    TEXT    NOT NULL
) STRICT;

-- Reconciliation evidence. M001 records the shape but does not yet drive kernel
-- reconciliation from it.
CREATE TABLE convergence_state (
    singleton                   INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    last_attempted_generation   INTEGER,
    last_converged_generation   INTEGER,
    last_attempt_timestamp      INTEGER,
    last_outcome                TEXT
) STRICT;