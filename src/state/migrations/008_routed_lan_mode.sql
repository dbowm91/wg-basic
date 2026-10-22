-- Migration 008: the typed routing mode and the routed-LAN destination allowlist.
--
-- A policy that declares a routed LAN is held to a different contract than one
-- that declares a host-only endpoint, so the mode is persisted rather than
-- inferred from the forwarding flags. The destination allowlist is persisted
-- beside it: the approved downstream prefixes are part of the contract, not a
-- runtime detail of one apply.
--
-- Existing rows keep the behaviour they already had. A policy that asks for
-- forwarding or masquerade is a gateway policy; one that asks for neither is
-- host-only. No existing row becomes a routed-LAN policy, because nothing
-- before this migration could express one, and no existing row loses a
-- destination allowlist, because none had one.
ALTER TABLE network_policy
ADD COLUMN mode TEXT NOT NULL DEFAULT 'host_only'
    CHECK (mode IN ('host_only', 'routed_lan', 'gateway'));

CREATE TABLE network_policy_destination_prefixes (
    position INTEGER NOT NULL PRIMARY KEY,
    prefix TEXT NOT NULL
) STRICT;

UPDATE network_policy
SET mode = 'gateway'
WHERE singleton = 1
  AND (masquerade = 1 OR ipv4_forwarding_required = 1 OR ipv6_forwarding_required = 1);
