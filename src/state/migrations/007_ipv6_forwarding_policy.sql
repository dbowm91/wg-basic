-- Migration 007: explicit opt-in for IPv6 forwarding policy.
ALTER TABLE network_policy
ADD COLUMN ipv6_forwarding_required INTEGER NOT NULL DEFAULT 0
CHECK (ipv6_forwarding_required IN (0, 1));
