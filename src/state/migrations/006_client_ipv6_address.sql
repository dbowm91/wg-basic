-- Migration 006: optional IPv6 tunnel address for managed clients.
-- IPv4 remains required and unchanged. NULL preserves every existing row.
ALTER TABLE clients
    ADD COLUMN assigned_ipv6_address TEXT
    CHECK (assigned_ipv6_address IS NULL OR instr(assigned_ipv6_address, ':') > 0);

CREATE UNIQUE INDEX clients_unique_ipv6_address
    ON clients (interface_id, assigned_ipv6_address)
    WHERE assigned_ipv6_address IS NOT NULL;
