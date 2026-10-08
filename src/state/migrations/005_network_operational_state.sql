-- Existing servers remain enabled; later offline maintenance may disable the
-- network projection without deleting server or client configuration.
CREATE TABLE network_operational_state (
    interface_id TEXT NOT NULL PRIMARY KEY
                 REFERENCES managed_interfaces (id) ON DELETE CASCADE,
    operational_enabled INTEGER NOT NULL DEFAULT 1
                        CHECK (operational_enabled IN (0, 1))
) STRICT;

INSERT INTO network_operational_state (interface_id, operational_enabled)
SELECT id, 1 FROM managed_interfaces;
