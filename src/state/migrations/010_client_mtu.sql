-- Migration 010: optional client MTU for the exported WireGuard config.
--
-- Null means the config omits the MTU line. The value is not applied to the
-- server link. Existing clients stay null, and desired generation does not move.
ALTER TABLE client_product_settings
ADD COLUMN mtu INTEGER CHECK (mtu IS NULL OR (mtu BETWEEN 1280 AND 9000));
