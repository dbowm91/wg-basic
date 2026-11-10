-- Migration 009: optional client expiration.
--
-- A null deadline means the client never expires. Existing clients stay null,
-- so this step does not disable anyone and does not advance desired generation.
-- The column is a Unix second on the management worker's clock. Expiry disables
-- the client; it does not delete the row, the address, or the keys.
ALTER TABLE client_product_settings
ADD COLUMN expires_at INTEGER;
