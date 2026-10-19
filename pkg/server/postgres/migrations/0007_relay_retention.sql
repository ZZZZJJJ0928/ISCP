-- The original signed receipt, its lookup fields and permanent unique key stay
-- immutable. No consumer reads this redundant canonical JSON representation.
-- Old binaries that INSERT this column are not schema-compatible rollback
-- targets; migrate only with Relay writers stopped and deploy the new binary.
ALTER TABLE iscp_relay.admissions DROP COLUMN IF EXISTS receipt_canonical;

-- Bound work when reclaiming delivered rows ahead of their transport deadline.
CREATE INDEX IF NOT EXISTS idx_relay_delivered_cleanup
 ON iscp_relay.messages(domain_id,expires_at,id) WHERE delivered_at IS NOT NULL;

INSERT INTO iscp_relay.schema_migrations(version,name)
 VALUES(7,'relay_retention') ON CONFLICT(version) DO NOTHING;
