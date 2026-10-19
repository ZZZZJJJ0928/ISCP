-- MarkMessageDelivered runs before each receive loop advances to the next
-- envelope. Index only pending receipts so retained delivery history does not
-- turn every delivery into a scan of the whole receipt ledger.
CREATE INDEX IF NOT EXISTS idx_sparkclaw_receipts_queued_message
ON iscp_relay.delivery_receipts (domain_id, message_id)
WHERE status = 'queued';
