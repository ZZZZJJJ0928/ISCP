-- Immutable admission order is distinct from signed second-resolution times.
ALTER TABLE iscp_relay.messages ADD COLUMN IF NOT EXISTS admission_order bigserial;
CREATE UNIQUE INDEX IF NOT EXISTS duplex_message_admission_order ON iscp_relay.messages(admission_order);
CREATE INDEX IF NOT EXISTS duplex_pending_session_order ON iscp_relay.messages(domain_id,recipient_device_id,sender_device_id,session_id,admission_order) WHERE delivered_at IS NULL;
INSERT INTO iscp_relay.schema_migrations(version,name) VALUES(6,'duplex_order') ON CONFLICT(version) DO NOTHING;
CREATE OR REPLACE FUNCTION iscp_relay.immutable_duplex_order() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.admission_order IS DISTINCT FROM OLD.admission_order THEN RAISE EXCEPTION 'immutable admission order' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS duplex_immutable_order ON iscp_relay.messages;
CREATE TRIGGER duplex_immutable_order BEFORE UPDATE ON iscp_relay.messages FOR EACH ROW EXECUTE FUNCTION iscp_relay.immutable_duplex_order();
