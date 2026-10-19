CREATE UNIQUE INDEX IF NOT EXISTS duplex_domain_single_scope ON iscp_relay.domain_authority(domain_id);
CREATE TABLE IF NOT EXISTS iscp_relay.admissions (
 domain_id text NOT NULL, message_id text NOT NULL,
 scope_id text NOT NULL, history_id text NOT NULL,
 sender_device_id text NOT NULL, recipient_device_id text NOT NULL,
 envelope_digest text NOT NULL, not_after timestamptz NOT NULL,
 accepted_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 receipt_raw bytea NOT NULL, receipt_canonical bytea NOT NULL,
 format_version integer NOT NULL DEFAULT 1 CHECK(format_version=1),
 PRIMARY KEY(domain_id,message_id),
 FOREIGN KEY(scope_id,domain_id) REFERENCES iscp_relay.domain_authority(scope_id,domain_id),
 CHECK(expires_at<=not_after AND expires_at>=accepted_at)
);
CREATE TABLE IF NOT EXISTS iscp_relay.legacy_admission_keys (
 domain_id text NOT NULL, message_id text NOT NULL, evidence_sha256 text NOT NULL,
 PRIMARY KEY(domain_id,message_id)
);
-- Every protected write checks the current scope's epoch and role. A real old
-- binary has no transaction marker and cannot overwrite records even if it
-- ignores format columns. Operator cutover additionally revokes old DB roles.
CREATE OR REPLACE FUNCTION iscp_relay.require_duplex_writer() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d text; s iscp_relay.writer_scopes%ROWTYPE;
BEGIN
 IF TG_OP='DELETE' THEN d:=OLD.domain_id; ELSE d:=NEW.domain_id; END IF;
 SELECT w.* INTO s FROM iscp_relay.writer_scopes w JOIN iscp_relay.domain_authority a ON a.scope_id=w.scope_id WHERE a.domain_id=d;
 IF NOT FOUND THEN
   IF TG_TABLE_NAME='admissions' THEN RAISE EXCEPTION 'duplex scope missing' USING ERRCODE='55000'; END IF;
   IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
 END IF;
 IF NOT s.writes_enabled OR s.writer_role::text<>current_user OR
    current_setting('iscp.writer_scope',true) IS DISTINCT FROM s.scope_id OR
    current_setting('iscp.writer_epoch',true) IS DISTINCT FROM s.writer_epoch::text OR
    current_setting('iscp.writer_format',true) IS DISTINCT FROM s.writer_format::text THEN
   RAISE EXCEPTION 'duplex writer fenced' USING ERRCODE='55000';
 END IF;
 IF TG_TABLE_NAME='admissions' AND TG_OP<>'INSERT' THEN
   RAISE EXCEPTION 'immutable admission cannot be changed or pruned' USING ERRCODE='55000';
 END IF;
 IF TG_TABLE_NAME='messages' THEN
 IF TG_OP='UPDATE' THEN
 IF
    (NEW.domain_id,NEW.message_id,NEW.sender_device_id,NEW.recipient_device_id,NEW.session_id,NEW.payload_type,NEW.route_metadata,NEW.envelope_raw,NEW.envelope_canonical,NEW.priority,NEW.queued_at,NEW.expires_at)
    IS DISTINCT FROM
    (OLD.domain_id,OLD.message_id,OLD.sender_device_id,OLD.recipient_device_id,OLD.session_id,OLD.payload_type,OLD.route_metadata,OLD.envelope_raw,OLD.envelope_canonical,OLD.priority,OLD.queued_at,OLD.expires_at) THEN
   RAISE EXCEPTION 'immutable queued message content' USING ERRCODE='55000';
 END IF;
 END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
DROP TRIGGER IF EXISTS duplex_message_writer ON iscp_relay.messages;
CREATE TRIGGER duplex_message_writer BEFORE INSERT OR UPDATE OR DELETE ON iscp_relay.messages FOR EACH ROW EXECUTE FUNCTION iscp_relay.require_duplex_writer();
DROP TRIGGER IF EXISTS duplex_receipt_writer ON iscp_relay.delivery_receipts;
CREATE TRIGGER duplex_receipt_writer BEFORE INSERT OR UPDATE OR DELETE ON iscp_relay.delivery_receipts FOR EACH ROW EXECUTE FUNCTION iscp_relay.require_duplex_writer();
DROP TRIGGER IF EXISTS duplex_admission_writer ON iscp_relay.admissions;
CREATE TRIGGER duplex_admission_writer BEFORE INSERT OR UPDATE OR DELETE ON iscp_relay.admissions FOR EACH ROW EXECUTE FUNCTION iscp_relay.require_duplex_writer();
INSERT INTO iscp_relay.schema_migrations(version,name) VALUES(3,'duplex_admission') ON CONFLICT(version) DO NOTHING;
