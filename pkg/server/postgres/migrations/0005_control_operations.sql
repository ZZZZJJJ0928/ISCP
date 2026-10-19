CREATE TABLE IF NOT EXISTS iscp_relay.control_operations (
 scope_id text NOT NULL, authority_id text NOT NULL, actor_domain text NOT NULL, actor_device text NOT NULL,
 namespace text NOT NULL, operation_id text NOT NULL, subject_device text NOT NULL,
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext)<=1048576),
 PRIMARY KEY(scope_id,actor_domain,actor_device,namespace,operation_id),
 FOREIGN KEY(scope_id,actor_domain) REFERENCES iscp_relay.domain_authority(scope_id,domain_id));
CREATE OR REPLACE FUNCTION iscp_relay.require_control_writer() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE scope text; s iscp_relay.writer_scopes%ROWTYPE;
BEGIN
 IF TG_OP='DELETE' THEN scope:=OLD.scope_id; ELSE scope:=NEW.scope_id; END IF;
 SELECT * INTO s FROM iscp_relay.writer_scopes WHERE scope_id=scope FOR SHARE;
 IF NOT FOUND OR NOT s.writes_enabled OR s.writer_role::text<>current_user OR
  current_setting('iscp.writer_scope',true) IS DISTINCT FROM s.scope_id OR
  current_setting('iscp.writer_epoch',true) IS DISTINCT FROM s.writer_epoch::text OR
  current_setting('iscp.writer_format',true) IS DISTINCT FROM s.writer_format::text THEN
  RAISE EXCEPTION 'control writer fenced' USING ERRCODE='55000';
 END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'control history cannot be silently pruned' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS control_operation_writer ON iscp_relay.control_operations;
CREATE TRIGGER control_operation_writer BEFORE INSERT OR UPDATE OR DELETE ON iscp_relay.control_operations FOR EACH ROW EXECUTE FUNCTION iscp_relay.require_control_writer();
INSERT INTO iscp_relay.schema_migrations(version,name) VALUES(5,'control_operations') ON CONFLICT(version) DO NOTHING;
