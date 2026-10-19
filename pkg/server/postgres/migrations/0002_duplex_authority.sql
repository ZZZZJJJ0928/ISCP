-- No existing namespace is activated by this additive migration. History must
-- be established by an explicit maintenance operation with retained evidence.
CREATE TABLE IF NOT EXISTS iscp_relay.writer_scopes (
 scope_id text PRIMARY KEY,
 writer_epoch numeric(20,0) NOT NULL DEFAULT 1 CHECK (writer_epoch BETWEEN 1 AND 18446744073709551615),
 writer_format integer NOT NULL DEFAULT 1 CHECK (writer_format = 1),
 writer_role name NOT NULL,
 writes_enabled boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS iscp_relay.domain_authority (
 scope_id text NOT NULL REFERENCES iscp_relay.writer_scopes(scope_id),
 domain_id text NOT NULL,
 history_id text,
 history_state text NOT NULL DEFAULT 'uninitialized' CHECK (history_state IN ('uninitialized','continuous','incomplete','closed')),
 history_evidence_sha256 text,
 activated_at timestamptz,
 PRIMARY KEY(scope_id,domain_id),
 CHECK (history_state <> 'continuous' OR (length(history_id)=43 AND length(history_evidence_sha256)=43 AND activated_at IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS iscp_relay.device_authority (
 scope_id text NOT NULL,
 domain_id text NOT NULL,
 device_id text NOT NULL,
 credential_generation numeric(20,0) NOT NULL CHECK (credential_generation BETWEEN 1 AND 18446744073709551615),
 authorization_revision numeric(20,0) NOT NULL CHECK (authorization_revision BETWEEN 1 AND 18446744073709551615),
 state_version numeric(20,0) NOT NULL CHECK (state_version BETWEEN 1 AND 18446744073709551615),
 state text NOT NULL CHECK (state IN ('active','closing','revoked')),
 PRIMARY KEY(scope_id,domain_id,device_id),
 FOREIGN KEY(scope_id,domain_id) REFERENCES iscp_relay.domain_authority(scope_id,domain_id)
);
CREATE TABLE IF NOT EXISTS iscp_relay.connection_owners (
 scope_id text NOT NULL,
 domain_id text NOT NULL,
 device_id text NOT NULL,
 owner_generation numeric(20,0) NOT NULL DEFAULT 0 CHECK (owner_generation BETWEEN 0 AND 18446744073709551615),
 connection_id text,
 authority_expires_at timestamptz,
 credential_generation numeric(20,0),
 authorization_revision numeric(20,0),
 PRIMARY KEY(scope_id,domain_id,device_id),
 FOREIGN KEY(scope_id,domain_id,device_id) REFERENCES iscp_relay.device_authority(scope_id,domain_id,device_id)
);
INSERT INTO iscp_relay.schema_migrations(version,name) VALUES(2,'duplex_authority') ON CONFLICT(version) DO NOTHING;
