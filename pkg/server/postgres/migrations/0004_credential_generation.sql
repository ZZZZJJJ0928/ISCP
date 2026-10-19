-- Legacy tokens are deliberately NULL, never silently upgraded to v0.3.
ALTER TABLE iscp_relay.access_tokens ADD COLUMN IF NOT EXISTS credential_generation numeric(20,0) CHECK(credential_generation BETWEEN 1 AND 18446744073709551615);
ALTER TABLE iscp_relay.refresh_tokens ADD COLUMN IF NOT EXISTS credential_generation numeric(20,0) CHECK(credential_generation BETWEEN 1 AND 18446744073709551615);
INSERT INTO iscp_relay.schema_migrations(version,name) VALUES(4,'credential_generation') ON CONFLICT(version) DO NOTHING;
