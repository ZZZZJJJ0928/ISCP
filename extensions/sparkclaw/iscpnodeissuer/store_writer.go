package iscpnodeissuer

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"regexp"
)

var ErrWriterFenced = errors.New("issuer writer is fenced")

const issuerWriterSchema = `
CREATE TABLE IF NOT EXISTS sparkclaw_iscp_issuer_writer (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 writer_epoch numeric(20,0) NOT NULL CHECK(writer_epoch>=1 AND writer_epoch<=18446744073709551615),
 writer_role name NOT NULL, format_version integer NOT NULL CHECK(format_version=2),
 writes_enabled boolean NOT NULL DEFAULT false,
 activation_evidence_sha256 text NOT NULL CHECK(length(activation_evidence_sha256)=43));
CREATE OR REPLACE FUNCTION sparkclaw_iscp_issuer_writer_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE s sparkclaw_iscp_issuer_writer%ROWTYPE;
BEGIN
 SELECT * INTO s FROM sparkclaw_iscp_issuer_writer WHERE singleton FOR SHARE;
 IF FOUND AND (NOT s.writes_enabled OR current_user<>s.writer_role OR
  current_setting('iscp.issuer_writer_epoch',true) IS DISTINCT FROM s.writer_epoch::text OR
  current_setting('iscp.issuer_writer_format',true) IS DISTINCT FROM '2') THEN
  RAISE EXCEPTION 'issuer writer fenced' USING ERRCODE='55000';
 END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
DROP TRIGGER IF EXISTS iscp_issuer_writer_guard ON sparkclaw_iscp_issuer_state;
CREATE TRIGGER iscp_issuer_writer_guard BEFORE INSERT OR UPDATE OR DELETE ON sparkclaw_iscp_issuer_state FOR EACH ROW EXECUTE FUNCTION sparkclaw_iscp_issuer_writer_guard();`

// ActivateControlWriter is an explicit maintenance action. It establishes only
// writer provenance; missing per-device operation history remains unavailable.
// Repeating startup never adopts or increments an epoch.
func (s *PostgresStore) ActivateControlWriter(ctx context.Context, epoch, evidence string) error {
	if !regexp.MustCompile(`^[1-9][0-9]{0,19}$`).MatchString(epoch) || !ValidActivationEvidence(evidence) {
		return ErrInvalid
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO sparkclaw_iscp_issuer_writer(singleton,writer_epoch,writer_role,format_version,writes_enabled,activation_evidence_sha256) VALUES(true,$1,current_user,2,true,$2) ON CONFLICT DO NOTHING`, epoch, evidence)
	return err
}
func (s *PostgresStore) ConfigureControlWriter(ctx context.Context, epoch string) error {
	if epoch == "" || s.writerEpoch != "" {
		return ErrWriterFenced
	}
	var matches bool
	err := s.pool.QueryRow(ctx, `SELECT writer_epoch::text=$1 AND writer_role=current_user AND writes_enabled AND format_version=2 FROM sparkclaw_iscp_issuer_writer WHERE singleton`, epoch).Scan(&matches)
	if err != nil || !matches {
		return ErrWriterFenced
	}
	s.writerEpoch = epoch
	return nil
}

// RequireControlWriter is part of Store's explicit maintenance contract.
// Update repeats this check under the aggregate transaction's writer lock.
func (s *PostgresStore) RequireControlWriter(ctx context.Context) error {
	if s.writerEpoch == "" {
		return ErrWriterFenced
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	return s.lockWriter(ctx, tx)
}
func (s *PostgresStore) lockWriter(ctx context.Context, tx pgx.Tx) error {
	var epoch, role string
	var enabled bool
	err := tx.QueryRow(ctx, `SELECT writer_epoch::text,writer_role::text,writes_enabled FROM sparkclaw_iscp_issuer_writer WHERE singleton FOR SHARE`).Scan(&epoch, &role, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		if s.writerEpoch != "" {
			return ErrWriterFenced
		}
		return nil
	}
	if err != nil {
		return err
	}
	if s.writerEpoch == "" || epoch != s.writerEpoch || !enabled {
		return ErrWriterFenced
	}
	var current string
	if err = tx.QueryRow(ctx, "SELECT current_user").Scan(&current); err != nil {
		return err
	}
	if current != role {
		return ErrWriterFenced
	}
	_, err = tx.Exec(ctx, "SELECT set_config('iscp.issuer_writer_epoch',$1,true),set_config('iscp.issuer_writer_format','2',true)", s.writerEpoch)
	return err
}
