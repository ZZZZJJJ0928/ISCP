package authority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/jackc/pgx/v5"
)

// LegacyCutoverEvidence is an independently audited inventory, including keys
// deleted by old cleanup. Database emptiness is never completeness evidence.
// Original business requests and their signatures are not imported or replayed.
type LegacyCutoverEvidence struct {
	Version                int      `json:"version"`
	ScopeID                string   `json:"scope_id"`
	DomainID               string   `json:"domain_id"`
	HistoryID              string   `json:"history_id"`
	ExpectedWriterEpoch    string   `json:"expected_writer_epoch"`
	CompleteKeyHistory     bool     `json:"complete_key_history"`
	SourceCheckpointSHA256 string   `json:"source_checkpoint_sha256"`
	RetiredWriterRoles     []string `json:"retired_writer_roles"`
	LegacyMessageIDs       []string `json:"legacy_message_ids"`
}

func ParseLegacyCutoverEvidence(raw []byte, expectedDigest string) (LegacyCutoverEvidence, error) {
	var m LegacyCutoverEvidence
	h := sha256.Sum256(raw)
	if len(raw) > 64<<20 || base64.RawURLEncoding.EncodeToString(h[:]) != expectedDigest {
		return m, errors.New("cutover evidence digest mismatch")
	}
	if _, err := canonical.ParseStrict(raw); err != nil {
		return m, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return m, errors.New("trailing cutover evidence")
	}
	if m.Version != 1 || !validID(m.ScopeID) || !validID(m.DomainID) || !validCounter(m.ExpectedWriterEpoch, false) || !validDigest(m.HistoryID) || !validDigest(m.SourceCheckpointSHA256) || !m.CompleteKeyHistory || len(m.RetiredWriterRoles) == 0 {
		return m, errors.New("complete independently audited key history and retired writer roles required")
	}
	seen := map[string]bool{}
	for _, key := range m.LegacyMessageIDs {
		if !validID(key) || seen[key] {
			return m, errors.New("invalid or duplicate legacy key")
		}
		seen[key] = true
	}
	return m, nil
}
func validDigest(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s
}
func lockCutoverTables(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `LOCK TABLE iscp_relay.messages,iscp_relay.delivery_receipts,iscp_relay.admissions,iscp_relay.legacy_admission_keys,iscp_relay.devices,iscp_relay.access_tokens,iscp_relay.refresh_tokens,iscp_relay.writer_scopes,iscp_relay.domain_authority,iscp_relay.device_authority,iscp_relay.connection_owners IN ACCESS EXCLUSIVE MODE`)
	return err
}

// PrepareLegacyCutover commits a fail-closed maintenance boundary before an
// operator verifies evidence. It cannot reset an already continuous namespace.
func PrepareLegacyCutover(ctx context.Context, tx pgx.Tx, scope, domain string) error {
	if !validID(scope) || !validID(domain) {
		return ErrUnavailable
	}
	if err := lockCutoverTables(ctx, tx); err != nil {
		return err
	}
	var existing bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iscp_relay.domain_authority WHERE (domain_id=$1 AND (scope_id<>$2 OR history_state NOT IN ('uninitialized','incomplete') OR history_id IS NOT NULL)) OR (scope_id=$2 AND domain_id<>$1))`, domain, scope).Scan(&existing); err != nil {
		return err
	}
	if existing {
		return errors.New("existing history cannot be replaced by legacy cutover")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO iscp_relay.writer_scopes(scope_id,writer_role,writes_enabled) VALUES($1,current_user,false) ON CONFLICT(scope_id) DO UPDATE SET writes_enabled=false`, scope); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO iscp_relay.domain_authority(scope_id,domain_id,history_state) VALUES($1,$2,'incomplete') ON CONFLICT(scope_id,domain_id) DO UPDATE SET history_state='incomplete'`, scope, domain); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO iscp_relay.device_authority(scope_id,domain_id,device_id,credential_generation,authorization_revision,state_version,state) SELECT $1,domain_id,device_id,1,1,1,CASE WHEN status='active' THEN 'active' ELSE 'revoked' END FROM iscp_relay.devices WHERE domain_id=$2 ON CONFLICT DO NOTHING`, scope, domain); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO iscp_relay.connection_owners(scope_id,domain_id,device_id) SELECT scope_id,domain_id,device_id FROM iscp_relay.device_authority WHERE scope_id=$1 AND domain_id=$2 ON CONFLICT DO NOTHING`, scope, domain)
	return err
}

// ActivateLegacyCutover requires a separately committed prepare step. Failures
// leave that incomplete maintenance state in place. All old key tombstones are
// preserved forever; old queued payloads and receipts stay byte-for-byte intact.
func ActivateLegacyCutover(ctx context.Context, tx pgx.Tx, m LegacyCutoverEvidence, evidenceDigest string, confirmComplete bool) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	h := sha256.Sum256(raw)
	if _, err = ParseLegacyCutoverEvidence(raw, base64.RawURLEncoding.EncodeToString(h[:])); err != nil {
		return err
	}
	if !confirmComplete || !m.CompleteKeyHistory || !validDigest(evidenceDigest) {
		return errors.New("explicit complete-history attestation required")
	}
	if err := lockCutoverTables(ctx, tx); err != nil {
		return err
	}
	var state, epoch, role string
	var history *string
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT a.history_state,a.history_id,w.writer_epoch::text,w.writes_enabled,current_user FROM iscp_relay.domain_authority a JOIN iscp_relay.writer_scopes w USING(scope_id) WHERE a.scope_id=$1 AND a.domain_id=$2`, m.ScopeID, m.DomainID).Scan(&state, &history, &epoch, &enabled, &role); err != nil {
		return err
	}
	if state != "incomplete" || history != nil || enabled || epoch != m.ExpectedWriterEpoch {
		return errors.New("prepared maintenance boundary or expected writer epoch missing")
	}
	for _, old := range m.RetiredWriterRoles {
		var unsafe, active bool
		if old == role {
			return errors.New("new writer must not reuse retired database role")
		}
		if err := tx.QueryRow(ctx, `SELECT rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname=$1`, old).Scan(&unsafe); err != nil {
			return err
		}
		if unsafe {
			return errors.New("retired writer role must be NOLOGIN without elevated privileges")
		}
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1)`, old).Scan(&active); err != nil {
			return err
		}
		if active {
			return errors.New("retired writer sessions still active")
		}
		for _, table := range []string{"messages", "delivery_receipts", "devices", "access_tokens", "refresh_tokens"} {
			var writable bool
			if err := tx.QueryRow(ctx, `SELECT has_table_privilege($1,$2,'INSERT,UPDATE,DELETE,TRUNCATE')`, old, "iscp_relay."+table).Scan(&writable); err != nil {
				return err
			}
			if writable {
				return fmt.Errorf("retired role retains write privileges on %s", table)
			}
		}
		// A login role that can assume the retired role would bypass NOLOGIN.
		var inherited bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolcanlogin AND NOT r.rolsuper AND pg_has_role(r.oid,$1,'MEMBER'))`, old).Scan(&inherited); err != nil {
			return err
		}
		if inherited {
			return errors.New("login role can still assume retired writer role")
		}
	}
	keys := map[string]bool{}
	for _, key := range m.LegacyMessageIDs {
		keys[key] = true
	}
	rows, err := tx.Query(ctx, `SELECT message_id FROM iscp_relay.messages WHERE domain_id=$1 UNION SELECT message_id FROM iscp_relay.delivery_receipts WHERE domain_id=$1 UNION SELECT message_id FROM iscp_relay.legacy_admission_keys WHERE domain_id=$1`, m.DomainID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			rows.Close()
			return err
		}
		if !keys[key] {
			rows.Close()
			return errors.New("audited manifest omits persisted legacy key")
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var admitted bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iscp_relay.admissions WHERE domain_id=$1)`, m.DomainID).Scan(&admitted); err != nil {
		return err
	}
	if admitted {
		return errors.New("existing v0.3 history cannot be replaced")
	}
	ordered := append([]string(nil), m.LegacyMessageIDs...)
	sort.Strings(ordered)
	for _, key := range ordered {
		if _, err = tx.Exec(ctx, `INSERT INTO iscp_relay.legacy_admission_keys(domain_id,message_id,evidence_sha256) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, m.DomainID, key, evidenceDigest); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE iscp_relay.domain_authority SET history_id=$3,history_state='continuous',history_evidence_sha256=$4,activated_at=now() WHERE scope_id=$1 AND domain_id=$2`, m.ScopeID, m.DomainID, m.HistoryID, evidenceDigest); err != nil {
		return err
	}
	// Every pre-maintenance process keeps its original epoch and stays fenced.
	// Legacy tokens retain their null generation and require control recovery.
	_, err = tx.Exec(ctx, `UPDATE iscp_relay.writer_scopes SET writer_epoch=writer_epoch+1,writer_role=current_user,writes_enabled=true WHERE scope_id=$1`, m.ScopeID)
	return err
}
