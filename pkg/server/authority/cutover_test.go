package authority

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
)

func TestLegacyCutoverRequiresCompleteEvidenceAndRetiredWriter(t *testing.T) {
	pool := authorityDatabase(t)
	ctx := t.Context()
	role := fmt.Sprintf("old_iscp_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{role}.Sanitize()
	if _, err := pool.Exec(ctx, "CREATE ROLE "+quoted+" LOGIN PASSWORD 'isolated-cutover-only'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), "DROP OWNED BY "+quoted)
		pool.Exec(context.Background(), "DROP ROLE "+quoted)
	})
	_, err := pool.Exec(ctx, `INSERT INTO iscp_relay.devices(id,domain_id,device_id,identity_raw,identity_canonical,public_key_thumbprint) VALUES('00000000-0000-4000-8000-000000000001','legacy-domain','sender','original identity','original identity','thumb'); INSERT INTO iscp_relay.messages(id,domain_id,message_id,sender_device_id,recipient_device_id,session_id,payload_type,route_metadata,envelope_raw,envelope_canonical,expires_at) VALUES('00000000-0000-4000-8000-000000000002','legacy-domain','still-queued','sender','receiver','legacy-session','test','{}','original queued ciphertext','original queued ciphertext',now()+interval '1 day')`)
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := pool.Begin(ctx)
	if err = PrepareLegacyCutover(ctx, tx, "relay", "legacy-domain"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	evidence := LegacyCutoverEvidence{Version: 1, ScopeID: "relay", DomainID: "legacy-domain", ExpectedWriterEpoch: "1", HistoryID: duplex.RandomID(), CompleteKeyHistory: true, SourceCheckpointSHA256: duplex.RandomID(), RetiredWriterRoles: []string{role}, LegacyMessageIDs: []string{"deleted-by-old-cleanup", "still-queued"}}
	activate := func(m LegacyCutoverEvidence) error {
		raw, _ := json.Marshal(m)
		h := sha256.Sum256(raw)
		digest := base64.RawURLEncoding.EncodeToString(h[:])
		parsed, e := ParseLegacyCutoverEvidence(raw, digest)
		if e != nil {
			return e
		}
		tx, e := pool.Begin(ctx)
		if e != nil {
			return e
		}
		defer tx.Rollback(context.Background())
		if e = ActivateLegacyCutover(ctx, tx, parsed, digest, true); e != nil {
			return e
		}
		return tx.Commit(ctx)
	}
	if err = activate(evidence); err == nil {
		t.Fatal("LOGIN old writer accepted")
	}
	retiredConfig := pool.Config().ConnConfig.Copy()
	retiredConfig.User = role
	retiredConfig.Password = "isolated-cutover-only"
	retiredSession, err := pgx.ConnectConfig(ctx, retiredConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer retiredSession.Close(context.Background())
	if _, err = pool.Exec(ctx, "ALTER ROLE "+quoted+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	if err = activate(evidence); err == nil {
		t.Fatal("existing retired writer session survived fence")
	}
	retiredSession.Close(ctx)
	if _, err = pool.Exec(ctx, "ALTER ROLE "+quoted+" NOLOGIN; GRANT INSERT ON iscp_relay.messages TO "+quoted); err != nil {
		t.Fatal(err)
	}
	if err = activate(evidence); err == nil {
		t.Fatal("old writer retained mutation rights")
	}
	if _, err = pool.Exec(ctx, "REVOKE ALL ON iscp_relay.messages FROM "+quoted); err != nil {
		t.Fatal(err)
	}
	missing := evidence
	missing.LegacyMessageIDs = []string{"deleted-by-old-cleanup"}
	if err = activate(missing); err == nil {
		t.Fatal("manifest omitted current queue key")
	}
	incomplete := evidence
	incomplete.CompleteKeyHistory = false
	if err = activate(incomplete); err == nil {
		t.Fatal("incomplete external evidence accepted")
	}
	var state string
	var enabled bool
	if err = pool.QueryRow(ctx, `SELECT history_state,writes_enabled FROM iscp_relay.domain_authority JOIN iscp_relay.writer_scopes USING(scope_id)`).Scan(&state, &enabled); err != nil || state != "incomplete" || enabled {
		t.Fatal(state, enabled, err)
	}
	if err = activate(evidence); err != nil {
		t.Fatal(err)
	}
	tx, _ = pool.Begin(ctx)
	defer tx.Rollback(context.Background())
	_, err = Lock(ctx, tx, Request{ScopeID: "relay", DomainID: "legacy-domain", ExpectedWriterEpoch: "2", RequireContinuousHistory: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range evidence.LegacyMessageIDs {
		r, e := repository.ReconcileAdmission(ctx, tx, "legacy-domain", "sender", duplex.Submission{MessageID: key}, time.Now())
		if e != nil || r.State != "unknown" || r.Reason != "legacy_record" {
			t.Fatal(key, r, e)
		}
	}
	repo := repository.NewRelayRepository(tx)
	claimed, err := repo.ClaimDuplexPendingMessage(ctx, repository.DomainID("legacy-domain"), "receiver", time.Now(), time.Minute)
	if err != nil || len(claimed) != 0 {
		t.Fatal("legacy ciphertext entered new delivery plane", claimed, err)
	}
	var raw []byte
	if err = tx.QueryRow(ctx, `SELECT envelope_raw FROM iscp_relay.messages WHERE message_id='still-queued'`).Scan(&raw); err != nil || string(raw) != "original queued ciphertext" {
		t.Fatal("legacy queue changed", err)
	}
	tx.Rollback(ctx)
	if err = activate(evidence); err == nil {
		t.Fatal("continuous history was replaced")
	}
	t.Log("complete external legacy inventory preserves deleted keys as unknown and original queue bytes; new writer epoch fenced old process")
}
