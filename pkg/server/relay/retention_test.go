package iscprelayreference

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"github.com/Infinimesh-ai/ISCP/pkg/server/cleanup"
	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests use isolated databases created by receiveDatabase. Stop the
// background sweeper before seeding so every assertion uses the explicit cutoff.
func retentionQualification(t *testing.T) duplexQualification {
	t.Helper()
	q := newDuplexQualification(t)
	q.server.maintenanceCancel()
	q.server.duplexWG.Wait()
	return q
}

type retentionSeed struct {
	id, history     string
	expires         time.Time
	delivered       bool
	ciphertextBytes int
}

type retentionOriginal struct {
	sub     duplex.Submission
	receipt duplex.Receipt
}

func retentionTx(t *testing.T, q duplexQualification, keys ...string) pgx.Tx {
	t.Helper()
	tx, err := q.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	r := authority.Request{ScopeID: "relay-a", DomainID: "domain-a", ExpectedWriterEpoch: "1", RequireContinuousHistory: true,
		Devices: []authority.DeviceLock{{ID: q.a.Identity.DeviceID}}}
	for _, key := range keys {
		r.Keys = append(r.Keys, authority.Key{Namespace: "message", ID: key})
	}
	if _, err = authority.Lock(t.Context(), tx, r); err != nil {
		t.Fatal(err)
	}
	return tx
}

func retentionSeedMessages(t *testing.T, q duplexQualification, seeds []retentionSeed) map[string]retentionOriginal {
	t.Helper()
	keys := make([]string, len(seeds))
	for i, seed := range seeds {
		keys[i] = seed.id
	}
	tx := retentionTx(t, q, keys...)
	out := make(map[string]retentionOriginal, len(seeds))
	for _, seed := range seeds {
		env := qualificationEnvelope(q.a.Identity.DeviceID, q.b.Identity.DeviceID, seed.id)
		if seed.ciphertextBytes > 0 {
			env.Ciphertext = crypto.Base64URL(crypto.RandomBytes(seed.ciphertextBytes))
		}
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := duplex.Digest(json.RawMessage(raw))
		if err != nil {
			t.Fatal(err)
		}
		history := seed.history
		if history == "" {
			history = strings.Repeat("A", 43)
		}
		sub := duplex.Submission{MessageID: seed.id, EnvelopeDigest: digest, HistoryID: history, NotAfter: duplex.Timestamp(seed.expires), Envelope: raw}
		acceptedAt := seed.expires.Add(-30 * time.Second)
		result, err := repository.AdmitEnvelope(t.Context(), tx, "relay-a", "domain-a", q.a.Identity.DeviceID, "relay-a", sub, q.server.signer, acceptedAt)
		if err != nil || result.State != "accepted" || result.Receipt == nil {
			t.Fatalf("seed %s: %+v, %v", seed.id, result, err)
		}
		if err = duplex.VerifyReceipt(*result.Receipt, q.server.signer.Identity, sub, "relay-a", "domain-a", q.a.Identity.DeviceID, q.b.Identity.DeviceID); err != nil {
			t.Fatal(err)
		}
		if seed.delivered {
			if err = repository.NewRelayRepository(tx).MarkMessageDelivered(t.Context(), "domain-a", seed.id, acceptedAt.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
		}
		out[seed.id] = retentionOriginal{sub, *result.Receipt}
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return out
}

func retentionAdmissionSnapshot(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var result string
	// Compare every retained field, including receipt bytes and signature, while
	// allowing only the redundant canonical column to disappear in migration 7.
	if err := pool.QueryRow(t.Context(), `SELECT coalesce(jsonb_agg(to_jsonb(a)-'receipt_canonical' ORDER BY domain_id,message_id),'[]')::text FROM iscp_relay.admissions a`).Scan(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func retentionMessageIDs(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(t.Context(), `SELECT message_id FROM iscp_relay.messages ORDER BY message_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestRetentionBoundedProgressAndImmutableAdmissions(t *testing.T) {
	q := retentionQualification(t)
	now := time.Now().UTC().Truncate(time.Second)
	seeds := []retentionSeed{{id: "active-a", expires: now.Add(time.Hour)}, {id: "active-b", expires: now.Add(time.Hour)}}
	for i := 0; i < 600; i++ {
		seed := retentionSeed{id: fmt.Sprintf("eligible-%03d", i), expires: now.Add(-time.Second)}
		if i < 320 {
			seed.expires, seed.delivered = now.Add(time.Hour), true
		}
		seeds = append(seeds, seed)
	}
	retentionSeedMessages(t, q, seeds)
	before := retentionAdmissionSnapshot(t, q.pool)
	dry, err := cleanup.PruneDuplexRelayMessages(t.Context(), q.pool, "relay-a", "domain-a", "1", now, true)
	if err != nil || !dry.DryRun || dry.WouldDelete != 256 || dry.Deleted != 0 || len(retentionMessageIDs(t, q.pool)) != 602 {
		t.Fatalf("dry-run changed data or counted more than next batch: %+v, %v", dry, err)
	}
	for batch, want := range []int64{256, 256, 88, 0} {
		result, err := cleanup.PruneDuplexRelayMessages(t.Context(), q.pool, "relay-a", "domain-a", "1", now, false)
		if err != nil || result.Deleted != want || result.DryRun {
			t.Fatalf("batch %d: got %+v, %v; want %d", batch, result, err, want)
		}
		if after := retentionAdmissionSnapshot(t, q.pool); after != before {
			t.Fatalf("batch %d changed immutable admission evidence", batch)
		}
	}
	if ids := strings.Join(retentionMessageIDs(t, q.pool), ","); ids != "active-a,active-b" {
		t.Fatalf("active undelivered messages lost: %s", ids)
	}
}

func TestRetentionExactExpiryAndHistoryBoundary(t *testing.T) {
	q := retentionQualification(t)
	now := time.Now().UTC().Truncate(time.Second)
	retentionSeedMessages(t, q, []retentionSeed{
		{id: "before", expires: now.Add(-time.Second)}, {id: "at", expires: now},
		{id: "after", expires: now.Add(time.Second)}, {id: "delivered", expires: now.Add(time.Hour), delivered: true},
		{id: "different-history", history: strings.Repeat("C", 43), expires: now.Add(-time.Second)},
	})
	// A legacy payload without an admission must not be mistaken for evidence
	// belonging to the currently continuous duplex history.
	tx := retentionTx(t, q, "legacy-no-admission")
	id, err := postgres.NewUUIDv7Like(now)
	if err != nil {
		t.Fatal(err)
	}
	if err = repository.NewRelayRepository(tx).StoreMessage(t.Context(), repository.RelayMessage{ID: postgres.UUIDString(id), DomainID: "domain-a", MessageID: "legacy-no-admission", SenderDeviceID: q.a.Identity.DeviceID, RecipientDeviceID: q.b.Identity.DeviceID, SessionID: "legacy-session", PayloadType: "test", RouteMetadata: []byte(`{}`), EnvelopeRaw: []byte(`{}`), EnvelopeCanonical: []byte(`{}`), QueuedAt: now.Add(-time.Minute), ExpiresAt: now}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	before := retentionAdmissionSnapshot(t, q.pool)
	result, err := cleanup.PruneDuplexRelayMessages(t.Context(), q.pool, "relay-a", "domain-a", "1", now, false)
	if err != nil || result.Deleted != 3 {
		t.Fatal(result, err)
	}
	if ids := strings.Join(retentionMessageIDs(t, q.pool), ","); ids != "after,different-history,legacy-no-admission" {
		t.Fatalf("expiry/current-history boundary crossed: %s", ids)
	}
	if before != retentionAdmissionSnapshot(t, q.pool) {
		t.Fatal("cleanup changed evidence")
	}
	result, err = cleanup.PruneDuplexRelayMessages(t.Context(), q.pool, "relay-a", "domain-a", "1", now.Add(time.Second), false)
	if err != nil || result.Deleted != 1 {
		t.Fatalf("next exact TTL boundary did not make progress: %+v %v", result, err)
	}
}

func TestRetentionSkipsLockedPayloadAndMakesProgress(t *testing.T) {
	q := retentionQualification(t)
	now := time.Now().UTC().Truncate(time.Second)
	retentionSeedMessages(t, q, []retentionSeed{{id: "locked", expires: now}, {id: "unlocked", expires: now}})
	before := retentionAdmissionSnapshot(t, q.pool)
	tx, err := q.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var locked string
	if err = tx.QueryRow(t.Context(), `SELECT message_id FROM iscp_relay.messages WHERE message_id='locked' FOR UPDATE`).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	result, err := cleanup.PruneDuplexRelayMessages(ctx, q.pool, "relay-a", "domain-a", "1", now, false)
	if err != nil || result.Deleted != 1 {
		t.Fatalf("locked row blocked unrelated cleanup: %+v, %v", result, err)
	}
	if ids := strings.Join(retentionMessageIDs(t, q.pool), ","); ids != "locked" {
		t.Fatal(ids)
	}
	if err = tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	result, err = cleanup.PruneDuplexRelayMessages(t.Context(), q.pool, "relay-a", "domain-a", "1", now, false)
	if err != nil || result.Deleted != 1 || before != retentionAdmissionSnapshot(t, q.pool) {
		t.Fatal(result, err, "locked row/evidence did not survive")
	}
}

func TestRetentionExpiryOnlyAPIRemainsBounded(t *testing.T) {
	q := retentionQualification(t)
	now := time.Now().UTC().Truncate(time.Second)
	seeds := []retentionSeed{{id: "delivered-still-live", expires: now.Add(time.Hour), delivered: true}}
	for i := 0; i < 520; i++ {
		seeds = append(seeds, retentionSeed{id: fmt.Sprintf("expired-%03d", i), expires: now})
	}
	retentionSeedMessages(t, q, seeds)
	before := retentionAdmissionSnapshot(t, q.pool)
	dry, err := cleanup.ExpiredDuplexRelayMessages(t.Context(), q.pool, "relay-a", "domain-a", "1", now, true)
	if err != nil || !dry.DryRun || dry.WouldDelete != 256 || len(retentionMessageIDs(t, q.pool)) != 521 {
		t.Fatal(dry, err)
	}
	for _, want := range []int64{256, 256, 8, 0} {
		result, err := cleanup.ExpiredDuplexRelayMessages(t.Context(), q.pool, "relay-a", "domain-a", "1", now, false)
		if err != nil || result.Deleted != want {
			t.Fatal(result, err)
		}
	}
	if ids := strings.Join(retentionMessageIDs(t, q.pool), ","); ids != "delivered-still-live" || before != retentionAdmissionSnapshot(t, q.pool) {
		t.Fatal("expiry-only compatibility path deleted a live payload or evidence", ids)
	}
}

func TestRetentionWrongWriterAndUnavailableHistoryCannotDelete(t *testing.T) {
	for _, test := range []struct{ name, sql, scope, epoch string }{
		{name: "old-epoch", scope: "relay-a", epoch: "2"},
		{name: "wrong-scope", scope: "wrong-relay", epoch: "1"},
		{name: "disabled", sql: `UPDATE iscp_relay.writer_scopes SET writes_enabled=false`, scope: "relay-a", epoch: "1"},
		{name: "wrong-role", sql: `UPDATE iscp_relay.writer_scopes SET writer_role='not_current_writer'`, scope: "relay-a", epoch: "1"},
		{name: "incomplete", sql: `UPDATE iscp_relay.domain_authority SET history_state='incomplete'`, scope: "relay-a", epoch: "1"},
		{name: "closed", sql: `UPDATE iscp_relay.domain_authority SET history_state='closed'`, scope: "relay-a", epoch: "1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			q := retentionQualification(t)
			now := time.Now().UTC().Truncate(time.Second)
			retentionSeedMessages(t, q, []retentionSeed{{id: "keep-evidence-and-payload", expires: now}})
			before := retentionAdmissionSnapshot(t, q.pool)
			if test.sql != "" {
				if _, err := q.pool.Exec(t.Context(), test.sql); err != nil {
					t.Fatal(err)
				}
			}
			for _, dry := range []bool{true, false} {
				if _, err := cleanup.PruneDuplexRelayMessages(t.Context(), q.pool, test.scope, "domain-a", test.epoch, now, dry); err == nil {
					t.Fatal("unauthorized cleanup succeeded")
				}
			}
			if len(retentionMessageIDs(t, q.pool)) != 1 || before != retentionAdmissionSnapshot(t, q.pool) {
				t.Fatal("rejected cleanup changed stored data")
			}
		})
	}
}

func retentionWireQuery(t *testing.T, p *duplexTestPeer, original retentionOriginal, request string) duplex.Frame {
	t.Helper()
	sub := original.sub
	p.write(t, duplex.Frame{V: 1, Kind: "submit.query", ConnectionID: p.ready.ConnectionID, OwnerGeneration: p.ready.OwnerGeneration, RequestID: request, HistoryID: sub.HistoryID, MessageID: sub.MessageID, EnvelopeDigest: sub.EnvelopeDigest, NotAfter: sub.NotAfter})
	got := p.read(t)
	a, _ := json.Marshal(original.receipt)
	b, _ := json.Marshal(got.Receipt)
	if got.Kind != "submit.status" || got.State != "expired" || !bytes.Equal(a, b) {
		t.Fatalf("expired original key lost its signed receipt: %+v", got)
	}
	return got
}

func TestRetentionExpiredOriginalQueryAndConflictNeverReadmit(t *testing.T) {
	q := retentionQualification(t)
	now := time.Now().UTC().Truncate(time.Second)
	original := retentionSeedMessages(t, q, []retentionSeed{{id: "original-key", expires: now.Add(-time.Second)}})["original-key"]
	before := retentionAdmissionSnapshot(t, q.pool)
	result, err := cleanup.PruneDuplexRelayMessages(t.Context(), q.pool, "relay-a", "domain-a", "1", now, false)
	if err != nil || result.Deleted != 1 {
		t.Fatal(result, err)
	}
	p := connectDuplexTest(t, q.http.URL, q.a, q.token)
	retentionWireQuery(t, p, original, "2")
	sub := original.sub
	f := duplex.Frame{V: 1, Kind: "submit", ConnectionID: p.ready.ConnectionID, OwnerGeneration: p.ready.OwnerGeneration, RequestID: "3", HistoryID: sub.HistoryID, MessageID: sub.MessageID, EnvelopeDigest: sub.EnvelopeDigest, NotAfter: sub.NotAfter, Envelope: sub.Envelope}
	p.write(t, f)
	got := p.read(t)
	a, _ := json.Marshal(original.receipt)
	b, _ := json.Marshal(got.Receipt)
	if got.Kind != "accepted" || !bytes.Equal(a, b) {
		t.Fatal("same original resubmit changed its receipt", got)
	}
	conflict := qualificationFrame(p, qualificationEnvelope(q.a.Identity.DeviceID, q.b.Identity.DeviceID, sub.MessageID))
	conflict.RequestID = "4"
	p.write(t, conflict)
	if got = p.read(t); got.Kind != "rejected" || got.Code != "message_conflict" {
		t.Fatal("new intent reused retained original key", got)
	}
	retentionWireQuery(t, p, original, "5")
	if len(retentionMessageIDs(t, q.pool)) != 0 || before != retentionAdmissionSnapshot(t, q.pool) {
		t.Fatal("expired receipt query/resubmit/conflict recreated payload or admission")
	}
}

// Start from the real version-6 DDL, not an ALTER-added approximation of its
// removed column. receiveDatabase owns this disposable database and its cleanup.
func retentionVersionSixQualification(t *testing.T) duplexQualification {
	t.Helper()
	pool := receiveDatabase(t)
	if _, err := pool.Exec(t.Context(), `DROP SCHEMA iscp_relay CASCADE; DROP SCHEMA iscp_trust CASCADE`); err != nil {
		t.Fatal(err)
	}
	migrations, err := postgres.EmbeddedMigrations()
	if err != nil {
		t.Fatal(err)
	}
	var old []postgres.Migration
	for _, migration := range migrations {
		if migration.Name < "0007_" {
			old = append(old, migration)
		}
	}
	if len(old) != 6 {
		t.Fatalf("expected original six migrations, got %d", len(old))
	}
	if err = postgres.ApplyMigrations(t.Context(), pool, old); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err = os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{SignerFile: filepath.Join(directory, "relay-signer.json"), DomainID: "domain-a", RelayID: "relay-a", BaseURL: "http://relay.test", AllowedOrigins: []string{"http://relay.test"}, DB: pool, AdminToken: "admin-test-token", ProfileGate: config.DefaultGate(config.ProfileProduction)})
	if err != nil {
		t.Fatal(err)
	}
	s.maintenanceCancel()
	s.duplexWG.Wait()
	h := httptest.NewServer(s.Handler())
	t.Cleanup(func() { s.Close(); h.Close() })
	provider := crypto.NewProvider()
	a, err := identity.NewDevice(provider, "domain-a", "qualification-a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.NewDevice(provider, "domain-a", "qualification-b", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	access := bindDeviceForTest(t, s.Handler(), provider, a, "relay-a", randomToken())
	bindDeviceForTest(t, s.Handler(), provider, b, "relay-a", randomToken())
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err = authority.BootstrapEmpty(t.Context(), tx, "relay-a", "domain-a", strings.Repeat("A", 43), strings.Repeat("B", 43), true); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return duplexQualification{pool, s, h, a, b, access.Token}
}

func retentionInsertVersionSixAdmission(t *testing.T, q duplexQualification, now time.Time) retentionOriginal {
	t.Helper()
	env := qualificationEnvelope(q.a.Identity.DeviceID, q.b.Identity.DeviceID, "version-six-original")
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := duplex.Digest(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	expires, accepted := now.Add(-time.Second), now.Add(-30*time.Second)
	sub := duplex.Submission{MessageID: env.MessageID, EnvelopeDigest: digest, HistoryID: strings.Repeat("A", 43), NotAfter: duplex.Timestamp(expires), Envelope: raw}
	receipt, err := duplex.SignReceipt(crypto.NewProvider(), q.server.signer, duplex.Receipt{ReceiptID: crypto.Base64URL(crypto.RandomBytes(16)), RelayID: "relay-a", DomainID: "domain-a", HistoryID: sub.HistoryID, MessageID: sub.MessageID, SenderDeviceID: env.SenderDeviceID, RecipientDeviceID: env.RecipientDeviceID, EnvelopeDigest: digest, NotAfter: sub.NotAfter, AcceptedAt: duplex.Timestamp(accepted), ExpiresAt: duplex.Timestamp(expires)})
	if err != nil {
		t.Fatal(err)
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptCanonical, err := canonical.Marshal(receiptRaw)
	if err != nil {
		t.Fatal(err)
	}
	tx := retentionTx(t, q, sub.MessageID)
	// This is the actual previous writer shape, including both receipt columns.
	if _, err = tx.Exec(t.Context(), `INSERT INTO iscp_relay.admissions(domain_id,message_id,scope_id,history_id,sender_device_id,recipient_device_id,envelope_digest,not_after,accepted_at,expires_at,receipt_raw,receipt_canonical) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, "domain-a", sub.MessageID, "relay-a", sub.HistoryID, env.SenderDeviceID, env.RecipientDeviceID, digest, expires, accepted, expires, receiptRaw, receiptCanonical); err != nil {
		t.Fatal(err)
	}
	id, err := postgres.NewUUIDv7Like(accepted)
	if err != nil {
		t.Fatal(err)
	}
	route, err := json.Marshal(env.Route)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := canonical.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = repository.NewRelayRepository(tx).StoreMessage(t.Context(), repository.RelayMessage{ID: postgres.UUIDString(id), DomainID: "domain-a", MessageID: sub.MessageID, SenderDeviceID: env.SenderDeviceID, RecipientDeviceID: env.RecipientDeviceID, SessionID: env.SessionID, PayloadType: env.PayloadType, RouteMetadata: route, EnvelopeRaw: raw, EnvelopeCanonical: canon, Priority: env.Route.Priority, QueuedAt: accepted, ExpiresAt: expires}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return retentionOriginal{sub, receipt}
}

func TestRetentionMigrationSixToSevenPreservesOriginalWireEvidence(t *testing.T) {
	q := retentionVersionSixQualification(t)
	now := time.Now().UTC().Truncate(time.Second)
	original := retentionInsertVersionSixAdmission(t, q, now)
	before := retentionAdmissionSnapshot(t, q.pool)
	var originalRaw, originalCanonical []byte
	if err := q.pool.QueryRow(t.Context(), `SELECT receipt_raw,receipt_canonical FROM iscp_relay.admissions WHERE message_id=$1`, original.sub.MessageID).Scan(&originalRaw, &originalCanonical); err != nil {
		t.Fatal(err)
	}
	canonicalRaw, err := canonical.Marshal(originalRaw)
	if err != nil || !bytes.Equal(originalCanonical, canonicalRaw) {
		t.Fatal("version-six fixture did not store its genuine duplicate receipt", err)
	}
	var oldIndex string
	if err = q.pool.QueryRow(t.Context(), `SELECT indexdef FROM pg_indexes WHERE schemaname='iscp_relay' AND indexname='admissions_pkey'`).Scan(&oldIndex); err != nil {
		t.Fatal(err)
	}
	p := connectDuplexTest(t, q.http.URL, q.a, q.token)
	retentionWireQuery(t, p, original, "2")
	migrations, err := postgres.EmbeddedMigrations()
	if err != nil {
		t.Fatal(err)
	}
	var next []postgres.Migration
	for _, migration := range migrations {
		if migration.Name == "0007_relay_retention.sql" {
			next = append(next, migration)
		}
	}
	if len(next) != 1 {
		t.Fatal("retention migration 7 not present")
	}
	if err = postgres.ApplyMigrations(t.Context(), q.pool, next); err != nil {
		t.Fatal(err)
	}
	// Reapplication must not change the retained bytes or drop legacy receipt
	// compatibility. The fresh database path is covered by the other fixtures.
	if err = postgres.ApplyMigrations(t.Context(), q.pool, next); err != nil {
		t.Fatal(err)
	}
	// Exercise the one-time deployment rewrite as well as logical column removal.
	if _, err = q.pool.Exec(t.Context(), `VACUUM (FULL, ANALYZE) iscp_relay.admissions`); err != nil {
		t.Fatal(err)
	}
	var removed, legacyKept, version int
	if err = q.pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns WHERE table_schema='iscp_relay' AND table_name='admissions' AND column_name='receipt_canonical'`).Scan(&removed); err != nil {
		t.Fatal(err)
	}
	if err = q.pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns WHERE table_schema='iscp_relay' AND table_name='delivery_receipts' AND column_name='receipt_canonical'`).Scan(&legacyKept); err != nil {
		t.Fatal(err)
	}
	if err = q.pool.QueryRow(t.Context(), `SELECT max(version) FROM iscp_relay.schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	var retainedRaw []byte
	var retainedIndex string
	if err = q.pool.QueryRow(t.Context(), `SELECT receipt_raw FROM iscp_relay.admissions WHERE message_id=$1`, original.sub.MessageID).Scan(&retainedRaw); err != nil {
		t.Fatal(err)
	}
	if err = q.pool.QueryRow(t.Context(), `SELECT indexdef FROM pg_indexes WHERE schemaname='iscp_relay' AND indexname='admissions_pkey'`).Scan(&retainedIndex); err != nil {
		t.Fatal(err)
	}
	if removed != 0 || legacyKept != 1 || version != 7 || before != retentionAdmissionSnapshot(t, q.pool) || !bytes.Equal(originalRaw, retainedRaw) || oldIndex != retainedIndex {
		t.Fatal("migration changed retained evidence/index or legacy compatibility", removed, legacyKept, version)
	}
	retentionWireQuery(t, p, original, "3")
	var signed duplex.Receipt
	if err = json.Unmarshal(retainedRaw, &signed); err != nil {
		t.Fatal(err)
	}
	if err = duplex.VerifyReceipt(signed, q.server.signer.Identity, original.sub, "relay-a", "domain-a", q.a.Identity.DeviceID, q.b.Identity.DeviceID); err != nil {
		t.Fatal("original retained signature no longer verifies", err)
	}
	result, err := cleanup.PruneDuplexRelayMessages(t.Context(), q.pool, "relay-a", "domain-a", "1", now, false)
	if err != nil || result.Deleted != 1 {
		t.Fatal(result, err)
	}
	retentionWireQuery(t, p, original, "4")
	conflict := qualificationFrame(p, qualificationEnvelope(q.a.Identity.DeviceID, q.b.Identity.DeviceID, original.sub.MessageID))
	conflict.RequestID = "5"
	p.write(t, conflict)
	if got := p.read(t); got.Kind != "rejected" || got.Code != "message_conflict" {
		t.Fatal("migrated key allowed new intent", got)
	}
	if len(retentionMessageIDs(t, q.pool)) != 0 || before != retentionAdmissionSnapshot(t, q.pool) {
		t.Fatal("migrated query/conflict lost tombstone or recreated payload")
	}
}

func retentionWait(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("retention condition did not complete within its bounded deadline")
}

func retentionMetrics(t *testing.T, s *Server, want map[string]uint64) {
	t.Helper()
	w := httptest.NewRecorder()
	s.metrics(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for metric, value := range want {
		if !strings.Contains(w.Body.String(), fmt.Sprintf("iscp_relay_payload_cleanup_%s %d\n", metric, value)) {
			t.Fatalf("metric %s=%d missing: %s", metric, value, w.Body.String())
		}
	}
}

func TestRetentionStartupSweepMetricsAndCloseCancellation(t *testing.T) {
	t.Run("startup-before-first-tick", func(t *testing.T) {
		q := retentionQualification(t)
		now := time.Now().UTC().Truncate(time.Second)
		retentionSeedMessages(t, q, []retentionSeed{{id: "startup-delivered", expires: now.Add(time.Hour), delivered: true}, {id: "startup-active", expires: now.Add(time.Hour)}})
		before := retentionAdmissionSnapshot(t, q.pool)
		s, err := New(q.server.cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		retentionWait(t, 5*time.Second, func() bool { return s.payloadCleanup.batches.Load() == 1 && s.payloadCleanup.lastSuccess.Load() > 0 })
		retentionMetrics(t, s, map[string]uint64{"runs_total": 1, "batches_total": 1, "deleted_total": 1, "errors_total": 0})
		if s.payloadCleanup.lastSuccess.Load() == 0 || strings.Join(retentionMessageIDs(t, q.pool), ",") != "startup-active" || before != retentionAdmissionSnapshot(t, q.pool) {
			t.Fatal("startup pass lost evidence, active payload, or success timestamp")
		}
	})
	t.Run("close-cancels-blocked-startup", func(t *testing.T) {
		q := retentionQualification(t)
		now := time.Now().UTC().Truncate(time.Second)
		retentionSeedMessages(t, q, []retentionSeed{{id: "shutdown-keeps-payload", expires: now}})
		tx, err := q.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(t.Context(), `SELECT scope_id FROM iscp_relay.writer_scopes WHERE scope_id='relay-a' FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		s, err := New(q.server.cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		retentionWait(t, 2*time.Second, func() bool {
			var n int
			err := q.pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%writer_epoch::text%'`).Scan(&n)
			return err == nil && n > 0
		})
		done := make(chan struct{})
		go func() { s.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Close did not cancel a blocked cleanup query")
		}
		retentionMetrics(t, s, map[string]uint64{"runs_total": 1, "batches_total": 0, "deleted_total": 0, "errors_total": 0})
		if len(retentionMessageIDs(t, q.pool)) != 1 {
			t.Fatal("shutdown cancellation deleted uncommitted payload")
		}
	})
}

func TestRetentionLaterBatchDeadlineKeepsCommittedProgressAndMetrics(t *testing.T) {
	q := retentionQualification(t)
	now := time.Now().UTC().Truncate(time.Second)
	seeds := make([]retentionSeed, 300)
	for i := range seeds {
		seeds[i] = retentionSeed{id: fmt.Sprintf("deadline-%03d", i), expires: now}
	}
	retentionSeedMessages(t, q, seeds)
	before := retentionAdmissionSnapshot(t, q.pool)
	firstCommitted, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(resume) })
	var releases atomic.Uint64
	cfg := q.pool.Config()
	cfg.MaxConns = 1
	// The test-only pool hook observes Commit's release; it does not modify
	// production. One connection prevents the next batch from racing past the
	// exclusive authority lock we acquire after the first real commit.
	cfg.AfterRelease = func(*pgx.Conn) bool {
		if releases.Add(1) == 1 {
			close(firstCommitted)
			<-resume
		}
		return true
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		once.Do(func() { close(resume) })
		pool.Close()
	}()
	s := &Server{cfg: Config{DB: pool, RelayID: "relay-a", DomainID: "domain-a"}, writerEpoch: "1"}
	done := make(chan struct{})
	go func() { s.cleanupPayloads(context.Background()); close(done) }()
	select {
	case <-firstCommitted:
	case <-time.After(2 * time.Second):
		t.Fatal("first cleanup batch never committed")
	}
	lock, err := q.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(context.Background())
	if _, err = lock.Exec(t.Context(), `SELECT scope_id FROM iscp_relay.writer_scopes WHERE scope_id='relay-a' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	once.Do(func() { close(resume) })
	select {
	case <-done:
	case <-time.After(payloadCleanupBudget + time.Second):
		t.Fatal("later blocked batch exceeded the production pass budget")
	}
	retentionMetrics(t, s, map[string]uint64{"runs_total": 1, "batches_total": 1, "deleted_total": 256, "errors_total": 1})
	if len(retentionMessageIDs(t, q.pool)) != 44 || before != retentionAdmissionSnapshot(t, q.pool) || s.payloadCleanup.lastSuccess.Load() == 0 {
		t.Fatal("later deadline rolled back the first batch or its retained evidence")
	}
	if err = lock.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	s.cleanupPayloads(t.Context())
	retentionMetrics(t, s, map[string]uint64{"runs_total": 2, "batches_total": 2, "deleted_total": 300, "errors_total": 1})
	if len(retentionMessageIDs(t, q.pool)) != 0 || before != retentionAdmissionSnapshot(t, q.pool) {
		t.Fatal("retry did not finish the remaining committed work")
	}
}

func TestRetentionLargeTOASTBacklogStaysWithinEachBatchBudget(t *testing.T) {
	q := retentionQualification(t)
	now := time.Now().UTC().Truncate(time.Second)
	seeds := make([]retentionSeed, 530)
	for i := range seeds {
		// Random ciphertext does not compress to an unrealistically tiny TOAST
		// value. Each actual envelope carries about 64 KiB of encrypted content.
		seeds[i] = retentionSeed{id: fmt.Sprintf("toast-%03d", i), expires: now, ciphertextBytes: 48 << 10}
	}
	started := time.Now()
	retentionSeedMessages(t, q, seeds)
	t.Logf("seeded %d real signed admissions in %s", len(seeds), time.Since(started))
	before := retentionAdmissionSnapshot(t, q.pool)
	var payloadBytes, toastBytes int64
	if err := q.pool.QueryRow(t.Context(), `SELECT sum(octet_length(envelope_raw)+octet_length(envelope_canonical)) FROM iscp_relay.messages`).Scan(&payloadBytes); err != nil {
		t.Fatal(err)
	}
	if err := q.pool.QueryRow(t.Context(), `SELECT pg_total_relation_size(reltoastrelid) FROM pg_class WHERE oid='iscp_relay.messages'::regclass`).Scan(&toastBytes); err != nil {
		t.Fatal(err)
	}
	if payloadBytes < 64<<20 || toastBytes < 32<<20 {
		t.Fatalf("fixture did not exercise a real large TOAST backlog: payload=%d toast=%d", payloadBytes, toastBytes)
	}
	for batch, want := range []int64{256, 256, 18} {
		ctx, cancel := context.WithTimeout(t.Context(), payloadCleanupBudget)
		started = time.Now()
		result, err := cleanup.PruneDuplexRelayMessages(ctx, q.pool, "relay-a", "domain-a", "1", now, false)
		elapsed := time.Since(started)
		cancel()
		t.Logf("TOAST batch %d: deleted=%d elapsed=%s original_payload_bytes=%d original_toast_bytes=%d", batch+1, result.Deleted, elapsed, payloadBytes, toastBytes)
		if err != nil || result.Deleted != want || elapsed >= payloadCleanupBudget {
			t.Fatalf("large batch exceeded production limit: %+v %v %s", result, err, elapsed)
		}
	}
	if len(retentionMessageIDs(t, q.pool)) != 0 || before != retentionAdmissionSnapshot(t, q.pool) {
		t.Fatal("large cleanup lost evidence or left eligible payloads")
	}
}

func TestRetentionUncommittedDeliveryRollbackKeepsLivePayload(t *testing.T) {
	q := retentionQualification(t)
	now := time.Now().UTC().Truncate(time.Second)
	retentionSeedMessages(t, q, []retentionSeed{{id: "delivery-pending", expires: now.Add(time.Hour)}, {id: "delivery-complete", expires: now.Add(time.Hour), delivered: true}})
	before := retentionAdmissionSnapshot(t, q.pool)
	tx := retentionTx(t, q, "delivery-pending")
	if err := repository.NewRelayRepository(tx).MarkMessageDelivered(t.Context(), "domain-a", "delivery-pending", now); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	result, err := cleanup.PruneDuplexRelayMessages(ctx, q.pool, "relay-a", "domain-a", "1", now, false)
	cancel()
	if err != nil || result.Deleted != 1 {
		t.Fatal("uncommitted delivery blocked independent cleanup", result, err)
	}
	if err = tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	result, err = cleanup.PruneDuplexRelayMessages(t.Context(), q.pool, "relay-a", "domain-a", "1", now, false)
	if err != nil || result.Deleted != 0 || strings.Join(retentionMessageIDs(t, q.pool), ",") != "delivery-pending" {
		t.Fatal("rolled-back delivery was prematurely pruned", result, err)
	}
	tx = retentionTx(t, q, "delivery-pending")
	if err = repository.NewRelayRepository(tx).MarkMessageDelivered(t.Context(), "domain-a", "delivery-pending", now); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	result, err = cleanup.PruneDuplexRelayMessages(t.Context(), q.pool, "relay-a", "domain-a", "1", now, false)
	if err != nil || result.Deleted != 1 || before != retentionAdmissionSnapshot(t, q.pool) {
		t.Fatal("committed delivery did not become safely reclaimable", result, err)
	}
}
