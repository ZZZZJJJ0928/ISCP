package authority

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func authorityDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SC_RELAY_TEST_DSN")
	if dsn == "" {
		t.Skip("SC_RELAY_TEST_DSN required for isolated PostgreSQL fence test")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	name := fmt.Sprintf("duplex_authority_%d", time.Now().UnixNano())
	if _, e = admin.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.Database = name
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, `DROP DATABASE `+pgx.Identifier{name}.Sanitize()+` WITH (FORCE)`)
		admin.Close()
	})
	ms, e := postgres.EmbeddedMigrations()
	if e != nil {
		t.Fatal(e)
	}
	if e = postgres.ApplyMigrations(ctx, pool, ms); e != nil {
		t.Fatal(e)
	}
	return pool
}
func TestAuthorityTransactionFence(t *testing.T) {
	pool := authorityDatabase(t)
	ctx := context.Background()
	req := Request{ScopeID: "relay-test", DomainID: "domain-test", ExpectedWriterEpoch: "1", Devices: []DeviceLock{{ID: "device-test"}}, Owners: []DeviceLock{{ID: "device-test"}}, Keys: []Key{{Namespace: "message", ID: "message-test"}}, RequireContinuousHistory: true}
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Lock(ctx, tx, req); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("missing scope %v", e)
	}
	tx.Rollback(ctx)
	_, e = pool.Exec(ctx, `INSERT INTO iscp_relay.writer_scopes(scope_id,writer_role) VALUES('relay-test',current_user); INSERT INTO iscp_relay.domain_authority(scope_id,domain_id) VALUES('relay-test','domain-test'); INSERT INTO iscp_relay.device_authority VALUES('relay-test','domain-test','device-test',1,1,1,'active'); INSERT INTO iscp_relay.connection_owners(scope_id,domain_id,device_id) VALUES('relay-test','domain-test','device-test')`)
	if e != nil {
		t.Fatal(e)
	}
	tx, _ = pool.Begin(ctx)
	if _, e = Lock(ctx, tx, req); !errors.Is(e, ErrWriterFenced) {
		t.Fatalf("default inactive %v", e)
	}
	tx.Rollback(ctx)
	if _, e = pool.Exec(ctx, `UPDATE iscp_relay.writer_scopes SET writes_enabled=true`); e != nil {
		t.Fatal(e)
	}
	tx, _ = pool.Begin(ctx)
	if _, e = Lock(ctx, tx, req); !errors.Is(e, ErrHistoryUnavailable) {
		t.Fatalf("default unavailable history %v", e)
	}
	tx.Rollback(ctx)
	// Independent control recovery can reconcile while WSS intake is unavailable.
	control := req
	control.RequireContinuousHistory = false
	tx, _ = pool.Begin(ctx)
	if _, e = Lock(ctx, tx, control); e != nil {
		t.Fatal(e)
	}
	tx.Rollback(ctx)
	// Explicit synthetic empty-domain provenance, never inferred by migration.
	if _, e = pool.Exec(ctx, `UPDATE iscp_relay.domain_authority SET history_state='continuous',history_id=repeat('A',43),history_evidence_sha256=repeat('B',43),activated_at=now()`); e != nil {
		t.Fatal(e)
	}
	first, _ := pool.Begin(ctx)
	defer first.Rollback(ctx)
	if _, e = Lock(ctx, first, req); e != nil {
		t.Fatal(e)
	}
	independent := req
	independent.Keys = []Key{{Namespace: "message", ID: "other-message"}}
	second, _ := pool.Begin(ctx)
	if _, e = Lock(ctx, second, independent); e != nil {
		t.Fatalf("independent shared readers blocked: %v", e)
	}
	second.Rollback(ctx)
	// A query of the same key cannot cross a preceding admission transaction.
	waiter, _ := pool.Begin(ctx)
	waitCtx, cancel := context.WithTimeout(ctx, 75*time.Millisecond)
	_, e = Lock(waitCtx, waiter, req)
	cancel()
	if e == nil {
		t.Fatal("same key crossed unfinished transaction")
	}
	waiter.Rollback(ctx)
	// Revocation/rotation takes UPDATE on the same device row and cannot become
	// effective until the current reader has committed or rolled back.
	revoke := req
	revoke.Devices = []DeviceLock{{ID: "device-test", Exclusive: true}}
	revoke.Owners = []DeviceLock{{ID: "device-test", Exclusive: true}}
	writer, _ := pool.Begin(ctx)
	waitCtx, cancel = context.WithTimeout(ctx, 75*time.Millisecond)
	_, e = Lock(waitCtx, writer, revoke)
	cancel()
	if e == nil {
		t.Fatal("revocation crossed active authority reader")
	}
	writer.Rollback(ctx)
	first.Commit(ctx)
	writer, _ = pool.Begin(ctx)
	if _, e = Lock(ctx, writer, revoke); e != nil {
		t.Fatal(e)
	}
	if _, e = writer.Exec(ctx, `UPDATE iscp_relay.device_authority SET state='revoked',authorization_revision=2,state_version=2; UPDATE iscp_relay.connection_owners SET owner_generation=1,connection_id=NULL`); e != nil {
		t.Fatal(e)
	}
	if e = writer.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	tx, _ = pool.Begin(ctx)
	if _, e = Lock(ctx, tx, req); !errors.Is(e, ErrRevoked) {
		t.Fatalf("revoked still admitted %v", e)
	}
	tx.Rollback(ctx)
	if _, e = pool.Exec(ctx, `UPDATE iscp_relay.writer_scopes SET writer_epoch=2`); e != nil {
		t.Fatal(e)
	}
	tx, _ = pool.Begin(ctx)
	if _, e = Lock(ctx, tx, req); !errors.Is(e, ErrWriterFenced) {
		t.Fatalf("old writer epoch %v", e)
	}
	tx.Rollback(ctx)
}
func TestAuthorityLocksSortAndRejectInvalidIdentity(t *testing.T) {
	got, e := sortedLocks([]DeviceLock{{"z", false}, {"a", false}, {"z", true}})
	if e != nil || len(got) != 2 || got[0].ID != "a" || got[1].ID != "z" || !got[1].Exclusive {
		t.Fatal(got, e)
	}
	if _, e = sortedLocks([]DeviceLock{{"bad\x00id", false}}); e == nil {
		t.Fatal("invalid identifier")
	}
	for _, s := range []string{"", "0", "01", "18446744073709551616", "+1", "-1"} {
		if validCounter(s, false) {
			t.Fatal("invalid generation", s)
		}
	}
	if !validCounter("18446744073709551615", false) {
		t.Fatal("uint64 maximum")
	}
}
