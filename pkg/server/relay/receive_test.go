package iscprelayreference

import (
	"context"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	"github.com/Infinimesh-ai/ISCP/pkg/server/queue"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Memory queue reservation remains a repository unit invariant. Public transport
// no longer exposes the retired receive-only socket; duplex_test.go exercises
// the supported persistent transport, ownership, rollback and recovery paths.
type receiveFixture struct {
	s                 *Server
	h                 *httptest.Server
	sender, recipient identity.Device
	access            credential
}

func newReceiveFixture(t *testing.T, persistent bool) *receiveFixture {
	t.Helper()
	var pool *pgxpool.Pool
	if persistent {
		pool = receiveDatabase(t)
	}
	s, err := New(Config{DomainID: "domain-a", RelayID: "relay-a", BaseURL: "http://relay.test", WebSocketURL: "ws://relay.test/v2/relay/connect", AdminToken: "admin-test-token", ProfileGate: config.DefaultGate(config.ProfileProduction), AllowedOrigins: []string{"http://relay.test"}, DB: pool})
	if err != nil {
		t.Fatal(err)
	}
	f := &receiveFixture{s: s, h: httptest.NewServer(s.Handler())}
	t.Cleanup(func() { s.Close(); f.h.Close() })
	p := crypto.NewProvider()
	f.sender, err = identity.NewDevice(p, "domain-a", "sender-a", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	f.recipient, err = identity.NewDevice(p, "domain-a", "recipient-a", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	f.access = bindDeviceForTest(t, s.Handler(), p, f.sender, "relay-a", randomToken())
	bindDeviceForTest(t, s.Handler(), p, f.recipient, "relay-a", randomToken())
	return f
}
func TestMemoryReceiveReservationPreservesFailedMessage(t *testing.T) {
	f := newReceiveFixture(t, false)
	now := time.Now().UTC()
	msg := queue.Message{DomainID: "domain-a", RecipientDeviceID: f.recipient.Identity.DeviceID, MessageID: "large", Envelope: make([]byte, relayMaxQueuedBytes), ExpiresAt: now.Add(time.Minute)}
	if !f.s.enqueueMemory(msg, now) {
		t.Fatal("enqueue")
	}
	claimed, err := f.s.claimOne(t.Context(), f.recipient.Identity, now)
	if err != nil || claimed == nil {
		t.Fatal(err)
	}
	if f.s.enqueueMemory(queue.Message{Envelope: []byte("extra"), ExpiresAt: now.Add(time.Minute)}, now) {
		t.Fatal("claimed capacity was reused")
	}
	if err := claimed.finish(false); err != nil {
		t.Fatal(err)
	}
	if f.s.queue.UsedBytes() != relayMaxQueuedBytes || f.s.reservedBytes != 0 {
		t.Fatal("failed claim lost its reservation")
	}
}
func receiveDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SC_RELAY_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "relay_stream_" + strings.ToLower(strings.NewReplacer("-", "a", "_", "b").Replace(randomToken()[:16]))
	if _, err = admin.Exec(t.Context(), "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		admin.Close()
	})
	m, err := postgres.EmbeddedMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if err = postgres.ApplyMigrations(t.Context(), pool, m); err != nil {
		t.Fatal(err)
	}
	return pool
}
