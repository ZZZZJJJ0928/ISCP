package iscprelayreference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	"github.com/Infinimesh-ai/ISCP/pkg/server/queue"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
)

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

func (f *receiveFixture) send(t *testing.T, id string, priority int) {
	t.Helper()
	env := map[string]any{"domain_id": "domain-a", "message_id": id, "sender_device_id": f.sender.Identity.DeviceID, "recipient_device_id": f.recipient.Identity.DeviceID, "route": map[string]any{"ttl_seconds": 60, "priority": priority}, "opaque_payload": "unchanged"}
	proof := accessProofHeaderValue(t, crypto.NewProvider(), f.sender, f.access.Token, http.MethodPost, "/v2/relay/envelopes", randomToken())
	postJSONWithHeaders(t, f.s.Handler(), "/v2/relay/envelopes", map[string]string{"Authorization": "Bearer " + f.access.Token, accessProofHeader: proof}, env, http.StatusAccepted, nil)
}

func (f *receiveFixture) connect(t *testing.T) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(f.h.URL, "http")+"/v2/relay/connect", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var challenge struct{ State, Challenge string }
	if err := c.ReadJSON(&challenge); err != nil {
		t.Fatal(err)
	}
	proof, err := f.recipient.CreateProof(crypto.NewProvider(), "relay-a", challenge.Challenge, randomToken(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WriteJSON(proof); err != nil {
		t.Fatal(err)
	}
	var ready struct{ State string }
	if err := c.ReadJSON(&ready); err != nil || ready.State != "ready" {
		t.Fatalf("ready: %s %v", ready.State, err)
	}
	return c
}

type receiveFrame struct {
	State     string
	MessageID string `json:"message_id"`
	Envelope  json.RawMessage
}

func frames(c *websocket.Conn) <-chan receiveFrame {
	out := make(chan receiveFrame, 32)
	go func() {
		defer close(out)
		for {
			var value receiveFrame
			if c.ReadJSON(&value) != nil {
				return
			}
			out <- value
		}
	}()
	return out
}

func nextFrame(t *testing.T, out <-chan receiveFrame) receiveFrame {
	t.Helper()
	select {
	case f, ok := <-out:
		if !ok {
			t.Fatal("receive closed")
		}
		return f
	case <-time.After(3 * time.Second):
		t.Fatal("receive timed out")
	}
	return receiveFrame{}
}

func TestReceiveStreamContinuous(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(fmt.Sprint("postgres=", persistent), func(t *testing.T) {
			f := newReceiveFixture(t, persistent)
			out := frames(f.connect(t))
			for _, id := range []string{"first", "later"} {
				start := time.Now()
				f.send(t, id, 1)
				value := nextFrame(t, out)
				if value.State != "message" || value.MessageID != id || !strings.Contains(string(value.Envelope), "unchanged") {
					t.Fatalf("frame %+v", value)
				}
				if time.Since(start) > 500*time.Millisecond {
					t.Fatal("enqueue wake waited for fallback polling")
				}
			}
			select {
			case value := <-out:
				t.Fatalf("idle connection produced frame or closed: %+v", value)
			case <-time.After(100 * time.Millisecond):
			}
			f.send(t, "after-idle", 1)
			if value := nextFrame(t, out); value.MessageID != "after-idle" {
				t.Fatalf("after idle %+v", value)
			}
		})
	}
}

// This opt-in check uses wall-clock time to cover the retired 55-second window.
// It is a local transport check, not real-model or UI latency acceptance.
func TestReceiveStreamPastFormerWindow(t *testing.T) {
	if os.Getenv("SC_RELAY_LONG_TEST") != "1" {
		t.Skip("set SC_RELAY_LONG_TEST=1 for the 56-second continuous receive check")
	}
	f := newReceiveFixture(t, false)
	c := f.connect(t)
	_ = c.SetReadDeadline(time.Now().Add(65 * time.Second))
	out := frames(c)
	f.send(t, "before-window", 1)
	if nextFrame(t, out).MessageID != "before-window" {
		t.Fatal("missing initial message")
	}
	select {
	case value := <-out:
		t.Fatalf("healthy connection rotated: %+v", value)
	case <-time.After(56 * time.Second):
	}
	f.send(t, "after-window", 1)
	if nextFrame(t, out).MessageID != "after-window" {
		t.Fatal("missing message past former window")
	}
}

func TestReceiveStreamReplacesOldSocketAndRevokes(t *testing.T) {
	f := newReceiveFixture(t, true)
	old := frames(f.connect(t))
	current := frames(f.connect(t))
	select {
	case _, ok := <-old:
		if ok {
			t.Fatal("old receiver retained")
		}
	case <-time.After(time.Second):
		t.Fatal("old receiver not closed")
	}
	f.send(t, "replacement", 1)
	if value := nextFrame(t, current); value.MessageID != "replacement" {
		t.Fatalf("frame %+v", value)
	}
	f.s.MarkRevoked(f.recipient.Identity.DeviceID)
	select {
	case _, ok := <-current:
		if ok {
			t.Fatal("revoked receiver delivered")
		}
	case <-time.After(time.Second):
		t.Fatal("revoked receiver not closed")
	}
	f.s.Close()
}

func TestReceiveStreamClosedPeerCannotClaim(t *testing.T) {
	f := newReceiveFixture(t, false)
	c := f.connect(t)
	f.s.receiveMu.Lock()
	slot := f.s.receivers[receiveKey("domain-a", f.recipient.Identity.DeviceID)]
	f.s.receiveMu.Unlock()
	_ = c.Close()
	select {
	case <-slot.closed:
	case <-time.After(time.Second):
		t.Fatal("closed peer did not leave its receive slot")
	}
	f.send(t, "unread", 1)
	if got := nextFrame(t, frames(f.connect(t))); got.MessageID != "unread" {
		t.Fatalf("recovery %+v", got)
	}
}

func TestReceiveClaimReleaseOrderingAndLeaseFence(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(fmt.Sprint("postgres=", persistent), func(t *testing.T) {
			f := newReceiveFixture(t, persistent)
			f.send(t, "low", 0)
			f.send(t, "high", 9)
			now := time.Now().UTC().Truncate(time.Microsecond)
			claim, err := f.s.claimOne(t.Context(), f.recipient.Identity, now)
			if err != nil || claim == nil || claim.message.MessageID != "high" {
				t.Fatalf("claim %v %v", claim, err)
			}
			if err := claim.finish(false); err != nil {
				t.Fatal(err)
			}
			second := now.Add(time.Millisecond)
			again, err := f.s.claimOne(t.Context(), f.recipient.Identity, second)
			if err != nil || again == nil || again.message.MessageID != "high" {
				t.Fatalf("recover %v %v", again, err)
			}
			if persistent {
				if err := claim.finish(false); err != nil {
					t.Fatal(err)
				}
				var lease time.Time
				if err := again.tx.QueryRow(t.Context(), `SELECT delivery_claimed_until FROM iscp_relay.messages WHERE message_id='high'`).Scan(&lease); err != nil || !lease.Equal(second.Add(time.Minute)) {
					t.Fatalf("stale release crossed lease: %v %v", lease, err)
				}
			}
			if err := again.finish(true); err != nil {
				t.Fatal(err)
			}
			last, err := f.s.claimOne(t.Context(), f.recipient.Identity, time.Now().UTC())
			if err != nil || last == nil || last.message.MessageID != "low" {
				t.Fatalf("order %v %v", last, err)
			}
			if err := last.finish(true); err != nil {
				t.Fatal(err)
			}
		})
	}
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

func TestReceiveStreamClientContinuousUntilCanceled(t *testing.T) {
	f := newReceiveFixture(t, false)
	bundle := iscpbridge.EnrollmentBundle{DomainID: "domain-a", DeviceID: f.recipient.Identity.DeviceID, RelayID: "relay-a", RelayBaseURL: f.h.URL, RelayWebSocketURL: "ws" + strings.TrimPrefix(f.h.URL, "http") + "/v2/relay/connect", Access: iscpbridge.RelayCredential{DomainID: "domain-a", DeviceID: f.recipient.Identity.DeviceID, Token: "unused-receive-access", ExpiresAt: time.Now().Add(time.Hour)}}
	c, err := iscpbridge.NewRelayClient(iscpbridge.ProfileLocalLab, "", bundle, f.recipient, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	ready := make(chan struct{})
	received := make(chan string, 2)
	finished := make(chan error, 1)
	go func() {
		finished <- c.RunOnceReady(ctx, func(_ context.Context, raw json.RawMessage) error {
			var v struct {
				ID string `json:"message_id"`
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				return err
			}
			received <- v.ID
			return nil
		}, func() { close(ready) })
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	f.send(t, "reference-client", 1)
	select {
	case id := <-received:
		if id != "reference-client" {
			t.Fatal(id)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled continuous receive: %v", err)
	}
}

func TestReceiveWriteFailureReturnsOriginalMessage(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(fmt.Sprint("postgres=", persistent), func(t *testing.T) {
			f := newReceiveFixture(t, persistent)
			conn := f.connect(t)
			_ = conn.Close()
			f.s.Close()
			f.send(t, "failed-write", 1)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			c := &receiveConnection{conn: conn, ctx: ctx, cancel: cancel}
			slot := &receiveSlot{}
			slot.owner.Store(c)
			if count, err := f.s.deliverNext(slot, c, f.recipient.Identity); err == nil || count != 0 {
				t.Fatalf("closed write %d %v", count, err)
			}
			claim, err := f.s.claimOne(t.Context(), f.recipient.Identity, time.Now().UTC())
			if err != nil || claim == nil {
				t.Fatalf("lost failed write: %v", err)
			}
			defer claim.finish(false)
			if claim.message.MessageID != "failed-write" {
				t.Fatal("original message changed")
			}
			if err = claim.finish(true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReceiveDatabaseDisconnectRollsBackClaim(t *testing.T) {
	f := newReceiveFixture(t, true)
	f.send(t, "process-disconnect", 1)
	claim, err := f.s.claimOne(t.Context(), f.recipient.Identity, time.Now().UTC())
	if err != nil || claim == nil {
		t.Fatalf("claim %v", err)
	}
	defer claim.finish(false)
	// A dead worker loses its DB connection before it can release anything.
	// PostgreSQL rolls the unfinished claim back; recovery needs no lease wait.
	if err = claim.tx.Conn().Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = claim.finish(false)
	recovered, err := f.s.claimOne(t.Context(), f.recipient.Identity, time.Now().UTC())
	if err != nil || recovered == nil {
		t.Fatalf("disconnect lost message %v", err)
	}
	defer recovered.finish(false)
	if recovered.message.MessageID != "process-disconnect" {
		t.Fatal("recovered wrong message")
	}
}

func TestReceiveCanceledContextCanRollbackClaim(t *testing.T) {
	f := newReceiveFixture(t, true)
	f.send(t, "canceled", 1)
	ctx, cancel := context.WithCancel(t.Context())
	claim, err := f.s.claimOne(ctx, f.recipient.Identity, time.Now().UTC())
	if err != nil || claim == nil {
		cancel()
		t.Fatalf("claim %v", err)
	}
	defer claim.finish(false)
	cancel()
	if err := claim.finish(false); err != nil {
		t.Fatal(err)
	}
	recovered, err := f.s.claimOne(t.Context(), f.recipient.Identity, time.Now().UTC())
	if err != nil || recovered == nil {
		t.Fatalf("cancellation lost message: %v", err)
	}
	defer recovered.finish(false)
	if recovered.message.MessageID != "canceled" {
		t.Fatal("recovered wrong message")
	}
}

func TestReceivePendingPongDoesNotDelayMessagesAndMissingPongCloses(t *testing.T) {
	f := newReceiveFixture(t, false)
	c := f.connect(t)
	c.SetPingHandler(func(string) error { return nil })
	out := frames(c)
	// A pending independent liveness probe must not hold up a healthy write.
	for i := 0; i < 8; i++ {
		id := fmt.Sprintf("pending-pong-%d", i)
		f.send(t, id, 1)
		if got := nextFrame(t, out); got.MessageID != id {
			t.Fatalf("delivery waited for Pong: %+v", got)
		}
	}
	select {
	case value, ok := <-out:
		if ok {
			t.Fatalf("unexpected frame: %+v", value)
		}
	case <-time.After(receiveIOTimeout + time.Second):
		t.Fatal("missing Pong did not close socket")
	}
	f.send(t, "after-liveness-loss", 1)
	if got := nextFrame(t, frames(f.connect(t))); got.MessageID != "after-liveness-loss" {
		t.Fatalf("new receiver missed pending message: %+v", got)
	}
}

func TestReceiveCloseWaitsForAllReceivers(t *testing.T) {
	f := newReceiveFixture(t, false)
	out := frames(f.connect(t))
	f.s.Close()
	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("shutdown delivered frame")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown left socket open")
	}
	f.s.receiveMu.Lock()
	remaining := len(f.s.receivers)
	f.s.receiveMu.Unlock()
	if remaining != 0 {
		t.Fatalf("shutdown left %d receive slots", remaining)
	}
	f.s.Close()
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

func TestReceiveDoesNotImposeRequestRateQuota(t *testing.T) {
	f := newReceiveFixture(t, false)
	out := frames(f.connect(t))
	for i := 0; i < 150; i++ {
		id := fmt.Sprintf("burst-%d", i)
		f.send(t, id, 1)
		if got := nextFrame(t, out); got.MessageID != id {
			t.Fatalf("burst order changed: %+v", got)
		}
	}
}
