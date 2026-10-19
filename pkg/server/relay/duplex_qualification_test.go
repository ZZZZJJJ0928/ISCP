package iscprelayreference

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"github.com/Infinimesh-ai/ISCP/pkg/server/cleanup"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
)

type duplexQualification struct {
	pool   *pgxpool.Pool
	server *Server
	http   *httptest.Server
	a, b   identity.Device
	token  string
}

func newDuplexQualification(t *testing.T) duplexQualification {
	t.Helper()
	pool := receiveDatabase(t)
	s, err := New(Config{DomainID: "domain-a", RelayID: "relay-a", BaseURL: "http://relay.test", AllowedOrigins: []string{"http://relay.test"}, DB: pool, AdminToken: "admin-test-token", ProfileGate: config.DefaultGate(config.ProfileProduction)})
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(s.Handler())
	t.Cleanup(func() { s.Close(); h.Close() })
	p := crypto.NewProvider()
	a, _ := identity.NewDevice(p, "domain-a", "qualification-a", time.Now())
	b, _ := identity.NewDevice(p, "domain-a", "qualification-b", time.Now())
	ca := bindDeviceForTest(t, s.Handler(), p, a, "relay-a", randomToken())
	bindDeviceForTest(t, s.Handler(), p, b, "relay-a", randomToken())
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
	return duplexQualification{pool, s, h, a, b, ca.Token}
}
func qualificationEnvelope(sender, recipient, message string) envelope.SecureEnvelope {
	return envelope.SecureEnvelope{Type: envelope.TypeSecureEnvelope, DomainID: "domain-a", MessageID: message, SessionID: "qualification-session", SenderDeviceID: sender, RecipientDeviceID: recipient, Sequence: 1, Nonce: crypto.Base64URL(crypto.RandomBytes(12)), PayloadType: "test", Route: envelope.Route{RelayID: "relay-a", TTLSeconds: 30, Priority: 5}, Ciphertext: strings.Repeat("A", 40)}
}
func qualificationFrame(p *duplexTestPeer, env envelope.SecureEnvelope) duplex.Frame {
	raw, _ := json.Marshal(env)
	digest, _ := duplex.Digest(json.RawMessage(raw))
	return duplex.Frame{V: 1, Kind: "submit", ConnectionID: p.ready.ConnectionID, OwnerGeneration: p.ready.OwnerGeneration, RequestID: "2", HistoryID: p.challenge.HistoryID, MessageID: env.MessageID, EnvelopeDigest: digest, NotAfter: duplex.Timestamp(time.Now().Add(29 * time.Second)), Envelope: raw}
}
func TestDuplexPublicRevocationUsesSharedAuthority(t *testing.T) {
	q := newDuplexQualification(t)
	peer := connectDuplexTest(t, q.http.URL, q.a, q.token)
	tx, err := q.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	_, err = authority.Lock(t.Context(), tx, authority.Request{ScopeID: "relay-a", DomainID: "domain-a", ExpectedWriterEpoch: "1", Devices: []authority.DeviceLock{{ID: q.a.Identity.DeviceID}}, Owners: []authority.DeviceLock{{ID: q.a.Identity.DeviceID}}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, q.http.URL+"/v2/relay/devices/revoke-access", strings.NewReader(`{"device_id":"qualification-a"}`))
		req.Header.Set("Authorization", "Bearer admin-test-token")
		resp, e := http.DefaultClient.Do(req)
		if e != nil {
			done <- 0
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	select {
	case status := <-done:
		t.Fatal("revoke bypassed active disclosure guard", status)
	case <-time.After(80 * time.Millisecond):
	}
	if err = tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case status := <-done:
		if status != 200 {
			t.Fatal(status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoke did not complete")
	}
	var state, revision string
	var live int
	if err = q.pool.QueryRow(t.Context(), `SELECT state,authorization_revision::text FROM iscp_relay.device_authority WHERE device_id=$1`, q.a.Identity.DeviceID).Scan(&state, &revision); err != nil {
		t.Fatal(err)
	}
	if err = q.pool.QueryRow(t.Context(), `SELECT count(*) FROM iscp_relay.access_tokens WHERE device_id=$1 AND revoked_at IS NULL`, q.a.Identity.DeviceID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if state != "revoked" || revision != "2" || live != 0 {
		t.Fatal(state, revision, live)
	}
	_ = peer.ws.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err = peer.ws.ReadMessage(); err == nil {
		t.Fatal("revoked owner remained writable")
	}
}
func TestDuplexWireExactByteLimits(t *testing.T) {
	q := newDuplexQualification(t)
	for _, kind := range []string{"envelope", "frame"} {
		for _, delta := range []int{-1, 0, 1} {
			t.Run(fmt.Sprintf("%s/%+d", kind, delta), func(t *testing.T) {
				p := connectDuplexTest(t, q.http.URL, q.a, q.token)
				env := qualificationEnvelope(q.a.Identity.DeviceID, q.b.Identity.DeviceID, fmt.Sprintf("%s-%d", kind, delta))
				if kind == "envelope" {
					raw, _ := json.Marshal(env)
					env.Ciphertext += strings.Repeat("A", duplex.MaxEnvelopeBytes+delta-len(raw))
				}
				f := qualificationFrame(p, env)
				raw, _ := json.Marshal(f)
				if kind == "frame" {
					raw = append(raw, bytes.Repeat([]byte(" "), duplex.MaxFrameBytes+delta-len(raw))...)
				}
				if kind == "envelope" && len(f.Envelope) != duplex.MaxEnvelopeBytes+delta {
					t.Fatal(len(f.Envelope))
				}
				if err := p.ws.WriteMessage(websocket.TextMessage, raw); err != nil {
					t.Fatal(err)
				}
				if delta <= 0 {
					if got := p.read(t); got.Kind != "accepted" {
						t.Fatal(got)
					}
				} else {
					_ = p.ws.SetReadDeadline(time.Now().Add(3 * time.Second))
					_, reply, err := p.ws.ReadMessage()
					if err == nil {
						f, e := duplex.Decode(reply)
						if e != nil || f.Kind != "closing" {
							t.Fatal("oversize accepted", string(reply), e)
						}
					}
				}
			})
		}
	}
}
func TestDuplexEightDayTombstoneAndMissingHistory(t *testing.T) {
	q := newDuplexQualification(t)
	now := time.Now().UTC().Truncate(time.Second)
	then := now.Add(-8 * 24 * time.Hour)
	env := qualificationEnvelope(q.a.Identity.DeviceID, q.b.Identity.DeviceID, "eight-day-original")
	raw, _ := json.Marshal(env)
	digest, _ := duplex.Digest(json.RawMessage(raw))
	sub := duplex.Submission{MessageID: env.MessageID, EnvelopeDigest: digest, HistoryID: strings.Repeat("A", 43), NotAfter: duplex.Timestamp(then.Add(29 * time.Second)), Envelope: raw}
	tx, err := q.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	_, err = authority.Lock(t.Context(), tx, authority.Request{ScopeID: "relay-a", DomainID: "domain-a", ExpectedWriterEpoch: "1", Devices: []authority.DeviceLock{{ID: q.a.Identity.DeviceID}}, Keys: []authority.Key{{Namespace: "message", ID: sub.MessageID}}, RequireContinuousHistory: true})
	if err != nil {
		t.Fatal(err)
	}
	original, err := repository.AdmitEnvelope(t.Context(), tx, "relay-a", "domain-a", q.a.Identity.DeviceID, "relay-a", sub, q.server.signer, then)
	if err != nil || original.State != "accepted" {
		t.Fatal(original, err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	result, err := cleanup.ExpiredDuplexRelayMessages(t.Context(), q.pool, "relay-a", "domain-a", "1", now, false)
	if err != nil || result.Deleted != 1 {
		t.Fatal(result, err)
	}
	p := connectDuplexTest(t, q.http.URL, q.a, q.token)
	query := duplex.Frame{V: 1, Kind: "submit.query", ConnectionID: p.ready.ConnectionID, OwnerGeneration: p.ready.OwnerGeneration, RequestID: "2", HistoryID: sub.HistoryID, MessageID: sub.MessageID, EnvelopeDigest: sub.EnvelopeDigest, NotAfter: sub.NotAfter}
	p.write(t, query)
	got := p.read(t)
	a, _ := json.Marshal(original.Receipt)
	b, _ := json.Marshal(got.Receipt)
	if got.State != "expired" || !bytes.Equal(a, b) {
		t.Fatal("original tombstone lost", got)
	}
	if _, err = q.pool.Exec(t.Context(), `UPDATE iscp_relay.domain_authority SET history_state='incomplete' WHERE scope_id='relay-a' AND domain_id='domain-a'`); err != nil {
		t.Fatal(err)
	}
	query.RequestID = "3"
	p.write(t, query)
	got = p.read(t)
	if got.State != "unknown" || got.Reason != "history_unavailable" {
		t.Fatal(got)
	}
	f := qualificationFrame(p, qualificationEnvelope(q.a.Identity.DeviceID, q.b.Identity.DeviceID, "must-not-admit"))
	f.RequestID = "4"
	p.write(t, f)
	got = p.read(t)
	if got.Kind != "rejected" || got.Code != "history_unavailable" {
		t.Fatal(got)
	}
	var count int
	if err = q.pool.QueryRow(t.Context(), `SELECT count(*) FROM iscp_relay.admissions WHERE message_id='must-not-admit'`).Scan(&count); err != nil || count != 0 {
		t.Fatal(count, err)
	}
	if _, err = cleanup.ExpiredDuplexRelayMessages(t.Context(), q.pool, "relay-a", "domain-a", "1", now, false); err == nil {
		t.Fatal("cleanup accepted incomplete history")
	}
}
