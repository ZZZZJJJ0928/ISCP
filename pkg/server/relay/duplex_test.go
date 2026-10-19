package iscprelayreference

import (
	"context"
	"encoding/json"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type duplexTestPeer struct {
	ws               *websocket.Conn
	id               identity.Device
	token            string
	challenge, ready duplex.Frame
}

func (p *duplexTestPeer) read(t *testing.T) duplex.Frame {
	t.Helper()
	_ = p.ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, b, e := p.ws.ReadMessage()
	if e != nil {
		t.Fatal(e)
	}
	f, e := duplex.Decode(b)
	if e != nil {
		t.Fatal(e, string(b))
	}
	return f
}
func (p *duplexTestPeer) write(t *testing.T, f duplex.Frame) {
	t.Helper()
	b, e := duplex.Encode(f)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.ws.WriteMessage(websocket.TextMessage, b); e != nil {
		t.Fatal(e)
	}
}
func connectDuplexTest(t *testing.T, url string, id identity.Device, token string) *duplexTestPeer {
	t.Helper()
	d := websocket.Dialer{Subprotocols: []string{duplex.Protocol}}
	ws, _, e := d.Dial("ws"+strings.TrimPrefix(url, "http")+duplex.Path, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ws.Close() })
	p := &duplexTestPeer{ws: ws, id: id, token: token}
	p.challenge = p.read(t)
	h, e := duplex.AuthChallenge(p.challenge, "authenticate", "1", "0", token, id.Identity)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := id.CreateProof(crypto.NewProvider(), "relay-a", h, crypto.Base64URL(crypto.RandomBytes(16)), time.Now().UTC().Truncate(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	p.write(t, duplex.Frame{V: 1, Kind: "authenticate", ConnectionID: p.challenge.ConnectionID, RequestID: "1", ChallengeID: p.challenge.ChallengeID, AccessToken: token, Proof: &proof})
	p.ready = p.read(t)
	if p.ready.Kind != "ready" {
		t.Fatal(p.ready)
	}
	return p
}
func (p *duplexTestPeer) submit(t *testing.T, recipient, msg, request string) duplex.Frame {
	t.Helper()
	env := envelope.SecureEnvelope{Type: envelope.TypeSecureEnvelope, DomainID: "domain-a", MessageID: msg, SessionID: "session-test", SenderDeviceID: p.id.Identity.DeviceID, RecipientDeviceID: recipient, Sequence: 1, Nonce: crypto.Base64URL(crypto.RandomBytes(12)), PayloadType: "test", Route: envelope.Route{RelayID: "relay-a", TTLSeconds: 30, Priority: 5}, Ciphertext: crypto.Base64URL(crypto.RandomBytes(32))}
	raw, _ := json.Marshal(env)
	digest, _ := duplex.Digest(json.RawMessage(raw))
	f := duplex.Frame{V: 1, Kind: "submit", ConnectionID: p.ready.ConnectionID, OwnerGeneration: p.ready.OwnerGeneration, RequestID: request, HistoryID: p.challenge.HistoryID, MessageID: msg, EnvelopeDigest: digest, NotAfter: duplex.Timestamp(time.Now().Add(29 * time.Second)), Envelope: raw}
	p.write(t, f)
	return f
}
func TestDuplexPostgresBidirectionalAdmissionQueryAndFences(t *testing.T) {
	pool := receiveDatabase(t)
	s, e := New(Config{DomainID: "domain-a", RelayID: "relay-a", BaseURL: "http://relay.test", WebSocketURL: "ws://relay.test/v2/relay/duplex", AdminToken: "admin-test-token", ProfileGate: config.DefaultGate(config.ProfileProduction), AllowedOrigins: []string{"http://relay.test"}, DB: pool})
	if e != nil {
		t.Fatal(e)
	}
	h := httptest.NewServer(s.Handler())
	t.Cleanup(func() { s.Close(); h.Close() })
	p := crypto.NewProvider()
	a, _ := identity.NewDevice(p, "domain-a", "sender-a", time.Now())
	b, _ := identity.NewDevice(p, "domain-a", "recipient-a", time.Now())
	ca := bindDeviceForTest(t, s.Handler(), p, a, "relay-a", randomToken())
	cb := bindDeviceForTest(t, s.Handler(), p, b, "relay-a", randomToken())
	ctx := context.Background()
	// Explicit genesis fixture: the test itself created every identity and has
	// never admitted a message. Production migrations perform none of this.
	_, e = pool.Exec(ctx, `INSERT INTO iscp_relay.writer_scopes(scope_id,writer_role,writes_enabled) VALUES('relay-a',current_user,true); INSERT INTO iscp_relay.domain_authority(scope_id,domain_id,history_id,history_state,history_evidence_sha256,activated_at) VALUES('relay-a','domain-a',repeat('A',43),'continuous',repeat('B',43),now()); INSERT INTO iscp_relay.device_authority SELECT 'relay-a',domain_id,device_id,1,1,1,'active' FROM iscp_relay.devices; INSERT INTO iscp_relay.connection_owners(scope_id,domain_id,device_id) SELECT scope_id,domain_id,device_id FROM iscp_relay.device_authority`)
	if e != nil {
		t.Fatal(e)
	}
	one := connectDuplexTest(t, h.URL, a, ca.Token)
	two := connectDuplexTest(t, h.URL, b, cb.Token)
	first := one.submit(t, b.Identity.DeviceID, "message-one", "2")
	second := two.submit(t, a.Identity.DeviceID, "message-two", "2")
	receipts := map[string]*duplex.Receipt{}
	for _, peer := range []*duplexTestPeer{one, two} {
		seen := map[string]bool{}
		for len(seen) < 2 {
			f := peer.read(t)
			seen[f.Kind] = true
			if f.Kind == "accepted" {
				receipts[f.MessageID] = f.Receipt
			} else if f.Kind != "delivery" {
				t.Fatal(f)
			}
		}
	}
	for _, f := range []duplex.Frame{first, second} {
		if receipts[f.MessageID] == nil {
			t.Fatal("no durable receipt")
		}
	}
	query := first
	query.Kind = "submit.query"
	query.RequestID = "3"
	query.Envelope = nil
	one.write(t, query)
	status := one.read(t)
	if status.Kind != "submit.status" || status.State != "accepted" {
		t.Fatal(status)
	}
	before, _ := json.Marshal(receipts[first.MessageID])
	after, _ := json.Marshal(status.Receipt)
	if string(before) != string(after) {
		t.Fatal("lookup changed receipt")
	}
	first.RequestID = "4"
	one.write(t, first)
	duplicate := one.read(t)
	if duplicate.Kind != "accepted" {
		t.Fatal(duplicate)
	}
	after, _ = json.Marshal(duplicate.Receipt)
	if string(before) != string(after) {
		t.Fatal("duplicate changed original receipt")
	}
	conflict := first
	conflict.RequestID = "5"
	conflict.NotAfter = duplex.Timestamp(duplex.Time(first.NotAfter).Add(time.Second))
	one.write(t, conflict)
	if rejected := one.read(t); rejected.Kind != "rejected" || rejected.Code != "message_conflict" {
		t.Fatal(rejected)
	}
	// Guards reject the historical overwrite even using the service DB account.
	if _, e = pool.Exec(ctx, `UPDATE iscp_relay.messages SET envelope_raw='corrupt' WHERE message_id='message-one'`); e == nil {
		t.Fatal("unmarked old writer accepted")
	}
	for _, path := range []string{"/v2/relay/envelopes", "/v2/relay/connect"} {
		res, e := http.Get(h.URL + path)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != 410 {
			t.Fatal(path, res.StatusCode)
		}
	}
	res, e := http.Get(h.URL + duplex.Path)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 426 {
		t.Fatal(res.StatusCode)
	}
	replacement := connectDuplexTest(t, h.URL, a, ca.Token)
	if replacement.ready.OwnerGeneration == one.ready.OwnerGeneration {
		t.Fatal("generation not advanced")
	}
	query.ConnectionID = replacement.ready.ConnectionID
	query.OwnerGeneration = replacement.ready.OwnerGeneration
	query.RequestID = "2"
	replacement.write(t, query)
	if got := replacement.read(t); got.State != "accepted" {
		t.Fatal(got)
	}
}
