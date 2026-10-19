package iscprelayreference

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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
	_, e = pool.Exec(ctx, `INSERT INTO iscp_relay.writer_scopes(scope_id,writer_role,writes_enabled) VALUES('relay-a',current_user,true); INSERT INTO iscp_relay.domain_authority(scope_id,domain_id,history_id,history_state,history_evidence_sha256,activated_at) VALUES('relay-a','domain-a',repeat('A',43),'continuous',repeat('B',43),now()); INSERT INTO iscp_relay.device_authority SELECT 'relay-a',domain_id,device_id,1,1,1,'active' FROM iscp_relay.devices; INSERT INTO iscp_relay.connection_owners(scope_id,domain_id,device_id) SELECT scope_id,domain_id,device_id FROM iscp_relay.device_authority; UPDATE iscp_relay.access_tokens SET credential_generation=1; UPDATE iscp_relay.refresh_tokens SET credential_generation=1`)
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
	// Inject only the lost COMMIT acknowledgement; PostgreSQL actually commits.
	// The first response must be unknown, and the original key subsequently
	// recovers its exact immutable receipt instead of executing a new admission.
	s.duplexMu.Lock()
	s.admissionCommit = func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return io.ErrUnexpectedEOF
	}
	s.duplexMu.Unlock()
	uncertain := one.submit(t, b.Identity.DeviceID, "commit-unknown", "6")
	if got := one.read(t); got.State != "unknown" || got.Reason != "commit_unknown" {
		t.Fatal(got)
	}
	s.duplexMu.Lock()
	s.admissionCommit = nil
	s.duplexMu.Unlock()
	uncertain.Kind = "submit.query"
	uncertain.Envelope = nil
	uncertain.RequestID = "7"
	one.write(t, uncertain)
	if got := one.read(t); got.State != "accepted" || got.Receipt == nil {
		t.Fatal(got)
	}
	// Drain the already committed delivery before the independent scope test.
	if got := two.read(t); got.Kind != "delivery" {
		t.Fatal(got)
	}
	assertOldBinaryCannotOverwrite(t, pool, a, ca.Token, first)
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
	if _, e = pool.Exec(ctx, `UPDATE iscp_relay.device_authority SET credential_generation=2 WHERE domain_id='domain-a' AND device_id=$1`, a.Identity.DeviceID); e != nil {
		t.Fatal(e)
	}
	query.RequestID = "3"
	replacement.write(t, query)
	if got := replacement.read(t); got.Kind != "rejected" || got.Code != "auth_required" {
		t.Fatal(got)
	}
	// An active row and unexpired old token never authorize a revised scope.
	if _, e = pool.Exec(ctx, `UPDATE iscp_relay.device_authority SET authorization_revision=2 WHERE domain_id='domain-a' AND device_id=$1`, b.Identity.DeviceID); e != nil {
		t.Fatal(e)
	}
	second.Kind = "submit.query"
	second.Envelope = nil
	second.RequestID = "3"
	two.write(t, second)
	if got := two.read(t); got.Kind != "closing" || got.Code != "authentication_failed" {
		t.Fatal(got)
	}
}

func TestDuplexPostgresClientCallbackMayWaitForReceipt(t *testing.T) {
	pool := receiveDatabase(t)
	s, e := New(Config{DomainID: "domain-a", RelayID: "relay-a", BaseURL: "http://relay.test", AllowedOrigins: []string{"http://relay.test"}, DB: pool, AdminToken: "admin-test-token", ProfileGate: config.DefaultGate(config.ProfileProduction)})
	if e != nil {
		t.Fatal(e)
	}
	h := httptest.NewServer(s.Handler())
	t.Cleanup(func() { s.Close(); h.Close() })
	p := crypto.NewProvider()
	a, _ := identity.NewDevice(p, "domain-a", "client-a", time.Now())
	b, _ := identity.NewDevice(p, "domain-a", "client-b", time.Now())
	ca := bindDeviceForTest(t, s.Handler(), p, a, "relay-a", randomToken())
	cb := bindDeviceForTest(t, s.Handler(), p, b, "relay-a", randomToken())
	tx, e := pool.Begin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = authority.BootstrapEmpty(context.Background(), tx, "relay-a", "domain-a", strings.Repeat("A", 43), strings.Repeat("B", 43), true); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(context.Background()); e != nil {
		t.Fatal(e)
	}
	journalDirectory := t.TempDir()
	makeClient := func(id identity.Device, token string) *iscpbridge.RelayClient {
		now := time.Now()
		bundle := iscpbridge.EnrollmentBundle{DomainID: "domain-a", DeviceID: id.Identity.DeviceID, RelayID: "relay-a", RelayBaseURL: h.URL, RelayWebSocketURL: "ws" + strings.TrimPrefix(h.URL, "http") + duplex.Path, RelaySignerIdentity: &s.signer.Identity, Access: iscpbridge.RelayCredential{DomainID: "domain-a", DeviceID: id.Identity.DeviceID, Token: token, ExpiresAt: now.Add(time.Hour)}, ExpiresAt: now.Add(time.Hour)}
		client, e := iscpbridge.NewRelayClient(iscpbridge.ProfileLocalLab, filepath.Join(journalDirectory, id.Identity.DeviceID+".json"), bundle, id, 5*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		return client
	}
	one, two := makeClient(a, ca.Token), makeClient(b, cb.Token)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ready := make(chan struct{}, 2)
	done := make(chan error, 2)
	received := make(chan struct{}, 1)
	ordered := make(chan uint64, 32)
	lastSequence := uint64(1)
	makeEnvelope := func(sender, recipient, msg string) envelope.SecureEnvelope {
		return envelope.SecureEnvelope{Type: envelope.TypeSecureEnvelope, DomainID: "domain-a", MessageID: msg, SessionID: "session-client", SenderDeviceID: sender, RecipientDeviceID: recipient, Sequence: 1, Nonce: crypto.Base64URL(crypto.RandomBytes(12)), PayloadType: "test", Route: envelope.Route{RelayID: "relay-a", TTLSeconds: 30, Priority: 5}, Ciphertext: crypto.Base64URL(crypto.RandomBytes(32))}
	}
	go func() {
		done <- one.RunOnceReady(ctx, func(context.Context, json.RawMessage) error { received <- struct{}{}; return nil }, func() { ready <- struct{}{} })
	}()
	go func() {
		done <- two.RunOnceReady(ctx, func(ctx context.Context, raw json.RawMessage) error {
			var env envelope.SecureEnvelope
			_ = json.Unmarshal(raw, &env)
			if env.MessageID == "request" {
				return two.Submit(ctx, makeEnvelope(b.Identity.DeviceID, a.Identity.DeviceID, "response"))
			}
			if env.Sequence != lastSequence+1 {
				return errors.New("Relay reordered E2E sequence")
			}
			lastSequence = env.Sequence
			ordered <- env.Sequence
			return nil
		}, func() { ready <- struct{}{} })
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-ready:
		case e := <-done:
			t.Fatal(e)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if e = one.Submit(ctx, makeEnvelope(a.Identity.DeviceID, b.Identity.DeviceID, "request")); e != nil {
		t.Fatal(e)
	}
	select {
	case <-received:
	case e := <-done:
		t.Fatal(e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var futures []*iscpbridge.ReceiptFuture
	for i := uint64(2); i <= 21; i++ {
		env := makeEnvelope(a.Identity.DeviceID, b.Identity.DeviceID, fmt.Sprintf("ordered-%d", i))
		env.Sequence = i
		env.Route.Priority = int(i%2)*8 + 1
		future, err := one.Enqueue(ctx, env)
		if err != nil {
			t.Fatal(err)
		}
		futures = append(futures, future)
	}
	for _, future := range futures {
		if _, err := future.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for i := uint64(2); i <= 21; i++ {
		select {
		case got := <-ordered:
			if got != i {
				t.Fatal(got, i)
			}
		case err := <-done:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	// The verified unknown survives helper replacement and is reconciled by
	// the next socket owner, without involving a business resubmission.
	s.duplexMu.Lock()
	s.admissionCommit = func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return io.ErrUnexpectedEOF
	}
	s.duplexMu.Unlock()
	unknownEnv := makeEnvelope(a.Identity.DeviceID, b.Identity.DeviceID, "restart-unknown")
	unknownEnv.Sequence = 22
	var unknown *iscpbridge.UnknownAcceptance
	if err := one.Submit(ctx, unknownEnv); !errors.As(err, &unknown) {
		t.Fatal("wanted typed unknown", err)
	}
	cancel()
	for i := 0; i < 2; i++ {
		<-done
	}
	s.duplexMu.Lock()
	s.admissionCommit = nil
	s.duplexMu.Unlock()
	restarted := makeClient(a, ca.Token)
	recoveryCtx, stopRecovery := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopRecovery()
	recoveredDone := make(chan error, 1)
	go func() { recoveredDone <- restarted.RunOnceReady(recoveryCtx, nil, nil) }()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			state, ok := restarted.SubmissionStatus("restart-unknown")
			if ok && state.State == "accepted" {
				if state.MessageID != unknown.Submission.MessageID || state.EnvelopeDigest != unknown.Submission.EnvelopeDigest || state.NotAfter != unknown.Submission.NotAfter || state.SessionID != unknown.Submission.SessionID || state.Receipt == nil {
					t.Fatal(state)
				}
				stopRecovery()
				<-recoveredDone
				return
			}
		case err := <-recoveredDone:
			t.Fatal(err)
		case <-recoveryCtx.Done():
			t.Fatal("pending unknown not automatically reconciled")
		}
	}
}

func assertOldBinaryCannotOverwrite(t *testing.T, pool *pgxpool.Pool, id identity.Device, token string, original duplex.Frame) {
	t.Helper()
	binary := os.Getenv("SC_RELAY_OLD_BINARY")
	if binary == "" {
		binary = "/Users/dev/.cache/sparkclaw-iscp-parallel-20261019/baseline-iscp-public-relay"
	}
	raw, e := os.ReadFile(binary)
	if e != nil {
		t.Skip("real baseline binary unavailable; set SC_RELAY_OLD_BINARY")
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != "f47c8ae71a072dd10f1129d3f69f2c1067b3b45d20840604f839388131294899" {
		t.Fatal("unexpected baseline binary digest")
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := listener.Addr().String()
	listener.Close()
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(), "ISCP_DATABASE_URL="+pool.Config().ConnString(), "ISCP_RELAY_ADDR="+addr, "ISCP_DOMAIN_ID=domain-a", "ISCP_RELAY_ID=relay-a", "ISCP_RELAY_BASE_URL=http://"+addr, "ISCP_RELAY_WS_URL=ws://"+addr+"/v2/relay/connect", "ISCP_ALLOWED_ORIGINS=http://"+addr, "ISCP_SIGNER_FILE=", "ISCP_NODE_AUTHORITY_FILE=", "ISCP_ADMIN_TOKEN=admin-test-token")
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for {
		res, err := client.Get("http://" + addr + "/.well-known/iscp/relay")
		if err == nil {
			res.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("old binary did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	var before []byte
	if e = pool.QueryRow(context.Background(), `SELECT envelope_raw FROM iscp_relay.messages WHERE domain_id='domain-a' AND message_id=$1`, original.MessageID).Scan(&before); e != nil {
		t.Fatal(e)
	}
	var env map[string]any
	_ = json.Unmarshal(original.Envelope, &env)
	env["ciphertext"] = crypto.Base64URL(crypto.RandomBytes(64))
	changed, _ := json.Marshal(env)
	request, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/v2/relay/envelopes", bytes.NewReader(changed))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set(accessProofHeader, accessProofHeaderValue(t, crypto.NewProvider(), id, token, http.MethodPost, "/v2/relay/envelopes", randomToken()))
	response, e := client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode == http.StatusAccepted {
		t.Fatal("old executable admitted overwrite")
	}
	var after []byte
	if e = pool.QueryRow(context.Background(), `SELECT envelope_raw FROM iscp_relay.messages WHERE domain_id='domain-a' AND message_id=$1`, original.MessageID).Scan(&after); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("old executable changed immutable envelope")
	}
	var count int
	if e = pool.QueryRow(context.Background(), `SELECT count(*) FROM iscp_relay.admissions WHERE domain_id='domain-a' AND message_id=$1`, original.MessageID).Scan(&count); e != nil || count != 1 {
		t.Fatal("old executable damaged admission")
	}
}

func TestDuplexTimedOutQueuedWriteCannotOutliveAuthority(t *testing.T) {
	accepted := make(chan *websocket.Conn, 1)
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, e := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if e == nil {
			accepted <- ws
		}
	}))
	defer h.Close()
	peer, _, e := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(h.URL, "http"), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	ws := <-accepted
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &duplexConnection{ws: ws, ctx: ctx, cancel: cancel, connection: duplex.RandomID(), generation: "1", expires: time.Now().Add(-time.Second), writes: make(chan duplexWrite, 1), controlWrites: make(chan duplexWrite, 1), changed: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() { c.writer(); close(done) }()
	// An expired data write stays queued. Its waiter timing out represents the
	// authority transaction being about to release its shared revocation lock.
	if err := c.send(c.frame("closing", "maintenance"), true); err == nil {
		t.Fatal("expired data unexpectedly written")
	}
	// Simulate a later reauthentication after that authority guard was released.
	// Closing before send returns makes the old queued frame impossible to emit.
	c.mu.Lock()
	c.expires = time.Now().Add(time.Hour)
	c.mu.Unlock()
	select {
	case c.changed <- struct{}{}:
	default:
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, raw, err := peer.ReadMessage(); err == nil {
		t.Fatalf("post-guard frame leaked: %s", raw)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writer retained timed-out authority")
	}
}
