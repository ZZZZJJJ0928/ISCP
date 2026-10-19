package iscprelayreference

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
	"github.com/jackc/pgx/v5"
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
	signerDirectory := t.TempDir()
	if err := os.Chmod(signerDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{SignerFile: filepath.Join(signerDirectory, "relay-signer.json"), DomainID: "domain-a", RelayID: "relay-a", BaseURL: "http://relay.test", AllowedOrigins: []string{"http://relay.test"}, DB: pool, AdminToken: "admin-test-token", ProfileGate: config.DefaultGate(config.ProfileProduction)})
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

func TestDuplexLongIdleRealCredentialRotationAndReconnect(t *testing.T) {
	if os.Getenv("SC_RELAY_LONG_QUALIFICATION") != "1" {
		t.Skip("explicit >55 second live socket qualification")
	}
	q := newDuplexQualification(t)
	p := connectDuplexTest(t, q.http.URL, q.a, q.token)
	frames := make(chan duplex.Frame, 8)
	failures := make(chan error, 1)
	go func() {
		for {
			_, raw, err := p.ws.ReadMessage()
			if err != nil {
				failures <- err
				return
			}
			f, err := duplex.Decode(raw)
			if err != nil {
				failures <- err
				return
			}
			frames <- f
		}
	}()
	_ = p.ws.SetReadDeadline(time.Now().Add(90 * time.Second))
	read := func() duplex.Frame {
		t.Helper()
		select {
		case f := <-frames:
			return f
		case err := <-failures:
			t.Fatal(err)
		case <-time.After(5 * time.Second):
			t.Fatal("frame timeout")
		}
		return duplex.Frame{}
	}
	start := time.Now()
	select {
	case err := <-failures:
		t.Fatal("healthy idle closed", err)
	case f := <-frames:
		t.Fatal("unexpected idle data", f)
	case <-time.After(57 * time.Second):
	}
	q.server.duplexMu.Lock()
	owner := q.server.duplexOwners[receiveKey("domain-a", q.a.Identity.DeviceID)]
	q.server.duplexMu.Unlock()
	if owner == nil || owner.connection != p.ready.ConnectionID {
		t.Fatal("idle replaced owner")
	}
	owner.queueMu.Lock()
	queued := owner.pendingBytes
	owner.queueMu.Unlock()
	if queued != 0 || len(owner.writes) != 0 || len(owner.controlWrites) != 0 {
		t.Fatal("idle retained queue", queued)
	}
	tx, err := q.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	_, err = authority.Lock(t.Context(), tx, authority.Request{ScopeID: "relay-a", DomainID: "domain-a", ExpectedWriterEpoch: "1", Devices: []authority.DeviceLock{{ID: q.a.Identity.DeviceID, Exclusive: true}}})
	if err != nil {
		t.Fatal(err)
	}
	token := randomToken()
	_, err = tx.Exec(t.Context(), `UPDATE iscp_relay.access_tokens SET revoked_at=now() WHERE device_id=$1;`, q.a.Identity.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(t.Context(), `UPDATE iscp_relay.device_authority SET credential_generation=2,state_version=state_version+1 WHERE device_id=$1`, q.a.Identity.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(t.Context(), `INSERT INTO iscp_relay.access_tokens(id,domain_id,device_id,token_hash,issued_at,expires_at,credential_generation) VALUES('00000000-0000-4000-8000-000000000002','domain-a',$1,$2,now(),now()+interval '1 hour',2)`, q.a.Identity.DeviceID, crypto.SHA256([]byte(token)))
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	p.write(t, duplex.Frame{V: 1, Kind: "reauth.request", ConnectionID: p.ready.ConnectionID, OwnerGeneration: p.ready.OwnerGeneration, RequestID: "2"})
	challenge := read()
	challenge.Limits = p.challenge.Limits
	challenge.HistoryID = p.challenge.HistoryID
	challenge.RelayID = p.challenge.RelayID
	hash, err := duplex.AuthChallenge(challenge, "reauthenticate", "2", p.ready.OwnerGeneration, token, q.a.Identity)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := q.a.CreateProof(crypto.NewProvider(), "relay-a", hash, crypto.Base64URL(crypto.RandomBytes(16)), time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	p.write(t, duplex.Frame{V: 1, Kind: "reauthenticate", ConnectionID: p.ready.ConnectionID, OwnerGeneration: p.ready.OwnerGeneration, RequestID: "2", ChallengeID: challenge.ChallengeID, AccessToken: token, Proof: &proof})
	if got := read(); got.Kind != "reauthenticated" || got.ConnectionID != p.ready.ConnectionID || got.OwnerGeneration != p.ready.OwnerGeneration {
		t.Fatal(got)
	}
	submitted := p.submit(t, q.b.Identity.DeviceID, "idle-rotated", "3")
	accepted := read()
	if accepted.Kind != "accepted" {
		t.Fatal(accepted)
	}
	p.ws.Close()
	next := connectDuplexTest(t, q.http.URL, q.a, token)
	if next.ready.OwnerGeneration == p.ready.OwnerGeneration {
		t.Fatal("network reconnect reused old owner")
	}
	submitted.Kind = "submit.query"
	submitted.Envelope = nil
	submitted.ConnectionID = next.ready.ConnectionID
	submitted.OwnerGeneration = next.ready.OwnerGeneration
	submitted.RequestID = "2"
	next.write(t, submitted)
	got := next.read(t)
	if got.State != "accepted" || got.Receipt.ReceiptID != accepted.Receipt.ReceiptID {
		t.Fatal(got)
	}
	t.Logf("healthy empty socket idle=57s; total=%s; same-owner generation rotation then network reconnect preserved receipt", time.Since(start))
}

func TestDuplexPostgresInstanceRestartPreservesReceipt(t *testing.T) {
	if os.Getenv("SC_RELAY_RESTART_QUALIFICATION") != "1" {
		t.Skip("explicit isolated Docker PostgreSQL restart qualification")
	}
	name := fmt.Sprintf("iscp-duplex-restart-%d", time.Now().UnixNano())
	run := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		b, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("owned PostgreSQL command failed: %v %s", err, b)
		}
		return strings.TrimSpace(string(b))
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hostAddress := listener.Addr().String()
	listener.Close()
	run("run", "-d", "--name", name, "--label", "iscp.qualification=duplex-restart", "-e", "POSTGRES_PASSWORD=isolated-restart-only", "-p", hostAddress+":5432", "postgres:18")
	t.Cleanup(func() { exec.Command("docker", "rm", "-fv", name).Run() })
	endpoint := run("port", name, "5432/tcp")
	t.Setenv("SC_RELAY_TEST_DSN", "postgres://postgres:isolated-restart-only@"+endpoint+"/postgres?sslmode=disable")
	wait := func() {
		t.Helper()
		for i := 0; i < 100; i++ {
			if exec.Command("docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres").Run() == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("owned PostgreSQL did not become ready")
	}
	wait()
	q := newDuplexQualification(t)
	p := connectDuplexTest(t, q.http.URL, q.a, q.token)
	submitted := p.submit(t, q.b.Identity.DeviceID, "survives-instance-restart", "2")
	before := p.read(t)
	if before.Kind != "accepted" {
		t.Fatal(before)
	}
	q.server.Close()
	q.http.Close()
	if run("inspect", "-f", "{{ index .Config.Labels \"iscp.qualification\" }}", name) != "duplex-restart" {
		t.Fatal("refuse restart of unowned container")
	}
	run("restart", name)
	wait()
	q.pool.Reset()
	for i := 0; i < 100; i++ {
		if q.pool.Ping(t.Context()) == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	cfg := q.server.cfg
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(s.Handler())
	t.Cleanup(func() { s.Close(); h.Close() })
	if s.signer.Identity.PublicKey.Public != q.server.signer.Identity.PublicKey.Public {
		t.Fatal("restart changed receipt signer")
	}
	after := connectDuplexTest(t, h.URL, q.a, q.token)
	submitted.Kind = "submit.query"
	submitted.Envelope = nil
	submitted.RequestID = "2"
	submitted.ConnectionID = after.ready.ConnectionID
	submitted.OwnerGeneration = after.ready.OwnerGeneration
	after.write(t, submitted)
	got := after.read(t)
	expected, _ := json.Marshal(before.Receipt)
	actual, _ := json.Marshal(got.Receipt)
	if (got.State != "accepted" && got.State != "expired") || !bytes.Equal(expected, actual) {
		t.Fatal("database restart changed original receipt", got)
	}
	t.Log("isolated PostgreSQL 18 instance stopped/restarted with original volume; fresh Relay instance returned byte-identical receipt")
}

func TestDuplexCrossOwnerUnfinishedCommitCannotProveAbsence(t *testing.T) {
	q := newDuplexQualification(t)
	one := connectDuplexTest(t, q.http.URL, q.a, q.token)
	entered, release, committed := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var releaseOnce sync.Once
	releaseCommit := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseCommit)
	q.server.duplexMu.Lock()
	q.server.admissionCommit = func(_ context.Context, tx pgx.Tx) error {
		close(entered)
		<-release
		err := tx.Commit(context.Background())
		committed <- err
		return err
	}
	q.server.duplexMu.Unlock()
	first := one.submit(t, q.b.Identity.DeviceID, "unfinished-commit", "2")
	<-entered
	ws, _, err := (&websocket.Dialer{Subprotocols: []string{duplex.Protocol}}).Dial("ws"+strings.TrimPrefix(q.http.URL, "http")+duplex.Path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	next := &duplexTestPeer{ws: ws}
	challenge := next.read(t)
	hash, err := duplex.AuthChallenge(challenge, "authenticate", "1", "0", q.token, q.a.Identity)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := q.a.CreateProof(crypto.NewProvider(), "relay-a", hash, crypto.Base64URL(crypto.RandomBytes(16)), time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	next.write(t, duplex.Frame{V: 1, Kind: "authenticate", ConnectionID: challenge.ConnectionID, RequestID: "1", ChallengeID: challenge.ChallengeID, AccessToken: q.token, Proof: &proof})
	_ = ws.SetReadDeadline(time.Now().Add(7 * time.Second))
	_, raw, err := ws.ReadMessage()
	if err == nil {
		f, e := duplex.Decode(raw)
		if e != nil || f.Kind != "closing" {
			t.Fatal("new owner bypassed uncommitted original", f, e)
		}
	}
	var generation string
	if err = q.pool.QueryRow(t.Context(), `SELECT owner_generation::text FROM iscp_relay.connection_owners WHERE device_id=$1`, q.a.Identity.DeviceID).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if generation != one.ready.OwnerGeneration {
		t.Fatal("lock timeout installed owner", generation)
	}
	releaseCommit()
	if err = <-committed; err != nil {
		t.Fatal(err)
	}
	q.server.duplexMu.Lock()
	q.server.admissionCommit = nil
	q.server.duplexMu.Unlock()
	recovered := connectDuplexTest(t, q.http.URL, q.a, q.token)
	first.Kind = "submit.query"
	first.Envelope = nil
	first.ConnectionID = recovered.ready.ConnectionID
	first.OwnerGeneration = recovered.ready.OwnerGeneration
	first.RequestID = "2"
	recovered.write(t, first)
	got := recovered.read(t)
	if got.State != "accepted" || got.Receipt == nil {
		t.Fatal("unfinished original was reclassified absent", got)
	}
}
