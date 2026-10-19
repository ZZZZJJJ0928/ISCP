package iscprelayreference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"github.com/gorilla/websocket"
)

type refreshPair struct{ Access, Refresh credential }

func currentTestRefresh(q duplexQualification) string {
	q.server.mu.RLock()
	defer q.server.mu.RUnlock()
	for _, c := range q.server.refresh {
		if c.DeviceID == q.a.Identity.DeviceID {
			return c.Token
		}
	}
	return ""
}
func refreshTestHTTP(url, token string) (int, refreshPair, error) {
	raw, _ := json.Marshal(map[string]string{"refresh": token})
	resp, err := http.Post(url+"/v2/relay/devices/refresh-access", "application/json", strings.NewReader(string(raw)))
	if err != nil {
		return 0, refreshPair{}, err
	}
	defer resp.Body.Close()
	var pair refreshPair
	if resp.StatusCode == 200 {
		err = json.NewDecoder(resp.Body).Decode(&pair)
	}
	return resp.StatusCode, pair, err
}
func reauthenticateTestPeer(t *testing.T, p *duplexTestPeer, token string) {
	t.Helper()
	p.write(t, duplex.Frame{V: 1, Kind: "reauth.request", ConnectionID: p.ready.ConnectionID, OwnerGeneration: p.ready.OwnerGeneration, RequestID: "2"})
	challenge := p.read(t)
	challenge.RelayID = p.challenge.RelayID
	challenge.HistoryID = p.challenge.HistoryID
	challenge.Limits = p.challenge.Limits
	h, err := duplex.AuthChallenge(challenge, "reauthenticate", "2", p.ready.OwnerGeneration, token, p.id.Identity)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := p.id.CreateProof(crypto.NewProvider(), "relay-a", h, duplex.RandomID(), time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	p.write(t, duplex.Frame{V: 1, Kind: "reauthenticate", ConnectionID: p.ready.ConnectionID, OwnerGeneration: p.ready.OwnerGeneration, RequestID: "2", ChallengeID: challenge.ChallengeID, AccessToken: token, Proof: &proof})
	got := p.read(t)
	if got.Kind != "reauthenticated" || got.ConnectionID != p.ready.ConnectionID || got.OwnerGeneration != p.ready.OwnerGeneration {
		t.Fatal("reauth replaced same-identity owner", got)
	}
}
func rejectTestAccess(t *testing.T, q duplexQualification, token string) {
	t.Helper()
	ws, _, err := (&websocket.Dialer{Subprotocols: []string{duplex.Protocol}}).Dial("ws"+strings.TrimPrefix(q.http.URL, "http")+duplex.Path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	p := &duplexTestPeer{ws: ws}
	challenge := p.read(t)
	h, err := duplex.AuthChallenge(challenge, "authenticate", "1", "0", token, q.a.Identity)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := q.a.CreateProof(crypto.NewProvider(), "relay-a", h, duplex.RandomID(), time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	p.write(t, duplex.Frame{V: 1, Kind: "authenticate", ConnectionID: challenge.ConnectionID, RequestID: "1", ChallengeID: challenge.ChallengeID, AccessToken: token, Proof: &proof})
	got := p.read(t)
	if got.Kind != "closing" || got.Code != "authentication_failed" {
		t.Fatal("old access admitted", got)
	}
}
func TestDuplexUnmanagedHTTPRefreshAtomicGenerationAndReauth(t *testing.T) {
	q := newDuplexQualification(t)
	refresh := currentTestRefresh(q)
	p := connectDuplexTest(t, q.http.URL, q.a, q.token)
	status, pair, err := refreshTestHTTP(q.http.URL, refresh)
	if err != nil || status != 200 {
		t.Fatal(status, err)
	}
	reauthenticateTestPeer(t, p, pair.Access.Token)
	p.submit(t, q.b.Identity.DeviceID, "after-http-refresh", "3")
	if got := p.read(t); got.Kind != "accepted" {
		t.Fatal(got)
	}
	next := connectDuplexTest(t, q.http.URL, q.a, pair.Access.Token)
	if next.ready.OwnerGeneration == p.ready.OwnerGeneration {
		t.Fatal("new socket did not advance owner")
	}
	rejectTestAccess(t, q, q.token)
	var gen string
	var liveAccess, liveRefresh int
	if err = q.pool.QueryRow(t.Context(), `SELECT credential_generation::text FROM iscp_relay.device_authority WHERE device_id=$1`, q.a.Identity.DeviceID).Scan(&gen); err != nil || gen != "2" {
		t.Fatal(gen, err)
	}
	if err = q.pool.QueryRow(t.Context(), `SELECT count(*) FROM iscp_relay.access_tokens WHERE device_id=$1 AND revoked_at IS NULL AND credential_generation=2`, q.a.Identity.DeviceID).Scan(&liveAccess); err != nil {
		t.Fatal(err)
	}
	if err = q.pool.QueryRow(t.Context(), `SELECT count(*) FROM iscp_relay.refresh_tokens WHERE device_id=$1 AND revoked_at IS NULL AND credential_generation=2`, q.a.Identity.DeviceID).Scan(&liveRefresh); err != nil || liveAccess != 1 || liveRefresh != 1 {
		t.Fatal(liveAccess, liveRefresh, err)
	}
	// Two actual HTTP rotations using one refresh can install only one successor.
	type result struct {
		status int
		pair   refreshPair
		err    error
	}
	done := make(chan result, 2)
	for range 2 {
		go func() { s, p, e := refreshTestHTTP(q.http.URL, pair.Refresh.Token); done <- result{s, p, e} }()
	}
	wins := 0
	var winner refreshPair
	for range 2 {
		r := <-done
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.status == 200 {
			wins++
			winner = r.pair
		} else if r.status != 401 {
			t.Fatal(r.status)
		}
	}
	if wins != 1 {
		t.Fatal("concurrent refresh installed multiple successors", wins)
	}
	rejectTestAccess(t, q, pair.Access.Token)
	connectDuplexTest(t, q.http.URL, q.a, winner.Access.Token)
	if err = q.pool.QueryRow(t.Context(), `SELECT credential_generation::text FROM iscp_relay.device_authority WHERE device_id=$1`, q.a.Identity.DeviceID).Scan(&gen); err != nil || gen != "3" {
		t.Fatal(gen, err)
	}
}
func TestDuplexUnmanagedRefreshRejectsNULLAndFencedAuthorities(t *testing.T) {
	for _, reason := range []string{"null-generation", "revoked", "writer-epoch"} {
		t.Run(reason, func(t *testing.T) {
			q := newDuplexQualification(t)
			refresh := currentTestRefresh(q)
			tx, err := q.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			_, err = authority.Lock(t.Context(), tx, authority.Request{ScopeID: "relay-a", DomainID: "domain-a", ExpectedWriterEpoch: "1", Devices: []authority.DeviceLock{{ID: q.a.Identity.DeviceID, Exclusive: true}}, Owners: []authority.DeviceLock{{ID: q.a.Identity.DeviceID, Exclusive: true}}})
			if err != nil {
				t.Fatal(err)
			}
			switch reason {
			case "null-generation":
				_, err = tx.Exec(t.Context(), `UPDATE iscp_relay.refresh_tokens SET credential_generation=NULL WHERE device_id=$1`, q.a.Identity.DeviceID)
				if err == nil {
					_, err = tx.Exec(t.Context(), `UPDATE iscp_relay.access_tokens SET credential_generation=NULL WHERE device_id=$1`, q.a.Identity.DeviceID)
				}
			case "revoked":
				_, err = tx.Exec(t.Context(), `UPDATE iscp_relay.device_authority SET state='revoked' WHERE device_id=$1`, q.a.Identity.DeviceID)
			case "writer-epoch":
				_, err = tx.Exec(t.Context(), `UPDATE iscp_relay.writer_scopes SET writer_epoch=2 WHERE scope_id='relay-a'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			status, _, err := refreshTestHTTP(q.http.URL, refresh)
			if reason == "null-generation" {
				rejectTestAccess(t, q, q.token)
			}
			if err != nil || status != 401 {
				t.Fatal(status, err)
			}
			var gen string
			if err = q.pool.QueryRow(t.Context(), `SELECT credential_generation::text FROM iscp_relay.device_authority WHERE device_id=$1`, q.a.Identity.DeviceID).Scan(&gen); err != nil || gen != "1" {
				t.Fatal("refused refresh changed authority", gen, err)
			}
		})
	}
}

type blockedRefreshResponse struct {
	http.ResponseWriter
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockedRefreshResponse) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	return w.ResponseWriter.Write(b)
}
func (w *blockedRefreshResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func TestDuplexUnmanagedRefreshDisclosureBlocksPublicRevocation(t *testing.T) {
	q := newDuplexQualification(t)
	refresh := currentTestRefresh(q)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/relay/devices/refresh-access" {
			w = &blockedRefreshResponse{ResponseWriter: w, entered: entered, release: release}
		}
		q.server.Handler().ServeHTTP(w, r)
	}))
	defer func() { unblock(); h.Close() }()
	done := make(chan int, 1)
	go func() { status, _, _ := refreshTestHTTP(h.URL, refresh); done <- status }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("refresh never reached guarded disclosure")
	}
	revoked := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, h.URL+"/v2/relay/devices/revoke-access", strings.NewReader(`{"device_id":"qualification-a"}`))
		req.Header.Set("Authorization", "Bearer admin-test-token")
		resp, e := http.DefaultClient.Do(req)
		if e != nil {
			revoked <- 0
			return
		}
		resp.Body.Close()
		revoked <- resp.StatusCode
	}()
	select {
	case status := <-revoked:
		t.Fatal("revoke crossed pending credential disclosure", status)
	case <-time.After(80 * time.Millisecond):
	}
	unblock()
	if status := <-done; status != 200 {
		t.Fatal(status)
	}
	if status := <-revoked; status != 200 {
		t.Fatal(status)
	}
	var live int
	if err := q.pool.QueryRow(t.Context(), `SELECT count(*) FROM iscp_relay.access_tokens WHERE device_id=$1 AND revoked_at IS NULL`, q.a.Identity.DeviceID).Scan(&live); err != nil || live != 0 {
		t.Fatal(live, err)
	}
}

func TestDuplexActualClientInvalidationRefreshKeepsSocketAndPersists(t *testing.T) {
	for _, initialFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(initialFailure), func(t *testing.T) {
			q := newDuplexQualification(t)
			q.server.cfg.BaseURL = q.http.URL
			q.server.cfg.WebSocketURL = "ws" + strings.TrimPrefix(q.http.URL, "http") + duplex.Path
			now := time.Now().UTC()
			path := filepath.Join(t.TempDir(), "enrollment.json")
			bundle := iscpbridge.EnrollmentBundle{Type: iscpbridge.EnrollmentBundleType, Mode: iscpbridge.BundleModeWorkbenchLocalLab, DomainID: "domain-a", DeviceID: q.a.Identity.DeviceID, RelayID: "relay-a", RelayBaseURL: q.http.URL, RelayWebSocketURL: q.server.cfg.WebSocketURL, RelaySignerIdentity: &q.server.signer.Identity, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Access: iscpbridge.RelayCredential{DomainID: "domain-a", DeviceID: q.a.Identity.DeviceID, Token: q.token, ExpiresAt: now.Add(15 * time.Minute)}, Refresh: iscpbridge.RelayCredential{DomainID: "domain-a", DeviceID: q.a.Identity.DeviceID, Token: currentTestRefresh(q), ExpiresAt: now.Add(24 * time.Hour)}}
			if err := iscpbridge.SaveEnrollment(path, bundle); err != nil {
				t.Fatal(err)
			}
			client, err := iscpbridge.NewRelayCredentialClient(iscpbridge.ProfileLocalLab, path, bundle, q.a, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			invalidate := func() {
				tx, e := q.pool.Begin(t.Context())
				if e != nil {
					t.Fatal(e)
				}
				defer tx.Rollback(context.Background())
				_, e = authority.Lock(t.Context(), tx, authority.Request{ScopeID: "relay-a", DomainID: "domain-a", ExpectedWriterEpoch: "1", Devices: []authority.DeviceLock{{ID: q.a.Identity.DeviceID, Exclusive: true}}})
				if e != nil {
					t.Fatal(e)
				}
				_, e = tx.Exec(t.Context(), `UPDATE iscp_relay.access_tokens SET revoked_at=now() WHERE domain_id='domain-a' AND device_id=$1 AND token_hash=$2`, q.a.Identity.DeviceID, crypto.SHA256([]byte(q.token)))
				if e != nil {
					t.Fatal(e)
				}
				if e = tx.Commit(t.Context()); e != nil {
					t.Fatal(e)
				}
			}
			if initialFailure {
				invalidate()
				if err = client.RunOnceReady(t.Context(), func(context.Context, json.RawMessage) error { return nil }, nil); err == nil {
					t.Fatal("rejected authentication became READY")
				}
				if client.Enrollment().Access.Token == q.token {
					t.Fatal("initial rejection did not refresh original identity")
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ready, done := make(chan struct{}, 2), make(chan error, 1)
			go func() {
				done <- client.RunOnceReady(ctx, func(context.Context, json.RawMessage) error { return nil }, func() { ready <- struct{}{} })
			}()
			select {
			case <-ready:
			case err := <-done:
				t.Fatal(err)
			case <-time.After(3 * time.Second):
				t.Fatal("client not ready")
			}
			var oldConnection, oldOwner string
			if err = q.pool.QueryRow(t.Context(), `SELECT connection_id,owner_generation::text FROM iscp_relay.connection_owners WHERE device_id=$1`, q.a.Identity.DeviceID).Scan(&oldConnection, &oldOwner); err != nil {
				t.Fatal(err)
			}
			if !initialFailure {
				invalidate()
				err = client.Submit(t.Context(), qualificationEnvelope(q.a.Identity.DeviceID, q.b.Identity.DeviceID, "trigger-auth-required"))
				var rejected *duplex.Rejected
				if !errors.As(err, &rejected) || rejected.Code != "auth_required" {
					t.Fatal("expected explicit access rejection", err)
				}
			}
			var ownerGen, currentConnection, gen string
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				err = q.pool.QueryRow(t.Context(), `SELECT connection_id,owner_generation::text,credential_generation::text FROM iscp_relay.connection_owners WHERE device_id=$1`, q.a.Identity.DeviceID).Scan(&currentConnection, &ownerGen, &gen)
				if err == nil && gen == "2" {
					break
				}
				select {
				case err := <-done:
					t.Fatal("client disconnected instead of reauth", err)
				default:
				}
				time.Sleep(10 * time.Millisecond)
			}
			if gen != "2" || ownerGen != oldOwner || currentConnection != oldConnection {
				t.Fatal("HTTP rotation replaced owner or failed", gen, ownerGen == oldOwner, currentConnection == oldConnection)
			}
			if err = client.Submit(t.Context(), qualificationEnvelope(q.a.Identity.DeviceID, q.b.Identity.DeviceID, "after-client-http-refresh")); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var persisted iscpbridge.EnrollmentBundle
			if json.Unmarshal(raw, &persisted) != nil || persisted.Access.Token != client.Enrollment().Access.Token || persisted.Access.Token == q.token || persisted.DeviceID != bundle.DeviceID {
				t.Fatal("rotation was not persisted under original identity")
			}
			select {
			case <-ready:
				t.Fatal("same socket reauth fired replacement readiness")
			default:
			}
			cancel()
			<-done
		})
	}
}
