package iscprelayadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	ref "github.com/Infinimesh-ai/ISCP/pkg/server/relay"
)

// Exercise the public handler's real HTTP Write and Flush, rather than calling
// the adapter guard with a synthetic emit callback.
type registrationWriteGate struct {
	http.ResponseWriter
	phase   string
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *registrationWriteGate) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *registrationWriteGate) pause(phase string) {
	if w.phase == phase {
		w.once.Do(func() { close(w.entered); <-w.release })
	}
}
func (w *registrationWriteGate) Write(p []byte) (int, error) {
	w.pause("write")
	return w.ResponseWriter.Write(p)
}
func (w *registrationWriteGate) FlushError() error {
	w.pause("flush")
	return http.NewResponseController(w.ResponseWriter).Flush()
}

type registrationHTTPResult struct {
	status int
	body   []byte
	err    error
}

func publicRegistrationFixture(t *testing.T) lifecycleFixture {
	t.Helper()
	f := newLifecycleFixture(t)
	f.client = device(t, "public-registration-client")
	f.preparation, _ = prep(t, f.adapter, f.invite, f.signer, f.client, "public-registration-operation")
	if err := f.adapter.Prepare(t.Context(), f.preparation); err != nil {
		t.Fatal(err)
	}
	return f
}

func publicRegistrationServer(t *testing.T, f lifecycleFixture, managed ref.ManagedAdapter) *ref.Server {
	t.Helper()
	s, err := ref.New(ref.Config{DomainID: "test-domain", RelayID: "test-relay", BaseURL: "https://127.0.0.1", WebSocketURL: "wss://127.0.0.1/v2/relay/connect", AdminToken: "synthetic-test-only", AllowedOrigins: []string{"https://127.0.0.1"}, ProfileGate: config.DefaultGate(config.ProfileProduction), DB: f.pool, Managed: managed})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func startPublicRegistration(t *testing.T, f lifecycleFixture, server *httptest.Server) <-chan registrationHTTPResult {
	t.Helper()
	body, err := json.Marshal(map[string]any{"identity": f.client.Identity, "proof": proof(t, f.client, f.preparation.TicketV3.TicketID), "ticket": f.preparation.TicketV3})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/v2/relay/devices/register-with-ticket", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	done := make(chan registrationHTTPResult, 1)
	go func() {
		res, err := server.Client().Do(req)
		if err != nil {
			done <- registrationHTTPResult{err: err}
			return
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		done <- registrationHTTPResult{status: res.StatusCode, body: body, err: err}
	}()
	return done
}

func TestControlPublicRegistrationWriteAndFlushBlockActualRevoke(t *testing.T) {
	for _, phase := range []string{"write", "flush"} {
		t.Run(phase, func(t *testing.T) {
			f := publicRegistrationFixture(t)
			relay := publicRegistrationServer(t, f, f.adapter)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				relay.Handler().ServeHTTP(&registrationWriteGate{ResponseWriter: w, phase: phase, entered: entered, release: release}, r)
			}))
			t.Cleanup(server.Close)
			response := startPublicRegistration(t, f, server)
			select {
			case <-entered:
			case out := <-response:
				t.Fatalf("registration did not reach %s: %d %s %v", phase, out.status, out.body, out.err)
			case <-time.After(3 * time.Second):
				t.Fatal("registration did not reach disclosure")
			}
			revoked := make(chan error, 1)
			go func() {
				revoked <- f.adapter.Revoke(t.Context(), "public-registration-revoke", f.client.Identity.DeviceID, 2)
			}()
			// Confirm that the real revocation transaction reached a database lock,
			// so a merely unscheduled goroutine cannot make this assertion pass.
			deadline := time.Now().Add(2 * time.Second)
			for {
				select {
				case err := <-revoked:
					t.Fatal("actual Revoke bypassed public disclosure", err)
				default:
				}
				var waiting bool
				if err := f.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("Revoke never reached the authority lock")
				}
				time.Sleep(10 * time.Millisecond)
			}
			unblock()
			select {
			case out := <-response:
				var tokens map[string]json.RawMessage
				if out.err != nil || out.status != http.StatusOK || json.Unmarshal(out.body, &tokens) != nil || tokens["access"] == nil || tokens["refresh"] == nil {
					t.Fatalf("guarded registration failed: %d %s %v", out.status, out.body, out.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("registration did not finish after release")
			}
			select {
			case err := <-revoked:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Revoke did not finish after disclosure")
			}
			emitted := false
			if err := f.adapter.DiscloseRegistration(t.Context(), f.client.Identity, func() error { emitted = true; return nil }); err == nil || emitted {
				t.Fatal("post-revoke registration disclosed credentials", err, emitted)
			}
		})
	}
}

type registrationCommitGate struct {
	*Adapter
	committed chan struct{}
	release   chan struct{}
}

func (a *registrationCommitGate) Register(ctx context.Context, id identity.DeviceIdentity, proof identity.DeviceProof, ticket provisioning.PairingTicketV3) (json.RawMessage, error) {
	raw, err := a.Adapter.Register(ctx, id, proof, ticket)
	if err == nil {
		close(a.committed)
		<-a.release
	}
	return raw, err
}

func TestControlPublicRegistrationRechecksRevokeAfterCommit(t *testing.T) {
	f := publicRegistrationFixture(t)
	gate := &registrationCommitGate{Adapter: f.adapter, committed: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(gate.release) }) }
	defer unblock()
	relay := publicRegistrationServer(t, f, gate)
	server := httptest.NewServer(relay.Handler())
	t.Cleanup(server.Close)
	response := startPublicRegistration(t, f, server)
	select {
	case <-gate.committed:
	case out := <-response:
		t.Fatalf("registration did not commit: %d %s %v", out.status, out.body, out.err)
	case <-time.After(3 * time.Second):
		t.Fatal("registration did not commit")
	}
	if err := f.adapter.Revoke(t.Context(), "public-registration-pre-disclosure-revoke", f.client.Identity.DeviceID, 2); err != nil {
		t.Fatal(err)
	}
	unblock()
	select {
	case out := <-response:
		if out.err != nil || out.status != http.StatusForbidden || bytes.Contains(out.body, []byte(`"access"`)) || bytes.Contains(out.body, []byte(`"refresh"`)) {
			t.Fatalf("revoked registration response escaped guard: %d %s %v", out.status, out.body, out.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoked response did not finish")
	}
}
