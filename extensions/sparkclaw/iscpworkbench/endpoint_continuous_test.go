package iscpworkbench

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
	"github.com/gorilla/websocket"
)

// This authenticated continuous-socket fixture verifies actual PoP and encrypted
// Endpoint delivery, including stale frames from a retired process.
func TestContinuousRelayRetainsEncryptedSession(t *testing.T) {
	for _, profile := range []string{iscpbridge.ProfileLocalLab, iscpbridge.ProfileProduction} {
		t.Run(profile, func(t *testing.T) { testContinuousRelay(t, profile) })
	}
}
func testContinuousRelay(t *testing.T, profile string) {
	desktop, backend := testMaterials(t)
	provider := iscpcrypto.NewProvider()
	signer, err := identity.NewDevice(provider, desktop.enrollment.DomainID, "relay-test-signer", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	devices := map[string]identity.DeviceIdentity{desktop.device.Identity.DeviceID: desktop.device.Identity, backend.device.Identity.DeviceID: backend.device.Identity}
	var queueMu sync.Mutex
	queues := map[string][]json.RawMessage{}
	var polls, proofs, posts atomic.Int32
	newServer := httptest.NewServer
	if profile == iscpbridge.ProfileProduction {
		newServer = httptest.NewTLSServer
	}
	server := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/relay/connect":
			connection, err := new(websocket.Upgrader).Upgrade(w, r, nil)
			if err != nil {
				t.Error(err)
				return
			}
			defer connection.Close()
			challenge := newUUID()
			if err := connection.WriteJSON(map[string]string{"state": "challenge", "challenge": challenge}); err != nil {
				return
			}
			var proof identity.DeviceProof
			if connection.ReadJSON(&proof) != nil {
				return
			}
			id, ok := devices[proof.DeviceID]
			if !ok || identity.VerifyProof(provider, id, proof, "relay-test", challenge, time.Now().UTC(), time.Minute) != nil {
				t.Error("invalid authenticated drain poll proof")
				return
			}
			proofs.Add(1)
			if connection.WriteJSON(map[string]string{"state": "ready"}) != nil {
				return
			}
			polls.Add(1)
			closed := make(chan struct{})
			go func() {
				defer close(closed)
				for {
					if _, _, err := connection.ReadMessage(); err != nil {
						return
					}
				}
			}()
			ticker := time.NewTicker(2 * time.Millisecond)
			defer ticker.Stop()
			for {
				queueMu.Lock()
				snapshot := queues[id.DeviceID]
				delete(queues, id.DeviceID)
				queueMu.Unlock()
				for _, raw := range snapshot {
					if connection.WriteJSON(map[string]any{"state": "message", "message_id": newUUID(), "envelope": raw}) != nil {
						return
					}
				}
				select {
				case <-closed:
					return
				case <-ticker.C:
				}
			}
		case "/v2/relay/envelopes":
			raw, err := io.ReadAll(io.LimitReader(r.Body, 100<<10))
			if err != nil {
				w.WriteHeader(400)
				return
			}
			var env envelope.SecureEnvelope
			if json.Unmarshal(raw, &env) != nil {
				w.WriteHeader(400)
				return
			}
			id, ok := devices[env.SenderDeviceID]
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			var proof identity.DeviceProof
			proofRaw, decodeErr := iscpcrypto.DecodeBase64URL(r.Header.Get("X-ISCP-Access-Proof"))
			challenge := strings.Join([]string{"iscp/v2/relay/access-proof", http.MethodPost, "/v2/relay/envelopes", iscpcrypto.Base64URL(iscpcrypto.SHA256([]byte(token)))}, "\x00")
			if !ok || token != id.DeviceID+"-access" || decodeErr != nil || json.Unmarshal(proofRaw, &proof) != nil || identity.VerifyProof(provider, id, proof, "relay-test", challenge, time.Now().UTC(), time.Minute) != nil {
				t.Error("invalid encrypted envelope access PoP")
				w.WriteHeader(401)
				return
			}
			posts.Add(1)
			queueMu.Lock()
			queues[env.RecipientDeviceID] = append(queues[env.RecipientDeviceID], json.RawMessage(raw))
			queueMu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Errorf("unexpected reference lifecycle endpoint: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	invitation, err := identity.NewDevice(provider, desktop.enrollment.DomainID, "node-invitation", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(m material) material {
		m.enrollment.Mode = iscpbridge.BundleModeWorkbenchLocalLab
		if profile == iscpbridge.ProfileProduction {
			m.enrollment.Mode = iscpbridge.BundleModeWorkbenchNodeManaged
			m.enrollment.InvitationSignerIdentity = &invitation.Identity
			m.enrollment.TLSCertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
		}
		m.enrollment.TrustRootIdentity = identity.DeviceIdentity{}
		m.enrollment.RelaySignerIdentity = &signer.Identity
		m.enrollment.RelayBaseURL = server.URL
		m.enrollment.RelayWebSocketURL = "ws" + strings.TrimPrefix(server.URL, "http") + "/v2/relay/connect"
		m.enrollment.Access.Token = m.device.Identity.DeviceID + "-access"
		return m
	}
	desktop, backend = prepare(desktop), prepare(backend)
	// The Relay keeps queued data when either process restarts. Seed both
	// directions with actual SDK frames from a retired session, including a
	// recent signed Hello that predates the new local responder. None may
	// reach business dispatch or abort the fresh handshake's drain snapshot.
	oldID := newUUID()
	oldTime := time.Now().UTC().Add(-2 * time.Second)
	oldDesktop, err := session.CreateHello(provider, desktop.device, oldID, backend.device.Identity.DeviceID, desktop.grant.GrantID, oldTime)
	if err != nil {
		t.Fatal(err)
	}
	oldBackend, err := session.CreateHello(provider, backend.device, oldID, desktop.device.Identity.DeviceID, "", oldTime)
	if err != nil {
		t.Fatal(err)
	}
	oldDesktopState, err := session.Establish(provider, oldDesktop, oldBackend.Hello, desktop.device.Identity, backend.device.Identity)
	if err != nil {
		t.Fatal(err)
	}
	oldBackendState, err := session.Establish(provider, oldBackend, oldDesktop.Hello, backend.device.Identity, desktop.device.Identity)
	if err != nil {
		t.Fatal(err)
	}
	oldDesktopReady, err := oldDesktopState.CreateReady(provider, desktop.device)
	if err != nil {
		t.Fatal(err)
	}
	oldBackendReady, err := oldBackendState.CreateReady(provider, backend.device)
	if err != nil {
		t.Fatal(err)
	}
	if err := oldDesktopState.VerifyReady(provider, oldBackendReady, backend.device.Identity); err != nil {
		t.Fatal(err)
	}
	if err := oldBackendState.VerifyReady(provider, oldDesktopReady, desktop.device.Identity); err != nil {
		t.Fatal(err)
	}
	appendOldHandshake := func(sender, recipient, payloadType string, value any) {
		raw, _ := json.Marshal(value)
		env := envelope.SecureEnvelope{Type: envelope.TypeSecureEnvelope, DomainID: desktop.enrollment.DomainID, MessageID: newUUID(), SessionID: oldID, SenderDeviceID: sender, RecipientDeviceID: recipient, PayloadType: payloadType, Nonce: iscpcrypto.Base64URL(randomBytes(12)), Route: envelope.Route{RelayID: "relay-test", TTLSeconds: 30, Priority: 5}, Ciphertext: iscpcrypto.Base64URL(raw)}
		frame, _ := json.Marshal(env)
		queues[recipient] = append(queues[recipient], frame)
	}
	appendOldHandshake("desktop", "gateway", session.TypeHello, oldDesktop.Hello)
	appendOldHandshake("desktop", "gateway", session.TypeReady, oldDesktopReady)
	appendOldHandshake("gateway", "desktop", session.TypeHello, oldBackend.Hello)
	appendOldHandshake("gateway", "desktop", session.TypeReady, oldBackendReady)
	appendOldEncrypted := func(state *session.State, payloadType string, value any) {
		raw, _ := json.Marshal(value)
		env, err := envelope.Encrypt(provider, state, newUUID(), payloadType, envelope.Route{RelayID: "relay-test", TTLSeconds: 30, Priority: 5}, raw)
		if err != nil {
			t.Fatal(err)
		}
		frame, _ := json.Marshal(env)
		queues[env.RecipientDeviceID] = append(queues[env.RecipientDeviceID], frame)
	}
	appendOldEncrypted(oldDesktopState, manifestType, capabilityManifest{Profile: Profile, Role: RoleInitiator, Operations: Operations(), MaxRequestBytes: MaxRequestBytes, MaxResponseBytes: MaxResponseBytes, MaxConcurrent: MaxConcurrent})
	appendOldEncrypted(oldDesktopState, RequestType, Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity})
	appendOldEncrypted(oldBackendState, pingType, map[string]string{"nonce": newUUID()})
	appendOldEncrypted(oldBackendState, ResponseType, Response{Type: ResponseType, Profile: Profile, ID: newUUID(), Status: 200})
	clientRelay, err := iscpbridge.NewRelayCredentialClient(profile, filepath.Join(t.TempDir(), "desktop-enrollment.json"), desktop.enrollment, desktop.device, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	serverRelay, err := iscpbridge.NewRelayCredentialClient(profile, filepath.Join(t.TempDir(), "backend-enrollment.json"), backend.enrollment, backend.device, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{}, 2)
	var disconnected atomic.Int32
	state := func(value string) {
		if value == "transport_ready" {
			ready <- struct{}{}
		}
		if value == "disconnected" {
			disconnected.Add(1)
		}
	}
	client, err := newEndpoint(Config{Role: RoleInitiator, RelayProfile: profile}, desktop, clientRelay, nil, state)
	if err != nil {
		t.Fatal(err)
	}
	var handlerCalls atomic.Int32
	responder, err := newEndpoint(Config{Role: RoleResponder, RelayProfile: profile, Mode: "node-managed"}, backend, serverRelay, func(context.Context, Request) Response {
		handlerCalls.Add(1)
		return Response{Status: 200, Body: json.RawMessage(`{"retained":true}`)}
	}, state)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	done := make(chan struct{}, 2)
	go func() { _ = client.Run(ctx); done <- struct{}{} }()
	go func() { _ = responder.Run(ctx); done <- struct{}{} }()
	defer func() {
		cancel()
		_ = client.Close()
		_ = responder.Close()
		for range 2 {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("continuous receive endpoint leaked")
			}
		}
	}()
	for range 2 {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal("continuous handshake never completed")
		}
	}
	if handlerCalls.Load() != 0 {
		t.Fatal("retired queue request reached the restarted responder")
	}
	client.mu.Lock()
	sessionID := client.session.id
	client.mu.Unlock()
	response, err := client.Call(ctx, Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity})
	if err != nil || response.Status != 200 || string(response.Body) != `{"retained":true}` {
		t.Fatalf("encrypted continuous RPC: %+v %v", response, err)
	}
	client.mu.Lock()
	retained := client.session != nil && client.session.id == sessionID && client.session.manifest
	client.mu.Unlock()
	if !retained || disconnected.Load() != 0 || polls.Load() != 2 || proofs.Load() != 2 || posts.Load() < 8 || handlerCalls.Load() != 1 {
		t.Fatalf("session lost across continuous receive: retained=%v disconnected=%d polls=%d proofs=%d posts=%d", retained, disconnected.Load(), polls.Load(), proofs.Load(), posts.Load())
	}
}
