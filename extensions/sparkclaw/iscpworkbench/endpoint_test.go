package iscpworkbench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
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
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

type testRelayBus struct {
	mu           sync.Mutex
	peers        map[string]*testRelay
	envelopes    []envelope.SecureEnvelope
	beforeSubmit func(context.Context, envelope.SecureEnvelope) error
}

type testRelay struct {
	bus     *testRelayBus
	inbox   chan json.RawMessage
	disrupt chan struct{}
}

func (r *testRelay) Submit(ctx context.Context, value any) error {
	env, ok := value.(envelope.SecureEnvelope)
	if !ok {
		return errors.New("expected SDK envelope")
	}
	r.bus.mu.Lock()
	hook := r.bus.beforeSubmit
	r.bus.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, env); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	r.bus.mu.Lock()
	peer := r.bus.peers[env.RecipientDeviceID]
	r.bus.envelopes = append(r.bus.envelopes, env)
	r.bus.mu.Unlock()
	if peer == nil {
		return errors.New("unknown peer")
	}
	select {
	case peer.inbox <- raw:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *testRelay) RunOnceReady(ctx context.Context, handle func(context.Context, json.RawMessage) error, onReady func()) error {
	onReady()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.disrupt:
			return errors.New("local connection interrupted")
		case raw := <-r.inbox:
			if err := handle(ctx, raw); err != nil {
				return err
			}
		}
	}
}

func testMaterials(t *testing.T) (material, material) {
	t.Helper()
	provider := iscpcrypto.NewProvider()
	now := time.Now().UTC()
	desktop, err := identity.NewDevice(provider, "domain-local-test", "desktop", now)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := identity.NewDevice(provider, "domain-local-test", "gateway", now)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := identity.NewDevice(provider, "issuer-local-test", "issuer", now)
	if err != nil {
		t.Fatal(err)
	}
	cloud, err := identity.NewDevice(provider, "cloud", "cloud-root", now)
	if err != nil {
		t.Fatal(err)
	}
	cloud.Identity.PublicKey.KID = "cloud-trust-prod-1"
	thumbprint, _ := identity.Thumbprint(desktop.Identity)
	grant, err := trust.SignGrant(provider, issuer, trust.Grant{GrantID: newUUID(), RevocationEpoch: 1, SubjectDeviceID: desktop.Identity.DeviceID, Audience: backend.Identity.DeviceID, ConfirmationThumbprint: thumbprint, Permissions: []string{Permission}, RelayConstraints: []string{"relay-test"}, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	bundle := func(device identity.Device) iscpbridge.EnrollmentBundle {
		return iscpbridge.EnrollmentBundle{Type: iscpbridge.EnrollmentBundleType, DomainID: device.Identity.DomainID, DeviceID: device.Identity.DeviceID, RelayID: "relay-test", RelayBaseURL: "https://relay.invalid", RelayWebSocketURL: "wss://relay.invalid/v1/receive", TrustRootIdentity: cloud.Identity, Access: iscpbridge.RelayCredential{DomainID: device.Identity.DomainID, DeviceID: device.Identity.DeviceID, Token: "fixture-access", ExpiresAt: now.Add(time.Hour)}, Refresh: iscpbridge.RelayCredential{DomainID: device.Identity.DomainID, DeviceID: device.Identity.DeviceID, Token: "fixture-refresh", ExpiresAt: now.Add(2 * time.Hour)}, IssuedAt: now, ExpiresAt: now.Add(2 * time.Hour)}
	}
	return material{device: desktop, peer: backend.Identity, issuer: issuer.Identity, grant: grant, enrollment: bundle(desktop)}, material{device: backend, peer: desktop.Identity, issuer: issuer.Identity, grant: grant, enrollment: bundle(backend)}
}

func testEndpoints(t *testing.T, handler Handler) (*Endpoint, *Endpoint, *testRelayBus, *testRelay) {
	t.Helper()
	desktop, backend := testMaterials(t)
	bus := &testRelayBus{peers: map[string]*testRelay{}}
	d := &testRelay{bus: bus, inbox: make(chan json.RawMessage, 128), disrupt: make(chan struct{}, 1)}
	b := &testRelay{bus: bus, inbox: make(chan json.RawMessage, 128), disrupt: make(chan struct{}, 1)}
	bus.peers[desktop.device.Identity.DeviceID] = d
	bus.peers[backend.device.Identity.DeviceID] = b
	initiator, err := newEndpoint(Config{Role: RoleInitiator}, desktop, d, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := newEndpoint(Config{Role: RoleResponder}, backend, b, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 2)
	go func() { _ = responder.Run(ctx); done <- struct{}{} }()
	go func() { _ = initiator.Run(ctx); done <- struct{}{} }()
	t.Cleanup(func() {
		cancel()
		_ = initiator.Close()
		_ = responder.Close()
		for range 2 {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("endpoint did not stop")
			}
		}
	})
	waitReady(t, initiator)
	waitReady(t, responder)
	return initiator, responder, bus, d
}

func waitReady(t *testing.T, e *Endpoint) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		ready := e.session != nil && e.session.manifest && !e.session.negotiating
		e.mu.Unlock()
		if ready {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.mu.Lock()
	state := e.stateName
	e.mu.Unlock()
	t.Fatalf("endpoint never ready: %s", state)
}

func TestEncryptedDesktopFirstHandshakeAndExactBody(t *testing.T) {
	body := json.RawMessage("{\n  \"text\" : \"private-body\", \"other\": true\n}")
	var calls atomic.Int32
	initiator, _, bus, _ := testEndpoints(t, func(ctx context.Context, request Request) Response {
		calls.Add(1)
		if !bytes.Equal(request.Body, body) {
			t.Errorf("original body changed: %s", request.Body)
		}
		return Response{Status: 200, Body: json.RawMessage(`{"ok":true}`)}
	})
	response, err := initiator.Call(context.Background(), Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity, Body: body})
	if err != nil || response.Status != 200 || string(response.Body) != `{"ok":true}` {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("handler calls=%d", calls.Load())
	}
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if bus.envelopes[0].PayloadType != session.TypeHello || bus.envelopes[0].SenderDeviceID != "desktop" {
		t.Fatal("SparkX did not send the first Hello")
	}
	var hello session.Hello
	raw, _ := iscpcrypto.DecodeBase64URL(bus.envelopes[0].Ciphertext)
	if json.Unmarshal(raw, &hello) != nil || hello.GrantID == "" {
		t.Fatal("initiating Hello has no pinned grant")
	}
	manifestCount, businessCount := 0, 0
	for _, env := range bus.envelopes {
		if env.PayloadType == manifestType {
			manifestCount++
		}
		if env.PayloadType == RequestType || env.PayloadType == ResponseType {
			businessCount++
		}
		if env.PayloadType == RequestType && strings.Contains(env.Ciphertext, "private-body") {
			t.Fatal("plaintext request reached Relay")
		}
	}
	// One safe RPC-policy negotiation precedes the original business request.
	if manifestCount != 2 || businessCount != 4 {
		t.Fatalf("manifests=%d business=%d", manifestCount, businessCount)
	}
}

func TestGrantBindingsFailClosed(t *testing.T) {
	desktop, backend := testMaterials(t)
	if err := verifyGrant(Config{Role: RoleInitiator}, desktop, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := verifyGrant(Config{Role: RoleResponder}, backend, time.Now()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*material){
		"issuer":           func(m *material) { m.grant.Issuer = "attacker" },
		"kid":              func(m *material) { m.grant.Signature.KID = "attacker-key" },
		"audience":         func(m *material) { m.grant.Audience = "other" },
		"subject":          func(m *material) { m.grant.SubjectDeviceID = "other" },
		"thumbprint":       func(m *material) { m.grant.ConfirmationThumbprint = "other" },
		"permission":       func(m *material) { m.grant.Permissions = []string{"other"} },
		"extra_permission": func(m *material) { m.grant.Permissions = []string{Permission, "admin"} },
		"relay":            func(m *material) { m.grant.RelayConstraints = []string{"other"} },
		"expiry":           func(m *material) { m.grant.ExpiresAt = time.Now().Add(-time.Minute) },
		"signature":        func(m *material) { m.grant.Signature.Value = iscpcrypto.Base64URL(make([]byte, 64)) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := desktop
			mutate(&m)
			if verifyGrant(Config{Role: RoleInitiator}, m, time.Now()) == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
	if verifyGrant(Config{Role: RoleResponder}, desktop, time.Now()) == nil {
		t.Fatal("initiator identity accepted as responder")
	}
}

func TestReplayManifestGatingAndDirections(t *testing.T) {
	var calls atomic.Int32
	initiator, responder, bus, _ := testEndpoints(t, func(context.Context, Request) Response { calls.Add(1); return Response{Status: 200} })
	request := Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity}
	if _, err := initiator.Call(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	bus.mu.Lock()
	var submitted envelope.SecureEnvelope
	for _, env := range bus.envelopes {
		if env.PayloadType == RequestType {
			submitted = env
			break
		}
	}
	bus.mu.Unlock()
	raw, _ := json.Marshal(submitted)
	if responder.receive(context.Background(), raw) == nil {
		t.Fatal("SDK envelope replay accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("replay reached business handler")
	}
	if _, err := responder.Call(context.Background(), request); err == nil {
		t.Fatal("responder initiated a business call")
	}
	responder.mu.Lock()
	responder.session.manifest = false
	responder.mu.Unlock()
	if responder.receive(context.Background(), raw) == nil {
		t.Fatal("business payload passed manifest gate")
	}
	responder.mu.Lock()
	responder.session.manifest = true
	responder.mu.Unlock()
	wrong := capabilityManifest{Profile: Profile, Role: RoleResponder, Operations: Operations(), MaxRequestBytes: MaxRequestBytes, MaxResponseBytes: MaxResponseBytes, MaxConcurrent: MaxConcurrent}
	manifest, _ := json.Marshal(wrong)
	if responder.acceptManifest(manifest, submitted.SessionID) == nil {
		t.Fatal("same-role manifest accepted")
	}
}

func TestFreshHandshakeAfterLocalRelayConnectionLoss(t *testing.T) {
	initiator, _, bus, desktopRelay := testEndpoints(t, func(context.Context, Request) Response { return Response{Status: 200} })
	initiator.mu.Lock()
	oldID := initiator.session.id
	initiator.mu.Unlock()
	desktopRelay.disrupt <- struct{}{}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		initiator.mu.Lock()
		fresh := initiator.session != nil && initiator.session.manifest && initiator.session.id != oldID
		initiator.mu.Unlock()
		if fresh {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	initiator.mu.Lock()
	if initiator.session == nil || !initiator.session.manifest || initiator.session.id == oldID {
		initiator.mu.Unlock()
		t.Fatal("no fresh session after connection loss")
	}
	initiator.mu.Unlock()
	if _, err := initiator.Call(context.Background(), Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity}); err != nil {
		t.Fatal(err)
	}
	bus.mu.Lock()
	defer bus.mu.Unlock()
	hellos := 0
	for _, env := range bus.envelopes {
		if env.PayloadType == session.TypeHello && env.SenderDeviceID == "desktop" {
			hellos++
		}
	}
	if hellos < 2 {
		t.Fatal("reconnect reused old session instead of fresh desktop Hello")
	}
}

func TestRequestAndResponseCaps(t *testing.T) {
	initiator, _, _, _ := testEndpoints(t, func(context.Context, Request) Response {
		return Response{Status: 200, Body: json.RawMessage(`"` + strings.Repeat("x", MaxResponseBytes) + `"`)}
	})
	request := Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity}
	response, err := initiator.Call(context.Background(), request)
	if err != nil || response.Status != 413 || len(response.Body) != 0 {
		t.Fatalf("oversized response=%+v err=%v", response, err)
	}
	request.ID = newUUID()
	request.Body = json.RawMessage(`"` + strings.Repeat("x", MaxRequestBytes) + `"`)
	if _, err := initiator.Call(context.Background(), request); err == nil {
		t.Fatal("oversized request accepted")
	}
	request.ID = newUUID()
	request.Body = nil
	request.Operation = "arbitrary.http.url"
	if _, err := initiator.Call(context.Background(), request); err == nil {
		t.Fatal("arbitrary operation accepted")
	}
}

func TestLegacyConcurrentCallsBoundedAndCloseCancelsHandlers(t *testing.T) {
	entered := make(chan struct{}, MaxConcurrent)
	stopped := make(chan struct{}, MaxConcurrent)
	initiator, responder, _, _ := testEndpoints(t, func(ctx context.Context, request Request) Response {
		entered <- struct{}{}
		<-ctx.Done()
		stopped <- struct{}{}
		return Response{Status: 500}
	})
	for _, e := range []*Endpoint{initiator, responder} {
		e.mu.Lock()
		e.session.capabilities.Limits.Concurrent = MaxConcurrent
		e.mu.Unlock()
	}
	results := make(chan error, MaxConcurrent)
	for range MaxConcurrent {
		go func() {
			_, err := initiator.Call(context.Background(), Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity})
			results <- err
		}()
	}
	for range MaxConcurrent {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("bounded call did not reach handler")
		}
	}
	if _, err := initiator.Call(context.Background(), Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity}); err == nil {
		t.Fatal("fifth concurrent call was admitted")
	}
	_ = responder.Close()
	_ = initiator.Close()
	for range MaxConcurrent {
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Fatal("session close did not cancel handler")
		}
		select {
		case err := <-results:
			if err == nil {
				t.Fatal("pending call succeeded after close")
			}
		case <-time.After(time.Second):
			t.Fatal("pending call leaked")
		}
	}
}

func writeFixtureConfig(t *testing.T, m material, role string) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, value any) {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(iscpbridge.IdentityFileName, m.device.Identity)
	if err := os.WriteFile(filepath.Join(directory, iscpbridge.IdentityKeyFileName), []byte(iscpcrypto.Base64URL(m.device.Private.BytesForDevStore())), 0600); err != nil {
		t.Fatal(err)
	}
	write("enrollment.json", m.enrollment)
	write("peer.json", m.peer)
	write("issuer.json", m.issuer)
	write("grant.json", m.grant)
	write("profile.json", Config{SchemaVersion: 1, Mode: "local-test", Role: role, IdentityDirectory: ".", IdentityKeyBackend: "file", EnrollmentFile: "enrollment.json", PeerIdentityFile: "peer.json", IssuerIdentityFile: "issuer.json", GrantFile: "grant.json"})
	return filepath.Join(directory, "profile.json")
}

func TestLoadConfigPrivatePinsAndHostedURLs(t *testing.T) {
	desktop, _ := testMaterials(t)
	path := writeFixtureConfig(t, desktop, RoleInitiator)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(cfg.EnrollmentFile) {
		t.Fatal("relative profile paths not resolved")
	}
	if _, err := NewEndpoint(cfg, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("public configuration accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	desktop.enrollment.RelayBaseURL = "http://localhost:1234"
	desktop.enrollment.RelayWebSocketURL = "ws://localhost:1234"
	badPath := writeFixtureConfig(t, desktop, RoleInitiator)
	if _, err := LoadConfig(badPath); err == nil {
		t.Fatal("insecure runtime profile accepted")
	}
	desktop, _ = testMaterials(t)
	desktop.peer.PublicKey.KID = "wrong-key"
	badPath = writeFixtureConfig(t, desktop, RoleInitiator)
	if _, err := LoadConfig(badPath); err == nil {
		t.Fatal("malformed pinned key accepted")
	}
}

func TestExplicitLocalLabConfigUsesRelaySignerWithoutCloudRoot(t *testing.T) {
	desktop, _ := testMaterials(t)
	signer, err := identity.NewDevice(iscpcrypto.NewProvider(), desktop.device.Identity.DomainID, "relay-test-signer", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	desktop.enrollment.Mode = iscpbridge.BundleModeWorkbenchLocalLab
	desktop.enrollment.TrustRootIdentity = identity.DeviceIdentity{}
	desktop.enrollment.RelaySignerIdentity = &signer.Identity
	desktop.enrollment.RelayBaseURL = "http://127.0.0.1:18180"
	desktop.enrollment.RelayWebSocketURL = "ws://127.0.0.1:18180/v2/relay/connect"
	path := writeFixtureConfig(t, desktop, RoleInitiator)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("local reference enrollment accepted without explicit local-lab Relay profile")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.RelayProfile = iscpbridge.ProfileLocalLab
	raw, _ = json.Marshal(cfg)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	public, err := cfg.PublicIdentity()
	if err != nil || public.RelayProfile != iscpbridge.ProfileLocalLab || public.RelayURL != desktop.enrollment.RelayBaseURL {
		t.Fatalf("public local identity: %+v %v", public, err)
	}
	endpoint, err := NewEndpoint(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = endpoint.Close()
	desktop.enrollment.RelayBaseURL = "http://192.168.1.11:18180"
	desktop.enrollment.RelayWebSocketURL = "ws://192.168.1.11:18180/v2/relay/connect"
	if validateEnrollment(desktop.enrollment, desktop.device.Identity, iscpbridge.ProfileLocalLab, time.Now()) == nil {
		t.Fatal("local-lab connected to a LAN host")
	}
}
