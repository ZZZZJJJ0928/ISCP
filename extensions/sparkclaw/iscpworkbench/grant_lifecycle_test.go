package iscpworkbench

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscplocalissuer"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

func lifecycleFixture(t *testing.T) (*iscplocalissuer.Issuer, Config, Config, trust.Grant) {
	t.Helper()
	d, b := testMaterials(t)
	dPath, bPath := writeFixtureConfig(t, d, RoleInitiator), writeFixtureConfig(t, b, RoleResponder)
	dCfg, err := LoadConfig(dPath)
	if err != nil {
		t.Fatal(err)
	}
	bCfg, err := LoadConfig(bPath)
	if err != nil {
		t.Fatal(err)
	}
	issuerDirectory := filepath.Join(t.TempDir(), "issuer")
	if _, err := iscplocalissuer.Initialize(issuerDirectory, filepath.Join(dCfg.IdentityDirectory, iscpbridge.IdentityFileName), filepath.Join(bCfg.IdentityDirectory, iscpbridge.IdentityFileName), d.enrollment.RelayID); err != nil {
		t.Fatal(err)
	}
	i, err := iscplocalissuer.Load(filepath.Join(issuerDirectory, "issuer.json"))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := i.Sign(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var issuer identity.DeviceIdentity
	if err := readJSONFile(filepath.Join(issuerDirectory, "issuer.identity.json"), &issuer, false); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []Config{dCfg, bCfg} {
		raw, _ := json.Marshal(issuer)
		if err := os.WriteFile(cfg.IssuerIdentityFile, raw, 0600); err != nil {
			t.Fatal(err)
		}
		raw, _ = json.Marshal(grant)
		if err := os.WriteFile(cfg.GrantFile, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := i.AuthorizeRenewal(dCfg.GrantFile, 24); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(i.Handler())
	t.Cleanup(server.Close)
	for _, cfg := range []*Config{&dCfg, &bCfg} {
		cfg.GrantRenewal = &GrantRenewalConfig{URL: server.URL, PendingFile: filepath.Join(cfg.IdentityDirectory, "renewal.pending.json"), PollIntervalSeconds: 1}
	}
	return i, dCfg, bCfg, grant
}

func TestAutomaticRenewalKeepsBusinessAcrossExpiryAndUsesFreshGrantAfterReconnect(t *testing.T) {
	i, dCfg, bCfg, original := lifecycleFixture(t)
	bus := &testRelayBus{peers: map[string]*testRelay{}}
	d := &testRelay{bus: bus, inbox: make(chan json.RawMessage, 128), disrupt: make(chan struct{}, 1)}
	b := &testRelay{bus: bus, inbox: make(chan json.RawMessage, 128), disrupt: make(chan struct{}, 1)}
	bus.peers["desktop"] = d
	bus.peers["gateway"] = b
	var calls atomic.Int32
	initiator, err := NewEndpointWithRelay(dCfg, d, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewEndpointWithRelay(bCfg, b, func(context.Context, Request) Response {
		calls.Add(1)
		return Response{Status: 200, Body: json.RawMessage(`{"ok":true}`)}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
				t.Error("renewing endpoint did not stop")
			}
		}
	})
	waitReady(t, initiator)
	waitReady(t, responder)
	call := func() {
		t.Helper()
		response, err := initiator.Call(ctx, Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity})
		if err != nil || response.Status != 200 {
			t.Fatalf("renewing business call failed: status=%d err=%v", response.Status, err)
		}
	}
	call()
	initiator.mu.Lock()
	sessionID := initiator.session.id
	initiator.mu.Unlock()
	if delay := time.Until(original.ExpiresAt.Add(300 * time.Millisecond)); delay > 0 {
		time.Sleep(delay)
	}
	call()
	for _, e := range []*Endpoint{initiator, responder} {
		grant := e.grantMaterial().grant
		if grant.GrantID == original.GrantID || !grant.ExpiresAt.After(original.ExpiresAt) {
			t.Fatal("grant was not renewed before original expiry")
		}
		var saved trust.Grant
		if err := readJSONFile(e.config.GrantFile, &saved, true); err != nil || saved.Signature.Value != grant.Signature.Value {
			t.Fatal("renewed authorization was not persisted")
		}
	}
	initiator.mu.Lock()
	sameSession := initiator.session != nil && initiator.session.id == sessionID
	initiator.mu.Unlock()
	if !sameSession {
		t.Fatal("renewal needlessly discarded active session")
	}
	d.disrupt <- struct{}{}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		initiator.mu.Lock()
		fresh := initiator.session != nil && initiator.session.manifest && initiator.session.id != sessionID
		initiator.mu.Unlock()
		if fresh {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	waitReady(t, initiator)
	call()
	bus.mu.Lock()
	var hello session.Hello
	for _, env := range bus.envelopes {
		if env.PayloadType == session.TypeHello && env.SenderDeviceID == "desktop" {
			_ = handshakeDecode(env, &hello)
		}
	}
	bus.mu.Unlock()
	if hello.GrantID == original.GrantID || hello.SessionID == sessionID {
		t.Fatal("reconnect did not bind renewed Grant")
	}
	if err := i.RevokeRenewal(); err != nil {
		t.Fatal(err)
	}
	expires := initiator.grantMaterial().grant.ExpiresAt
	if delay := time.Until(expires.Add(300 * time.Millisecond)); delay > 0 {
		time.Sleep(delay)
	}
	if _, err := initiator.Call(ctx, Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity}); err == nil {
		t.Fatal("business continued after expiry with revoked renewal authority")
	}
	if calls.Load() != 3 {
		t.Fatalf("unexpected repeated business admission: %d", calls.Load())
	}
}

func TestExpiredSeedOnlyBootstrapsWithExplicitRenewalAndStillFailsAdmission(t *testing.T) {
	_, cfg, _, grant := lifecycleFixture(t)
	// Wait for the genuinely signed seed to expire; configuration accepts it
	// only as lifecycle input. No synthetic timestamp is trusted as a Grant.
	if delay := time.Until(grant.ExpiresAt); delay > 0 {
		time.Sleep(delay)
	}
	if _, err := loadMaterial(cfg); err != nil {
		t.Fatal("explicit lifecycle could not load expired signed seed")
	}
	without := cfg
	without.GrantRenewal = nil
	if _, err := loadMaterial(without); err == nil {
		t.Fatal("expired Grant accepted without explicit lifecycle")
	}
	m, err := loadMaterial(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if verifyGrant(cfg, m, time.Now().UTC()) == nil {
		t.Fatal("expired bootstrap seed authorized business")
	}
	bad := cfg
	copyRenewal := *cfg.GrantRenewal
	bad.GrantRenewal = &copyRenewal
	bad.GrantRenewal.URL = "http://210.16.177.239:8080"
	if bad.Validate() == nil {
		t.Fatal("arbitrary insecure public renewal endpoint accepted")
	}
}

func TestPermanentRevocationStopsInflightAndFutureBusinessBeforeGrantExpiry(t *testing.T) {
	i, dCfg, bCfg, original := lifecycleFixture(t)
	if err := i.AuthorizePermanentRenewal(dCfg.GrantFile); err != nil {
		t.Fatal(err)
	}
	dCfg.GrantRenewal.AuthorizationLifetime = iscpauth.UntilRevoked
	bCfg.GrantRenewal.AuthorizationLifetime = iscpauth.UntilRevoked
	bus := &testRelayBus{peers: map[string]*testRelay{}}
	d := &testRelay{bus: bus, inbox: make(chan json.RawMessage, 128), disrupt: make(chan struct{}, 1)}
	b := &testRelay{bus: bus, inbox: make(chan json.RawMessage, 128), disrupt: make(chan struct{}, 1)}
	bus.peers["desktop"], bus.peers["gateway"] = d, b
	started, canceled := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	initiator, err := NewEndpointWithRelay(dCfg, d, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewEndpointWithRelay(bCfg, b, func(ctx context.Context, _ Request) Response {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		close(canceled)
		return Response{Status: 200, Body: json.RawMessage(`{"private":"result"}`)}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
			case <-time.After(time.Second):
				t.Error("revoked endpoint did not stop")
			}
		}
	})
	waitReady(t, initiator)
	waitReady(t, responder)
	result := make(chan error, 1)
	go func() {
		_, err := initiator.Call(ctx, Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity})
		result <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("handler not admitted")
	}
	if err := i.RevokeRenewal(); err != nil {
		t.Fatal(err)
	}
	if err := responder.refreshAuthorization(ctx); !errors.Is(err, iscpbridge.ErrAuthorizationRevoked) {
		t.Fatalf("revocation not detected: %v", err)
	}
	select {
	case <-canceled:
	case <-ctx.Done():
		t.Fatal("inflight handler survived revocation")
	}
	if err := initiator.checkAuthorization(ctx); !errors.Is(err, iscpbridge.ErrAuthorizationRevoked) {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("business result returned after revocation")
	}
	if !time.Now().Before(original.ExpiresAt) {
		t.Fatal("test did not exercise still-valid Grant")
	}
	if _, err := initiator.Call(ctx, Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity}); err == nil {
		t.Fatal("new call admitted after deletion")
	}
	for _, endpoint := range []*Endpoint{initiator, responder} {
		endpoint.mu.Lock()
		state := endpoint.stateName
		endpoint.mu.Unlock()
		if state != "authorization_revoked" {
			t.Fatalf("signed revocation overwritten: %s", state)
		}
	}
	restarted, err := NewEndpointWithRelay(dCfg, d, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.checkAuthorization(context.Background()); !errors.Is(err, iscpbridge.ErrAuthorizationRevoked) {
		t.Fatalf("restart restored deleted consent: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("execution repeated")
	}
}
