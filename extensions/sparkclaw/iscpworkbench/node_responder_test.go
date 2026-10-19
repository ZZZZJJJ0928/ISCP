package iscpworkbench

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
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

type countReceiveRelay struct {
	*testRelay
	calls atomic.Int32
}

func (r *countReceiveRelay) RunOnceReady(ctx context.Context, handler func(context.Context, json.RawMessage) error, ready func()) error {
	r.calls.Add(1)
	return r.testRelay.RunOnceReady(ctx, handler, ready)
}

func TestNodeResponderTwoPeersIsolationRenewalAndRevocation(t *testing.T) {
	provider := iscpcrypto.NewProvider()
	now := time.Now().UTC()
	first, backend := testMaterials(t)
	secondDevice, err := identity.NewDevice(provider, first.device.Identity.DomainID, "desktop-second", now)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := identity.NewDevice(provider, first.device.Identity.DomainID, "node-issuer", now)
	if err != nil {
		t.Fatal(err)
	}
	grant := func(d identity.Device) trust.Grant {
		g, e := trust.SignGrant(provider, issuer, trust.Grant{GrantID: newUUID(), RevocationEpoch: 1, SubjectDeviceID: d.Identity.DeviceID, Audience: backend.device.Identity.DeviceID, ConfirmationThumbprint: d.Identity.PublicKey.KID, Permissions: []string{Permission}, RelayConstraints: []string{"relay-test"}, NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Hour)})
		if e != nil {
			t.Fatal(e)
		}
		return g
	}
	first.issuer = issuer.Identity
	first.grant = grant(first.device)
	second := first
	second.device = secondDevice
	second.grant = grant(secondDevice)
	second.enrollment.DeviceID = secondDevice.Identity.DeviceID
	second.enrollment.Access.DeviceID = secondDevice.Identity.DeviceID
	second.enrollment.Refresh.DeviceID = secondDevice.Identity.DeviceID
	backend.issuer = issuer.Identity
	directory := t.TempDir()
	_ = os.Chmod(directory, 0700)
	registryPath := filepath.Join(directory, "peers.json")
	registry := PeerRegistry{SchemaVersion: 1, DeploymentID: "node-deployment", Peers: []ManagedPeer{
		{Identity: first.device.Identity, Grant: first.grant, Binding: Binding{"node-deployment", "owner-a", "client-a"}, InstallationID: newUUID(), AuthorizationRevision: 1, Scopes: []string{"workbench.read"}},
		{Identity: second.device.Identity, Grant: second.grant, Binding: Binding{"node-deployment", "owner-b", "client-b"}, InstallationID: newUUID(), AuthorizationRevision: 1, Scopes: []string{"workbench.read"}},
	}}
	write := func() {
		raw, _ := json.Marshal(registry)
		temp := registryPath + ".next"
		if err := os.WriteFile(temp, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(temp, registryPath); err != nil {
			t.Fatal(err)
		}
	}
	write()
	bus := &testRelayBus{peers: map[string]*testRelay{}}
	newRelay := func(id string) *testRelay {
		r := &testRelay{bus: bus, inbox: make(chan json.RawMessage, 128), disrupt: make(chan struct{}, 1)}
		bus.peers[id] = r
		return r
	}
	r1 := newRelay(first.device.Identity.DeviceID)
	r2 := newRelay(second.device.Identity.DeviceID)
	rb := &countReceiveRelay{testRelay: newRelay(backend.device.Identity.DeviceID)}
	var validated atomic.Int32
	factory := func(cfg Config) (Handler, error) {
		b := *cfg.Binding
		return func(ctx context.Context, r Request) Response {
			info, ok := SessionFromContext(ctx)
			if !ok || info.Binding == nil || *info.Binding != b {
				t.Error("peer binding crossed handler")
			}
			return Response{Status: 200, Body: json.RawMessage(`{"client_id":"` + b.ClientID + `"}`)}
		}, nil
	}
	node, err := newNodeResponder(Config{SchemaVersion: 2, Mode: "node-managed", Role: RoleResponder, RelayProfile: iscpbridge.ProfileProduction, PeerRegistryFile: registryPath}, backend, rb, factory, func(ctx context.Context, p ManagedPeer) error { validated.Add(1); return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	node.verifyDiscovery = nil
	d1, err := newEndpoint(Config{Role: RoleInitiator}, first, r1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := newEndpoint(Config{Role: RoleInitiator}, second, r2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var done sync.WaitGroup
	for _, run := range []func(context.Context) error{node.Run, d1.Run, d2.Run} {
		done.Add(1)
		go func(run func(context.Context) error) { defer done.Done(); _ = run(ctx) }(run)
	}
	t.Cleanup(func() { cancel(); _ = node.Close(); _ = d1.Close(); _ = d2.Close(); done.Wait() })
	waitReady(t, d1)
	waitReady(t, d2)
	call := func(e *Endpoint, want string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		out, err := e.Call(ctx, Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity})
		if err != nil || out.Status != 200 || string(out.Body) != `{"client_id":"`+want+`"}` {
			t.Fatalf("isolated call: %+v %v", out, err)
		}
	}
	call(d1, "client-a")
	call(d2, "client-b")
	if rb.calls.Load() != 1 {
		t.Fatalf("shared receive owners: %d", rb.calls.Load())
	}
	d2.mu.Lock()
	secondSession := d2.session.id
	d2.mu.Unlock()
	// A forged header naming peer two must not cancel its already authenticated
	// session. Its inner Hello was signed by peer one and is rejected.
	hello, e := session.CreateHello(provider, first.device, newUUID(), backend.device.Identity.DeviceID, second.grant.GrantID, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	rawHello, _ := json.Marshal(hello.Hello)
	forged := envelope.SecureEnvelope{Type: envelope.TypeSecureEnvelope, DomainID: first.device.Identity.DomainID, MessageID: newUUID(), SessionID: hello.Hello.SessionID, SenderDeviceID: secondDevice.Identity.DeviceID, RecipientDeviceID: backend.device.Identity.DeviceID, PayloadType: session.TypeHello, Route: envelope.Route{RelayID: "relay-test", TTLSeconds: 30}, Ciphertext: base64.RawURLEncoding.EncodeToString(rawHello)}
	raw, _ := json.Marshal(forged)
	if err = node.receive(ctx, raw); err != nil {
		t.Fatal(err)
	}
	call(d2, "client-b")
	d2.mu.Lock()
	if d2.session.id != secondSession {
		t.Error("forged peer header canceled valid peer session")
	}
	d2.mu.Unlock()
	// Updating peer one's signed Grant leaves peer two's keys, pending calls and
	// responder identity/queue owner untouched.
	registry.Peers[0].Grant = grant(first.device)
	write()
	if err = node.syncPeers(ctx); err != nil {
		t.Fatal(err)
	}
	call(d2, "client-b")
	registry.Peers[0].Revoked = true
	registry.Peers[0].AuthorizationRevision = 2
	write()
	if err = node.syncPeers(ctx); err != nil {
		t.Fatal(err)
	}
	node.mu.Lock()
	revoked := node.peers[first.device.Identity.DeviceID]
	other := node.peers[second.device.Identity.DeviceID]
	node.mu.Unlock()
	if revoked != nil || other == nil {
		t.Fatal("revoke crossed isolated peer state")
	}
	call(d2, "client-b")
	d2.mu.Lock()
	if d2.session.id != secondSession {
		t.Error("peer revoke restarted other session")
	}
	d2.mu.Unlock()
	if validated.Load() < 6 {
		t.Error("live authority was not checked on calls/results")
	}
}

func TestNodeRegistryRejectsWrongPeerGrantAndAuthorityRegression(t *testing.T) {
	first, backend := testMaterials(t)
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	path := filepath.Join(dir, "registry.json")
	r := PeerRegistry{1, "deployment", []ManagedPeer{{Identity: first.device.Identity, Grant: first.grant, Binding: Binding{"deployment", "owner", "client"}, InstallationID: newUUID(), AuthorizationRevision: 1, Scopes: []string{"workbench.read"}}}}
	write := func() {
		raw, _ := json.Marshal(r)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	n := &NodeResponder{config: Config{PeerRegistryFile: path, Role: RoleResponder}, material: backend}
	if _, err := n.registry(); err != nil {
		t.Fatal(err)
	}
	r.Peers[0].Grant.SubjectDeviceID = "another-device"
	write()
	if _, err := n.registry(); err == nil {
		t.Fatal("wrong Grant subject accepted")
	}
	r.Peers[0].Grant = first.grant
	r.Peers[0].AuthorizationRevision = 2
	write()
	if _, err := n.registry(); err == nil {
		t.Fatal("unsigned active revision accepted")
	}
	r.Peers[0].Revoked = true
	write()
	if _, err := n.registry(); err != nil {
		t.Fatal("durable newer revoke tombstone rejected", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := n.registry(); err == nil {
		t.Fatal("nonprivate registry accepted")
	}
}
