package iscpnodecontrol

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

type helloFixture struct {
	hub                         *hub
	agent, broker               *Peer
	agentHandler, brokerHandler Handler
	signer                      identity.Device
}

func newHelloFixture(t *testing.T) *helloFixture {
	t.Helper()
	a, b, signer := newDevice(t, "restart-agent"), newDevice(t, "restart-broker"), newDevice(t, "restart-issuer")
	now := time.Now().UTC()
	g, e := trust.SignGrant(c.NewProvider(), signer, trust.Grant{GrantID: "restart-control-grant", SubjectDeviceID: a.Identity.DeviceID, ConfirmationThumbprint: a.Identity.PublicKey.KID, Audience: b.Identity.DeviceID, Permissions: []string{ControlPermission}, RelayConstraints: []string{"relay"}, NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Hour), RevocationEpoch: 1})
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(t.TempDir(), "private")
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	handler := func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"ok":true}`), nil
	}
	f := &helloFixture{hub: &hub{queues: map[string][]json.RawMessage{}}, agentHandler: handler, brokerHandler: handler, signer: signer}
	raw, _ := json.Marshal(g)
	for _, which := range []string{"agent", "broker"} {
		if e = n.WritePrivateAtomic(filepath.Join(dir, which+".grant.json"), raw); e != nil {
			t.Fatal(e)
		}
	}
	f.agent, e = newPeer(PeerConfig{true, a, b.Identity, signer.Identity, g, "relay"}, queuedRelay{f.hub, a.Identity.DeviceID}, handler, true, true, filepath.Join(dir, "agent.grant.json"))
	if e != nil {
		t.Fatal(e)
	}
	f.broker, e = newPeer(PeerConfig{false, b, a.Identity, signer.Identity, g, "relay"}, queuedRelay{f.hub, b.Identity.DeviceID}, handler, true, true, filepath.Join(dir, "broker.grant.json"))
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func restartHelloPeer(t *testing.T, old *Peer, h *hub, handler Handler) *Peer {
	t.Helper()
	old.mu.Lock()
	cfg, file := old.cfg, old.grantFile
	old.mu.Unlock()
	p, e := newPeer(cfg, queuedRelay{h, cfg.Device.Identity.DeviceID}, handler, true, true, file)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func drainHello(t *testing.T, peers ...*Peer) {
	t.Helper()
	for _, p := range peers {
		if e := p.relay.RunOnceReady(t.Context(), p.receive, func() {}); e != nil {
			t.Fatal(e)
		}
	}
}
func driveHello(t *testing.T, f *helloFixture) {
	t.Helper()
	for i := 0; i < 20; i++ {
		for _, p := range []*Peer{f.agent, f.broker} {
			if e := p.begin(t.Context()); e != nil {
				t.Fatal(e)
			}
		}
		drainHello(t, f.agent, f.broker)
		if f.agent.Ready() && f.broker.Ready() {
			return
		}
	}
	t.Fatal("standard bilateral Hello/Ready failed")
}
func quietHello(t *testing.T, f *helloFixture) {
	t.Helper()
	for i := 0; i < 8; i++ {
		if e := f.agent.begin(t.Context()); e != nil {
			t.Fatal(e)
		}
		if e := f.broker.begin(t.Context()); e != nil {
			t.Fatal(e)
		}
		drainHello(t, f.agent, f.broker)
	}
	f.hub.mu.Lock()
	empty := len(f.hub.queues[f.agent.cfg.Device.Identity.DeviceID]) == 0 && len(f.hub.queues[f.broker.cfg.Device.Identity.DeviceID]) == 0
	count := len(f.hub.messages)
	f.hub.mu.Unlock()
	if !empty {
		t.Fatal("Hello/Ready retransmissions did not become quiet")
	}
	for i := 0; i < 10; i++ {
		f.agent.begin(t.Context())
		f.broker.begin(t.Context())
		drainHello(t, f.agent, f.broker)
	}
	f.hub.mu.Lock()
	defer f.hub.mu.Unlock()
	if len(f.hub.messages) != count {
		t.Fatal("healthy Ready session emitted periodic handshakes")
	}
}
func currentSession(p *Peer) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state == nil {
		return ""
	}
	return p.state.SessionID
}
func helloWire(t *testing.T, p *Peer, h session.Hello) json.RawMessage {
	t.Helper()
	raw, _ := json.Marshal(h)
	wire, _ := json.Marshal(envelope.SecureEnvelope{Type: envelope.TypeSecureEnvelope, DomainID: p.cfg.Peer.DomainID, SenderDeviceID: p.cfg.Peer.DeviceID, RecipientDeviceID: p.cfg.Device.Identity.DeviceID, SessionID: h.SessionID, PayloadType: session.TypeHello, Route: envelope.Route{RelayID: p.cfg.RelayID}, Ciphertext: c.Base64URL(raw)})
	return wire
}

func TestBrokerAloneIssuerAloneAndBothRestartRecoverStandardSession(t *testing.T) {
	f := newHelloFixture(t)
	driveHello(t, f)
	quietHello(t, f)
	first := currentSession(f.agent)
	f.broker = restartHelloPeer(t, f.broker, f.hub, f.brokerHandler)
	driveHello(t, f)
	quietHello(t, f)
	second := currentSession(f.agent)
	if second == first || second != currentSession(f.broker) {
		t.Fatal("broker restart kept stale session")
	}
	f.agent = restartHelloPeer(t, f.agent, f.hub, f.agentHandler)
	driveHello(t, f)
	quietHello(t, f)
	third := currentSession(f.agent)
	if third == second || third != currentSession(f.broker) {
		t.Fatal("issuer restart kept stale session")
	}
	f.agent = restartHelloPeer(t, f.agent, f.hub, f.agentHandler)
	f.broker = restartHelloPeer(t, f.broker, f.hub, f.brokerHandler)
	driveHello(t, f)
	quietHello(t, f)
	if currentSession(f.agent) == third || currentSession(f.agent) != currentSession(f.broker) {
		t.Fatal("simultaneous restart did not converge")
	}
}

func TestDuplicateHelloIsBoundedAndNeverResetsEncryptionSequence(t *testing.T) {
	f := newHelloFixture(t)
	driveHello(t, f)
	quietHello(t, f)
	f.agent.mu.Lock()
	original := f.agent.local.Hello
	f.agent.mu.Unlock()
	f.broker.mu.Lock()
	state := f.broker.state
	f.broker.mu.Unlock()
	// An exact replay can return only a bounded Ready response, without another
	// Hello ping-pong or a newly derived state with cleared anti-replay counters.
	before := len(f.hub.messages)
	if e := f.broker.receive(t.Context(), helloWire(t, f.broker, original)); e != nil {
		t.Fatal(e)
	}
	quietHello(t, f)
	f.broker.mu.Lock()
	same := f.broker.state == state
	f.broker.mu.Unlock()
	if !same || len(f.hub.messages)-before > 4 {
		t.Fatal("duplicate Hello reset state or caused an unbounded echo")
	}
	if e := f.broker.send(t.Context(), rpc{Version: 1, Kind: "request", ID: "sequence-probe-one", Method: "probe", Payload: json.RawMessage(`{}`)}); e != nil {
		t.Fatal(e)
	}
	first := f.hub.messages[len(f.hub.messages)-1]
	if e := f.broker.receive(t.Context(), helloWire(t, f.broker, original)); e != nil {
		t.Fatal(e)
	}
	if e := f.broker.send(t.Context(), rpc{Version: 1, Kind: "request", ID: "sequence-probe-two", Method: "probe", Payload: json.RawMessage(`{}`)}); e != nil {
		t.Fatal(e)
	}
	second := f.hub.messages[len(f.hub.messages)-1]
	if second.Sequence <= first.Sequence || second.SessionID != first.SessionID {
		t.Fatal("same-session replay reset the sender sequence")
	}
	// Across a process restart, the persisted remote timestamp rejects the old
	// signed Hello even while it remains inside the one-minute freshness window.
	restarted := restartHelloPeer(t, f.broker, f.hub, nil)
	if e := restarted.receive(t.Context(), helloWire(t, restarted, original)); e != nil {
		t.Fatal(e)
	}
	if restarted.state != nil {
		t.Fatal("old Hello restored an obsolete session after restart")
	}
}

func TestHelloRequiresDurableWatermarkAndCurrentGrant(t *testing.T) {
	f := newHelloFixture(t)
	driveHello(t, f)
	quietHello(t, f)
	prior := currentSession(f.agent)
	oldTime := f.agent.lastHello
	local, e := session.CreateHello(c.NewProvider(), f.broker.cfg.Device, "fresh-storage-failure", f.agent.cfg.Device.Identity.DeviceID, f.agent.cfg.Grant.GrantID, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	originalPath := f.agent.grantFile
	f.agent.grantFile = filepath.Join(filepath.Dir(originalPath), "missing-directory", "grant.json")
	if e = f.agent.receive(t.Context(), helloWire(t, f.agent, local.Hello)); e == nil {
		t.Fatal("Hello accepted with failed durable storage")
	}
	if currentSession(f.agent) != prior || !f.agent.lastHello.Equal(oldTime) {
		t.Fatal("failed checkpoint advanced the session/high-water")
	}
	f.agent.grantFile = originalPath
	f.agent.mu.Lock()
	f.agent.active = false
	f.agent.mu.Unlock()
	if e = f.agent.receive(t.Context(), helloWire(t, f.agent, local.Hello)); e != nil {
		t.Fatal(e)
	}
	if currentSession(f.agent) != prior || !f.agent.lastHello.Equal(oldTime) {
		t.Fatal("revoked peer adopted a new Hello")
	}
	f.agent.mu.Lock()
	f.agent.active = true
	f.agent.mu.Unlock()
	bad, e := session.CreateHello(c.NewProvider(), f.broker.cfg.Device, "wrong-grant-session", f.agent.cfg.Device.Identity.DeviceID, "different-grant", time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	if e = f.agent.receive(t.Context(), helloWire(t, f.agent, bad.Hello)); e != nil {
		t.Fatal(e)
	}
	if currentSession(f.agent) != prior {
		t.Fatal("wrong Grant adopted")
	}
}

func TestPeerRestartFencesOldInflightWithoutResubmittingMutation(t *testing.T) {
	f := newHelloFixture(t)
	driveHello(t, f)
	quietHello(t, f)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	f.broker.SetHandler(func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		calls.Add(1)
		close(entered)
		<-release
		return json.RawMessage(`{"ok":true}`), nil
	})
	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		result <- f.agent.Call(ctx, "relay.revoke", map[string]string{"operation_id": "same-durable-operation"}, nil)
	}()
	for i := 0; i < 50; i++ {
		drainHello(t, f.agent, f.broker)
		select {
		case <-entered:
			goto accepted
		default:
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("request was not admitted")
accepted:
	old := f.broker
	f.broker = restartHelloPeer(t, old, f.hub, f.brokerHandler)
	driveHello(t, f)
	quietHello(t, f)
	select {
	case e := <-result:
		if e != n.ErrUnavailable {
			t.Fatal("inflight was not fenced unavailable", e)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("stale pending call waited for its full timeout")
	}
	close(release)
	time.Sleep(5 * time.Millisecond)
	drainHello(t, f.agent, f.broker)
	if calls.Load() != 1 {
		t.Fatal("mutation was automatically replayed")
	}
	if !f.agent.Ready() || !f.broker.Ready() {
		t.Fatal("new healthy session was invalidated by old reply")
	}
}
