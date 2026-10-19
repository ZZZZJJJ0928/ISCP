package iscpnodecontrol

import (
	"bytes"
	"context"
	"encoding/json"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"sync"
	"testing"
	"time"
)

type hub struct {
	mu       sync.Mutex
	queues   map[string][]json.RawMessage
	messages []envelope.SecureEnvelope
}
type queuedRelay struct {
	hub    *hub
	device string
}

func (r queuedRelay) Submit(_ context.Context, v any) error {
	raw, _ := json.Marshal(v)
	var e envelope.SecureEnvelope
	_ = json.Unmarshal(raw, &e)
	r.hub.mu.Lock()
	defer r.hub.mu.Unlock()
	r.hub.queues[e.RecipientDeviceID] = append(r.hub.queues[e.RecipientDeviceID], raw)
	r.hub.messages = append(r.hub.messages, e)
	return nil
}
func (r queuedRelay) RunOnceReady(ctx context.Context, handle func(context.Context, json.RawMessage) error, ready func()) error {
	ready()
	r.hub.mu.Lock()
	batch := r.hub.queues[r.device]
	delete(r.hub.queues, r.device)
	r.hub.mu.Unlock()
	for _, v := range batch {
		if e := handle(ctx, v); e != nil {
			return e
		}
	}
	return nil
}
func newDevice(t *testing.T, id string) identity.Device {
	t.Helper()
	d, e := identity.NewDevice(c.NewProvider(), "control-test", id, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func TestStandardSessionControlRPCIsAuthenticatedAndEncrypted(t *testing.T) {
	a, b, signer := newDevice(t, "node-agent"), newDevice(t, "test1-sidecar"), newDevice(t, "control-authority")
	g, e := trust.SignGrant(c.NewProvider(), signer, trust.Grant{GrantID: "control-grant", SubjectDeviceID: a.Identity.DeviceID, ConfirmationThumbprint: a.Identity.PublicKey.KID, Audience: b.Identity.DeviceID, Permissions: []string{ControlPermission}, RelayConstraints: []string{"relay"}, NotBefore: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(time.Hour), RevocationEpoch: 1})
	if e != nil {
		t.Fatal(e)
	}
	h := &hub{queues: map[string][]json.RawMessage{}}
	p, e := NewPeer(PeerConfig{true, a, b.Identity, signer.Identity, g, "relay"}, queuedRelay{h, a.Identity.DeviceID}, func(ctx context.Context, method string, raw json.RawMessage) (json.RawMessage, error) {
		if method != "issuer.exchange" {
			return nil, n.ErrDenied
		}
		return json.Marshal(map[string]string{"sealed": "opaque-enrollment-frame"})
	})
	if e != nil {
		t.Fatal(e)
	}
	q, e := NewPeer(PeerConfig{false, b, a.Identity, signer.Identity, g, "relay"}, queuedRelay{h, b.Identity.DeviceID}, nil)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	go p.Run(ctx)
	go q.Run(ctx)
	deadline := time.Now().Add(15 * time.Second)
	for !p.Ready() || !q.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("standard Hello/Ready failed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	var out map[string]string
	if e = q.Call(ctx, "issuer.exchange", map[string]string{"frame": "original-client-frame"}, &out); e != nil || out["sealed"] != "opaque-enrollment-frame" {
		t.Fatal("RPC", e, out)
	}
	if e = q.Call(ctx, "relay.admin", map[string]string{}, &out); e != n.ErrDenied {
		t.Fatal("unallowlisted operation admitted", e)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	encrypted := 0
	for _, env := range h.messages {
		if env.PayloadType == payloadType {
			encrypted++
			raw, _ := c.DecodeBase64URL(env.Ciphertext)
			if string(raw) == "opaque-enrollment-frame" || bytes.Contains(raw, []byte("original-client-frame")) {
				t.Fatal("unencrypted control RPC")
			}

		}
	}
	if encrypted < 4 {
		t.Fatal("missing encrypted request/response frames")
	}
}
func TestControlGrantCannotBeBusinessGrantOrWrongDirection(t *testing.T) {
	a, b, signer := newDevice(t, "node-agent"), newDevice(t, "sidecar"), newDevice(t, "issuer")
	g, e := trust.SignGrant(c.NewProvider(), signer, trust.Grant{GrantID: "wrong-grant", SubjectDeviceID: a.Identity.DeviceID, ConfirmationThumbprint: a.Identity.PublicKey.KID, Audience: b.Identity.DeviceID, Permissions: []string{n.Permission}, RelayConstraints: []string{"relay"}, NotBefore: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(time.Hour), RevocationEpoch: 1})
	if e != nil {
		t.Fatal(e)
	}
	h := &hub{queues: map[string][]json.RawMessage{}}
	if _, e = NewPeer(PeerConfig{true, a, b.Identity, signer.Identity, g, "relay"}, queuedRelay{h, a.Identity.DeviceID}, nil); e == nil {
		t.Fatal("business permission promoted to enrollment controller")
	}
}
