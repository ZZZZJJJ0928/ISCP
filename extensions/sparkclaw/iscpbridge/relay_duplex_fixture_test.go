package iscpbridge

import (
	"context"
	"encoding/json"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// An independent signed wire peer, with no production fallback routes.
func newDuplexClientFixture(t *testing.T, stall bool, after func(*websocket.Conn, duplex.Frame)) (*RelayClient, *atomic.Bool) {
	t.Helper()
	p := crypto.NewProvider()
	now := time.Now().UTC().Truncate(time.Second)
	device, _ := identity.NewDevice(p, "domain", "device", now)
	signer, _ := identity.NewDevice(p, "domain", "relay", now)
	verified := &atomic.Bool{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/iscp/relay" {
			digest, _ := duplex.Digest(duplex.DefaultLimits())
			d := descriptor.RelayDescriptor{Type: "iscp.relay.descriptor.v2", RelayID: "relay", DomainID: "domain", BaseURL: server.URL, WebSocketURL: "ws" + strings.TrimPrefix(server.URL, "http") + duplex.Path, SigningKeys: []descriptor.PublicKey{{KTY: "Ed25519", Use: "descriptor-signature", KID: signer.Identity.PublicKey.KID, Public: signer.Identity.PublicKey.Public}}, Metadata: map[string]string{"duplex_protocol": duplex.Protocol, "duplex_path": duplex.Path, "duplex_limits_sha256": digest}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
			signed, _ := descriptor.Sign(p, signer, d.Type, d, now)
			_ = json.NewEncoder(w).Encode(map[string]any{"descriptor": signed})
			return
		}
		if r.URL.Path != duplex.Path {
			w.WriteHeader(404)
			return
		}
		ws, err := (&websocket.Upgrader{Subprotocols: []string{duplex.Protocol}}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		if stall {
			_, _, _ = ws.ReadMessage()
			return
		}
		limits := duplex.DefaultLimits()
		challenge := duplex.Frame{V: 1, Kind: "challenge", ConnectionID: duplex.RandomID(), RelayID: "relay", DomainID: "domain", ChallengeID: duplex.RandomID(), Challenge: duplex.RandomID(), ExpiresAt: duplex.Timestamp(time.Now().Add(10 * time.Second)), HistoryID: duplex.RandomID(), Limits: &limits}
		if writeDuplex(ws, challenge) != nil {
			return
		}
		auth, err := readDuplex(ws)
		if err != nil {
			return
		}
		expected, _ := duplex.AuthChallenge(challenge, "authenticate", "1", "0", "access", device.Identity)
		if auth.Proof == nil || identity.VerifyProof(p, device.Identity, *auth.Proof, "relay", expected, time.Now(), time.Minute) != nil {
			t.Error("duplex proof failed")
			return
		}
		verified.Store(true)
		ready := duplex.Frame{V: 1, Kind: "ready", ConnectionID: challenge.ConnectionID, OwnerGeneration: "1", RequestID: "1", DomainID: "domain", DeviceID: "device", HistoryID: challenge.HistoryID, Limits: &limits, AuthorityExpiresAt: duplex.Timestamp(now.Add(time.Hour))}
		if writeDuplex(ws, ready) != nil {
			return
		}
		after(ws, ready)
	}))
	t.Cleanup(server.Close)
	b := EnrollmentBundle{DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: server.URL, RelayWebSocketURL: "ws" + strings.TrimPrefix(server.URL, "http") + duplex.Path, RelaySignerIdentity: &signer.Identity, Access: RelayCredential{Token: "access", ExpiresAt: now.Add(time.Hour)}, Refresh: RelayCredential{ExpiresAt: now.Add(time.Hour)}, ExpiresAt: now.Add(time.Hour)}
	client, err := NewRelayClient(ProfileLocalLab, "", b, device, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return client, verified
}
func TestDuplexReadinessRequiresFreshProof(t *testing.T) {
	for _, stall := range []bool{false, true} {
		t.Run(map[bool]string{true: "stalled", false: "ready"}[stall], func(t *testing.T) {
			client, proof := newDuplexClientFixture(t, stall, func(ws *websocket.Conn, _ duplex.Frame) { _, _, _ = ws.ReadMessage() })
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			var ready atomic.Bool
			err := client.RunOnceReady(ctx, nil, func() { ready.Store(true); cancel() })
			if err == nil {
				t.Fatal("expected canceled socket")
			}
			if !stall && (!proof.Load() || !ready.Load()) {
				t.Fatal("did not verify proof before ready")
			}
			if stall && ready.Load() {
				t.Fatal("stalled challenge became ready")
			}
		})
	}
}
