package iscpbridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func TestSignedRelayDiscoveryPinnedCloudRoot(t *testing.T) {
	provider := iscpcrypto.NewProvider()
	now := time.Now().UTC()
	root, err := identity.NewDevice(provider, "cloud-domain", "cloud-root", now)
	if err != nil {
		t.Fatal(err)
	}
	root.Identity.PublicKey.KID = "cloud-trust-prod-1"
	tests := []string{"valid", "expired", "relay_id", "websocket", "foreign_root", "bad_signature", "malformed_key", "redirect"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if name == "redirect" {
					http.Redirect(w, r, "http://insecure.invalid", http.StatusFound)
					return
				}
				key := descriptor.PublicKey{KTY: "Ed25519", Use: "identity-signature", KID: root.Identity.PublicKey.KID, Public: root.Identity.PublicKey.Public, State: "active"}
				if name == "malformed_key" {
					key.KID = "not-a-thumbprint"
				}
				expires := now.Add(time.Hour)
				if name == "expired" {
					expires = now.Add(-time.Hour)
				}
				var value any
				kind := ""
				if r.URL.Path == "/.well-known/iscp/relay" {
					kind = "iscp.relay.descriptor.v2"
					relayID := "relay"
					if name == "relay_id" {
						relayID = "other"
					}
					ws := "wss" + strings.TrimPrefix(server.URL, "https") + "/v2/relay/connect"
					if name == "websocket" {
						ws = "wss://other.invalid/connect"
					}
					value = descriptor.RelayDescriptor{Type: kind, RelayID: relayID, DomainID: root.Identity.DomainID, BaseURL: server.URL, WebSocketURL: ws, SigningKeys: []descriptor.PublicKey{key}, IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: expires}
				} else if r.URL.Path == "/.well-known/iscp/trust-root" {
					kind = "iscp.trust_root.descriptor.v2"
					key.Use = "grant-signature"
					value = descriptor.TrustRootDescriptor{Type: kind, TrustRootID: root.Identity.DeviceID, DomainID: root.Identity.DomainID, BaseURL: server.URL, Keys: []descriptor.PublicKey{key}, IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: expires}
				} else {
					w.WriteHeader(404)
					return
				}
				signed, err := descriptor.Sign(provider, root, kind, value, now)
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				if name == "bad_signature" {
					signed.Signature.Value = iscpcrypto.Base64URL(make([]byte, 64))
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"descriptor": signed})
			}))
			defer server.Close()
			bundle := EnrollmentBundle{RelayID: "relay", RelayBaseURL: server.URL, RelayWebSocketURL: "wss" + strings.TrimPrefix(server.URL, "https") + "/v2/relay/connect", TrustRootIdentity: root.Identity}
			if name == "foreign_root" {
				foreign, err := identity.NewDevice(provider, "cloud-domain", "cloud-root", now)
				if err != nil {
					t.Fatal(err)
				}
				bundle.TrustRootIdentity = foreign.Identity
			}
			client := server.Client()
			client.Timeout = time.Second
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			err := verifyRelayDiscovery(context.Background(), client, bundle, now)
			if name == "valid" && err != nil {
				t.Fatal(err)
			}
			if name != "valid" && err == nil {
				t.Fatalf("invalid %s discovery accepted", name)
			}
		})
	}
}
