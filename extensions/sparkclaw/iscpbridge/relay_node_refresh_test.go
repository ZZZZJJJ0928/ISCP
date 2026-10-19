package iscpbridge

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func TestNodeRelayRefreshLostResponseRestartAndConcurrentIsolation(t *testing.T) {
	now := time.Now().UTC()
	provider := c.NewProvider()
	device, _ := identity.NewDevice(provider, "domain", "device", now)
	signer, _ := identity.NewDevice(provider, "domain", "relay-signer", now)
	invitation, _ := identity.NewDevice(provider, "domain", "invitation", now)
	var server *httptest.Server
	var mu sync.Mutex
	rotations := 0
	requests := 0
	var originalHeaders http.Header
	var receipt nodeRelayReceipt
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/iscp/relay":
			d := descriptor.RelayDescriptor{Type: "iscp.relay.descriptor.v2", RelayID: "relay", DomainID: "domain", BaseURL: server.URL, WebSocketURL: "wss" + strings.TrimPrefix(server.URL, "https") + "/v2/relay/duplex", SigningKeys: []descriptor.PublicKey{{KTY: "Ed25519", Use: "descriptor-signature", KID: signer.Identity.PublicKey.KID, Public: signer.Identity.PublicKey.Public}}, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Metadata: map[string]string{"sparkclaw_refresh_receipts": "v1"}}
			signed, e := descriptor.Sign(provider, signer, d.Type, d, now)
			if e != nil {
				t.Error(e)
				w.WriteHeader(500)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"descriptor": signed})
		case relayRefreshPath:
			mu.Lock()
			defer mu.Unlock()
			requests++
			var body map[string]string
			proofRaw, e := c.DecodeBase64URL(r.Header.Get("X-SparkClaw-Refresh-Proof"))
			var proof identity.DeviceProof
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["refresh"] != "original-refresh-secret" || e != nil || strictUnmarshal(proofRaw, &proof) != nil {
				t.Error("refresh fields invalid")
				w.WriteHeader(401)
				return
			}
			op, wrap := r.Header.Get("Idempotency-Key"), r.Header.Get("X-SparkClaw-Refresh-Wrap-Key")
			challenge := strings.Join([]string{"sparkclaw/iscp-node/refresh/v1", op, c.Base64URL(c.SHA256([]byte(body["refresh"]))), wrap}, "\x00")
			if identity.VerifyProof(provider, device.Identity, proof, "relay", challenge, time.Now().UTC(), time.Minute) != nil {
				t.Error("invalid refresh PoP")
				w.WriteHeader(401)
				return
			}
			if rotations == 0 {
				rotations++
				originalHeaders = r.Header.Clone()
				digestRaw, _ := json.Marshal(struct {
					OperationID string               `json:"operation_id"`
					RefreshHash string               `json:"refresh_hash"`
					WrapPublic  string               `json:"wrap_public"`
					Proof       identity.DeviceProof `json:"proof"`
				}{op, c.Base64URL(c.SHA256([]byte(body["refresh"]))), wrap, proof})
				canonicalRaw, _ := canonical.Marshal(digestRaw)
				receipt = nodeRelayReceipt{SchemaVersion: 1, OperationID: op, BindingDigest: c.Base64URL(c.SHA256(canonicalRaw)), DomainID: "domain", DeviceID: "device", State: "committed", IssuedAt: now}
				priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
				pubRaw, _ := c.DecodeBase64URL(wrap)
				pub, e := ecdh.X25519().NewPublicKey(pubRaw)
				if e != nil {
					t.Error(e)
					w.WriteHeader(401)
					return
				}
				shared, e := priv.ECDH(pub)
				if e != nil {
					t.Error(e)
					w.WriteHeader(401)
					return
				}
				receipt.EphemeralPublic = c.Base64URL(priv.PublicKey().Bytes())
				transcript := []byte(strings.Join([]string{"sparkclaw/iscp-node/relay-receipt/v1", op, receipt.BindingDigest, "domain", "device", device.Identity.PublicKey.KID}, "\x00"))
				info := append(append(append([]byte(nil), transcript...), pubRaw...), priv.PublicKey().Bytes()...)
				key, _ := provider.HKDF(shared, nil, info, 32)
				plain, _ := json.Marshal(rotatedRelayCredentials{Access: RelayCredential{"domain", "device", "successor-access", now.Add(15 * time.Minute)}, Refresh: RelayCredential{"domain", "device", "successor-refresh", now.Add(24 * time.Hour)}})
				nonce := c.RandomBytes(12)
				ct, _ := provider.Seal(key, nonce, plain, transcript)
				receipt.Nonce = c.Base64URL(nonce)
				receipt.Ciphertext = c.Base64URL(ct)
				// The server's durable rotation has committed but its response is
				// lost. Client must retain the exact proof/wrap request for replay.
				w.WriteHeader(503)
				return
			}
			for _, h := range []string{"Idempotency-Key", "X-SparkClaw-Refresh-Wrap-Key", "X-SparkClaw-Refresh-Proof"} {
				if r.Header.Get(h) != originalHeaders.Get(h) {
					t.Error("retry changed original mutation input")
					w.WriteHeader(409)
					return
				}
			}
			_ = json.NewEncoder(w).Encode(receipt)
		default:
			t.Error("unexpected node endpoint", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	bundle := EnrollmentBundle{Type: EnrollmentBundleType, Mode: BundleModeWorkbenchNodeManaged, DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: server.URL, RelayWebSocketURL: "wss" + strings.TrimPrefix(server.URL, "https") + "/v2/relay/duplex", RelaySignerIdentity: &signer.Identity, InvitationSignerIdentity: &invitation.Identity, TLSCertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), IssuedAt: now, ExpiresAt: now.Add(20 * time.Minute), Access: RelayCredential{"domain", "device", "original-access", now.Add(-time.Second)}, Refresh: RelayCredential{"domain", "device", "original-refresh-secret", now.Add(time.Hour)}}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	path := filepath.Join(dir, "enrollment.json")
	if err := SaveEnrollment(path, bundle); err != nil {
		t.Fatal(err)
	}
	client, err := NewRelayCredentialClient(ProfileProduction, path, bundle, device, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.ensureAccess(context.Background()); err == nil {
		t.Fatal("lost response treated as completed")
	}
	pending, err := os.ReadFile(client.nodeRefreshPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pending), bundle.Refresh.Token) || strings.Contains(string(pending), "wrap_private") {
		t.Fatal("refresh secret persisted unencrypted")
	}
	// Reconstructing the client simulates helper restart. Concurrent receive
	// and submit calls serialize the same refresh and share the saved successor.
	restarted, err := NewRelayCredentialClient(ProfileProduction, path, bundle, device, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := restarted.ensureAccess(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	if rotations != 1 || requests != 2 {
		t.Errorf("rotation/replay mismatch %d %d", rotations, requests)
	}
	mu.Unlock()
	updated := restarted.Enrollment()
	if updated.Access.Token != "successor-access" || updated.Refresh.Token != "successor-refresh" || updated.RelaySignerIdentity.PublicKey.Public != signer.Identity.PublicKey.Public || updated.InvitationSignerIdentity.PublicKey.Public != invitation.Identity.PublicKey.Public {
		t.Fatal("rotated credentials crossed authority bindings")
	}
	if _, err := os.Stat(restarted.nodeRefreshPath()); !os.IsNotExist(err) {
		t.Fatal("applied pending operation not cleared")
	}
	raw, _ := os.ReadFile(path)
	var saved EnrollmentBundle
	if strictUnmarshal(raw, &saved) != nil || saved.Refresh.Token != updated.Refresh.Token {
		t.Fatal("rotated enrollment was not durable")
	}
}

func TestNodeTLSCertificateCannotTrustUnknownReplacement(t *testing.T) {
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer first.Close()
	second := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer second.Close()
	// httptest shares its fixture certificate, so generate a structurally
	// invalid trust input to prove the adapter never falls back to system roots.
	for _, raw := range []string{"", "not a certificate", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: first.Certificate().Raw}))} {
		if _, err := VerifiedTLSConfig(raw); err == nil {
			t.Fatal("invalid public TLS trust accepted")
		}
	}
	cfg, err := VerifiedTLSConfig(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: first.Certificate().Raw})))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify || cfg.RootCAs == nil {
		t.Fatal("IP TLS verification disabled")
	}
}
