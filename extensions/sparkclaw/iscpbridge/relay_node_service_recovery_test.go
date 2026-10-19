package iscpbridge

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func sealServiceTestReceipt(t *testing.T, p serviceRecoveryRequest) nodeRelayReceipt {
	t.Helper()
	raw, _ := json.Marshal(p)
	canonicalRaw, _ := canonical.Marshal(raw)
	r := nodeRelayReceipt{SchemaVersion: 1, OperationID: p.OperationID, BindingDigest: c.Base64URL(c.SHA256(canonicalRaw)), DomainID: p.Identity.DomainID, DeviceID: p.Identity.DeviceID, State: "committed", IssuedAt: time.Now().UTC()}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubRaw, err := c.DecodeBase64URL(p.ReceiptWrapPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ecdh.X25519().NewPublicKey(pubRaw)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		t.Fatal(err)
	}
	r.EphemeralPublic = c.Base64URL(priv.PublicKey().Bytes())
	transcript := []byte(strings.Join([]string{"sparkclaw/iscp-node/relay-receipt/v1", p.OperationID, r.BindingDigest, r.DomainID, r.DeviceID, p.Identity.PublicKey.KID}, "\x00"))
	key, err := c.NewProvider().HKDF(shared, nil, append(append(append([]byte(nil), transcript...), pubRaw...), priv.PublicKey().Bytes()...), 32)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(rotatedRelayCredentials{Access: RelayCredential{r.DomainID, r.DeviceID, "service-access", time.Now().Add(15 * time.Minute)}, Refresh: RelayCredential{r.DomainID, r.DeviceID, "service-refresh", time.Now().Add(time.Hour)}})
	nonce := c.RandomBytes(12)
	ct, err := c.NewProvider().Seal(key, nonce, plain, transcript)
	if err != nil {
		t.Fatal(err)
	}
	r.Nonce = c.Base64URL(nonce)
	r.Ciphertext = c.Base64URL(ct)
	return r
}

func TestOperatorServiceRecoveryExpiredCredentialsLostResponseAndPrivateActivation(t *testing.T) {
	for _, scenario := range []string{"lost-response", "undeclared", "wrong-receipt-device"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Now().UTC()
			provider := c.NewProvider()
			device, _ := identity.NewDevice(provider, "domain", "operator-responder", now)
			signer, _ := identity.NewDevice(provider, "domain", "relay-signer", now)
			invitation, _ := identity.NewDevice(provider, "domain", "invitation", now)
			var server *httptest.Server
			posts := 0
			var original []byte
			var receipt nodeRelayReceipt
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/iscp/relay":
					metadata := map[string]string{}
					if scenario != "undeclared" {
						metadata["sparkclaw_service_peer_recovery"] = "v1"
					}
					d := descriptor.RelayDescriptor{Type: "iscp.relay.descriptor.v2", RelayID: "relay", DomainID: "domain", BaseURL: server.URL, WebSocketURL: "wss" + strings.TrimPrefix(server.URL, "https") + "/v2/relay/duplex", SigningKeys: []descriptor.PublicKey{{KTY: "Ed25519", Use: "descriptor-signature", KID: signer.Identity.PublicKey.KID, Public: signer.Identity.PublicKey.Public}}, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Metadata: metadata}
					signed, e := descriptor.Sign(provider, signer, d.Type, d, now)
					if e != nil {
						t.Error(e)
						w.WriteHeader(500)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"descriptor": signed})
				case serviceRecoveryPath:
					if r.Header.Get("Authorization") != "" {
						t.Error("expired bearer sent to service recovery")
					}
					posts++
					raw, _ := io.ReadAll(r.Body)
					var p serviceRecoveryRequest
					if strictUnmarshal(raw, &p) != nil {
						t.Error("invalid service request")
						w.WriteHeader(400)
						return
					}
					challenge := strings.Join([]string{"sparkclaw/iscp-node/service-recovery/v1", p.OperationID, p.ReceiptWrapPublicKey}, "\x00")
					if identity.VerifyProof(provider, device.Identity, p.Proof, "relay", challenge, time.Now().UTC(), time.Minute) != nil {
						t.Error("invalid stored-key service proof")
						w.WriteHeader(403)
						return
					}
					if posts == 1 {
						original = raw
						receipt = sealServiceTestReceipt(t, p)
						if scenario == "lost-response" {
							w.WriteHeader(503)
							return
						}
					}
					if string(original) != string(raw) {
						t.Error("service replay changed request, proof or wrap")
					}
					if scenario == "wrong-receipt-device" {
						receipt.DeviceID = "other-service"
					}
					_ = json.NewEncoder(w).Encode(receipt)
				default:
					t.Error("unexpected endpoint", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			bundle := EnrollmentBundle{Type: EnrollmentBundleType, Mode: BundleModeWorkbenchNodeManaged, DomainID: "domain", DeviceID: device.Identity.DeviceID, RelayID: "relay", RelayBaseURL: server.URL, RelayWebSocketURL: "wss" + strings.TrimPrefix(server.URL, "https") + "/v2/relay/duplex", RelaySignerIdentity: &signer.Identity, InvitationSignerIdentity: &invitation.Identity, TLSCertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), IssuedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour), Access: RelayCredential{"domain", device.Identity.DeviceID, "expired-access", now.Add(-time.Hour)}, Refresh: RelayCredential{"domain", device.Identity.DeviceID, "expired-refresh", now.Add(-time.Hour)}}
			dir := t.TempDir()
			_ = os.Chmod(dir, 0700)
			path := filepath.Join(dir, "enrollment.json")
			if err := SaveEnrollment(path, bundle); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			pending := filepath.Join(dir, "recovery.pending")
			updated, err := RecoverNodeServiceCredentials(context.Background(), bundle, device, pending)
			if scenario != "lost-response" {
				if err == nil {
					t.Fatal("unsupported/tampered recovery accepted")
				}
				if scenario == "undeclared" && posts != 0 {
					t.Fatal("undeclared adapter received mutation")
				}
				after, _ := os.ReadFile(path)
				if string(before) != string(after) {
					t.Fatal("rejected recovery changed active enrollment")
				}
				return
			}
			if err == nil {
				t.Fatal("lost response treated as complete")
			}
			encrypted, _ := os.ReadFile(pending)
			if strings.Contains(string(encrypted), "wrap_private") || strings.Contains(string(encrypted), device.Identity.PublicKey.Public) {
				t.Fatal("pending recovery persisted plaintext")
			}
			updated, err = RecoverNodeServiceCredentials(context.Background(), bundle, device, pending)
			if err != nil {
				t.Fatal(err)
			}
			if updated.Access.Token != "service-access" || updated.Refresh.Token != "service-refresh" || updated.DeviceID != bundle.DeviceID || updated.RelaySignerIdentity.PublicKey.Public != bundle.RelaySignerIdentity.PublicKey.Public {
				t.Fatal("service recovery crossed identity pins")
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("helper activated profile before caller saved result")
			}
			if _, err := os.Stat(pending); err != nil {
				t.Fatal("sealed receipt cleared before durable activation")
			}
			if err := SaveEnrollment(path, updated); err != nil {
				t.Fatal(err)
			}
			if err := CommitNodeServiceRecovery(pending); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(pending); !os.IsNotExist(err) {
				t.Fatal("applied receipt retained")
			}
			if posts != 2 {
				t.Fatal("operation was not replayed exactly")
			}
		})
	}
}
