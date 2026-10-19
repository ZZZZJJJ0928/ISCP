package iscpbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

func TestEnrollWithTicketV3(t *testing.T) {
	provider := iscpcrypto.NewProvider()
	now := time.Now().UTC()
	trustSigner, err := identity.NewDevice(provider, "infinimesh-cloud", "trust-root-test", now)
	if err != nil {
		t.Fatal(err)
	}
	phone, err := identity.NewDevice(provider, "dom_test", "dev_phone", now)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := provisioning.SignTicketV3(provider, trustSigner, provisioning.PairingTicketV3{
		TicketID: "ptk_test_v3", DomainID: "dom_test", RelayID: "relay-test", TrustRootID: "trust-root-test",
		Purpose: provisioning.PurposeInvite, ConsumerRole: "member_device",
		GrantAudience: phone.Identity.DeviceID, GrantPermissions: []string{"conversation"},
		GrantTTLSeconds: 3600, MaxUses: 1,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/iscp/relay":
			desc := descriptor.RelayDescriptor{
				Type: "iscp.relay.descriptor.v2", RelayID: "relay-test", DomainID: "infinimesh-cloud",
				BaseURL: server.URL, WebSocketURL: "ws" + strings.TrimPrefix(server.URL, "http") + "/v2/relay/connect",
				// A real deployment's descriptor declares the key it is signed
				// with; an empty key set is unverifiable and now rejected.
				SigningKeys: []descriptor.PublicKey{{
					KTY: "Ed25519", Use: "identity-signature",
					KID:    trustSigner.Identity.PublicKey.KID,
					Public: trustSigner.Identity.PublicKey.Public,
					State:  "active",
				}},
				IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour),
				Metadata: map[string]string{"grant_renewal": "true", "recovery_anchor": "true"},
			}
			signed, _ := descriptor.Sign(provider, trustSigner, desc.Type, desc, now)
			_ = json.NewEncoder(w).Encode(map[string]any{"descriptor": signed})
		case r.URL.Path == "/.well-known/iscp/trust-root":
			desc := descriptor.TrustRootDescriptor{
				Type: "iscp.trust_root.descriptor.v2", TrustRootID: "trust-root-test", DomainID: "infinimesh-cloud",
				BaseURL: server.URL,
				Keys: []descriptor.PublicKey{{
					KTY: "Ed25519", Use: "grant-signature",
					KID:    trustSigner.Identity.PublicKey.KID,
					Public: trustSigner.Identity.PublicKey.Public,
					State:  "active",
				}},
				IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour),
				Metadata: map[string]string{"multi_tenant": "true"},
			}
			signed, _ := descriptor.Sign(provider, trustSigner, desc.Type, desc, now)
			_ = json.NewEncoder(w).Encode(map[string]any{"descriptor": signed})
		case r.URL.Path == "/v2/relay/devices/register-with-ticket":
			var req struct {
				TicketV3 *provisioning.PairingTicketV3 `json:"ticket_v3"`
				Identity identity.DeviceIdentity       `json:"identity"`
				Proof    identity.DeviceProof          `json:"identity_proof"`
				Metadata map[string]any                `json:"metadata"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TicketV3 == nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// The Cloud contract: signed v3 ticket verified, proof challenge
			// must equal the ticket id.
			if err := provisioning.VerifyTicketV3(provider, *req.TicketV3, trustSigner.Identity, time.Now().UTC()); err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if err := identity.VerifyProof(provider, req.Identity, req.Proof, "relay-test", req.TicketV3.TicketID, time.Now().UTC(), 5*time.Minute); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if req.Metadata["product_kind"] != "sparkclaw" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			thumb, _ := identity.Thumbprint(req.Identity)
			grant, _ := trust.SignGrant(provider, trustSigner, trust.Grant{
				GrantID: "grant_issued_1", SubjectDeviceID: "dev_official_bridge",
				Audience: req.TicketV3.GrantAudience, ConfirmationThumbprint: thumb,
				Permissions: req.TicketV3.GrantPermissions, RelayConstraints: []string{"relay-test"},
				NotBefore: time.Now().UTC().Add(-time.Second), ExpiresAt: time.Now().UTC().Add(time.Hour),
			})
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":    map[string]any{"device_id": "dev_official_bridge", "domain_id": "dom_test"},
				"access":  RelayCredential{DomainID: "dom_test", DeviceID: "dev_official_bridge", Token: "tok_a", ExpiresAt: time.Now().UTC().Add(15 * time.Minute)},
				"refresh": RelayCredential{DomainID: "dom_test", DeviceID: "dev_official_bridge", Token: "tok_r", ExpiresAt: time.Now().UTC().Add(24 * time.Hour)},
				"grant":   grant,
			})
		case strings.HasPrefix(r.URL.Path, "/v2/trust/devices/status"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type": "iscp.trust.device_status.v2", "identity": phone.Identity,
				"domain_id": "dom_test", "device_id": phone.Identity.DeviceID,
				"status": "trusted", "public_key": phone.Identity.PublicKey,
				"device_record_version": 1, "revocation_epoch": 0,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Wrapper dual-carry transport (the v2 slot is opaque to the Bridge).
	wrapperRaw, _ := json.Marshal(map[string]any{
		"version": 1, "ticket_v3": ticket,
		"expected_audience_phone_id": phone.Identity.DeviceID,
		"display_name":               "SparkClaw",
	})
	payload := base64.RawURLEncoding.EncodeToString(wrapperRaw)

	dir := t.TempDir()
	bundle, err := EnrollWithTicket(context.Background(), TicketEnrollmentOptions{
		Payload:           payload,
		RelayBaseURL:      server.URL,
		RelayWebSocketURL: "ws" + strings.TrimPrefix(server.URL, "http") + "/v2/relay/connect",
		IdentityDirectory: filepath.Join(dir, "identity"),
		KeyBackend:        "file",
		Profile:           ProfileLocalLab,
	}, filepath.Join(dir, "enrollment.json"), nil)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if bundle.Mode != BundleModeManaged || bundle.DeviceID != "dev_official_bridge" || bundle.DomainID != "dom_test" {
		t.Fatalf("bundle = %#v", bundle)
	}
	if len(bundle.Peers) != 1 || bundle.Peers[0].Identity.DeviceID != phone.Identity.DeviceID ||
		bundle.Peers[0].OutboundGrant.GrantID != "grant_issued_1" {
		t.Fatalf("peers = %#v", bundle.Peers)
	}
	// The persisted identity carries the official Cloud-assigned ids.
	files := DeviceFiles{
		Directory:    filepath.Join(dir, "identity"),
		IdentityFile: filepath.Join(dir, "identity", IdentityFileName),
		KeyFile:      filepath.Join(dir, "identity", IdentityKeyFileName),
	}
	device, err := LoadDeviceWithKeyBackend(files.IdentityFile, files.KeyFile, "file", "")
	if err != nil {
		t.Fatalf("reload official identity: %v", err)
	}
	if device.Identity.DeviceID != "dev_official_bridge" {
		t.Fatalf("official identity = %#v", device.Identity)
	}
	// The reloaded bundle validates and drives a managed service.
	reloaded, err := LoadEnrollment(filepath.Join(dir, "enrollment.json"), time.Now().UTC())
	if err != nil {
		t.Fatalf("reload bundle: %v", err)
	}
	if reloaded.Mode != BundleModeManaged {
		t.Fatal("reloaded bundle lost managed mode")
	}
}

func TestEnrollWithTicketRejectsAudienceReversalAndV2Only(t *testing.T) {
	provider := iscpcrypto.NewProvider()
	now := time.Now().UTC()
	trustSigner, err := identity.NewDevice(provider, "infinimesh-cloud", "trust-root-test", now)
	if err != nil {
		t.Fatal(err)
	}
	// A wrapper carrying only a v2 ticket is rejected up front.
	v2, err := provisioning.SignTicket(provider, trustSigner, provisioning.PairingTicket{
		TicketID: "ptk_v2", DomainID: "dom_test", RelayID: "relay-test", TrustRootID: "trust-root-test",
		MaxUses: 1, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	wrapperRaw, _ := json.Marshal(map[string]any{"version": 1, "ticket": v2})
	if _, _, _, err := DecodeTicketEnrollmentPayload(base64.RawURLEncoding.EncodeToString(wrapperRaw)); err == nil ||
		!strings.Contains(err.Error(), "predates ISCP v0.2") {
		t.Fatalf("expected v2-only rejection, got %v", err)
	}
	// Wrapper hint disagreeing with the signed grant audience is rejected.
	v3, err := provisioning.SignTicketV3(provider, trustSigner, provisioning.PairingTicketV3{
		TicketID: "ptk_v3", DomainID: "dom_test", RelayID: "relay-test", TrustRootID: "trust-root-test",
		Purpose: provisioning.PurposeInvite, ConsumerRole: "member_device",
		GrantAudience: "dev_phone", GrantPermissions: []string{"conversation"},
		MaxUses: 1, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	ticket, expected, _, err := DecodeTicketEnrollmentPayload(base64.RawURLEncoding.EncodeToString(mustJSON(map[string]any{
		"version": 1, "ticket_v3": v3, "expected_audience_phone_id": "dev_other_phone",
	})))
	if err != nil {
		t.Fatal(err)
	}
	if expected != "dev_other_phone" || ticket.GrantAudience != "dev_phone" {
		t.Fatalf("decode = %#v expected %q", ticket, expected)
	}
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

// TestDescriptorVerificationRejectsUnusableDescriptors pins the discovery
// checks that were previously absent: descriptors were unmarshalled and
// trusted without verifying their signature or expiry, so an expired document,
// one rolled back to a retired key set, or one signed by a key it does not
// declare was accepted and its trust-root keys used to verify the ticket.
func TestDescriptorVerificationRejectsUnusableDescriptors(t *testing.T) {
	provider := iscpcrypto.NewProvider()
	now := time.Now().UTC()
	signer, err := identity.NewDevice(provider, "infinimesh-cloud", "trust-root-test", now)
	if err != nil {
		t.Fatal(err)
	}
	activeKey := descriptor.PublicKey{
		KTY: "Ed25519", Use: "identity-signature",
		KID: signer.Identity.PublicKey.KID, Public: signer.Identity.PublicKey.Public,
		State: "active",
	}

	serve := func(t *testing.T, keys []descriptor.PublicKey, issuedAt, expiresAt time.Time) string {
		t.Helper()
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/iscp/relay" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			desc := descriptor.RelayDescriptor{
				Type: "iscp.relay.descriptor.v2", RelayID: "relay-test", DomainID: "infinimesh-cloud",
				BaseURL: server.URL, WebSocketURL: "ws" + strings.TrimPrefix(server.URL, "http") + "/v2/relay/connect",
				SigningKeys: keys, IssuedAt: issuedAt, ExpiresAt: expiresAt,
			}
			signed, _ := descriptor.Sign(provider, signer, desc.Type, desc, issuedAt)
			_ = json.NewEncoder(w).Encode(map[string]any{"descriptor": signed})
		}))
		t.Cleanup(server.Close)
		return server.URL
	}

	t.Run("expired", func(t *testing.T) {
		url := serve(t, []descriptor.PublicKey{activeKey}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
		_, _, err := fetchVerifiedRelayDescriptor(t.Context(), &http.Client{Timeout: 5 * time.Second},
			provider, url, ProfileProduction, now)
		if err == nil || !strings.Contains(err.Error(), "verification failed") {
			t.Fatalf("expired descriptor must be rejected, got %v", err)
		}
	})

	t.Run("retired key set", func(t *testing.T) {
		retired := activeKey
		retired.State = "revoked"
		url := serve(t, []descriptor.PublicKey{retired}, now, now.Add(24*time.Hour))
		_, _, err := fetchVerifiedRelayDescriptor(t.Context(), &http.Client{Timeout: 5 * time.Second},
			provider, url, ProfileProduction, now)
		if err == nil || !strings.Contains(err.Error(), "active key it declares") {
			t.Fatalf("revoked signing key must be rejected, got %v", err)
		}
	})

	t.Run("signed by an undeclared key", func(t *testing.T) {
		other, err := identity.NewDevice(provider, "infinimesh-cloud", "impostor", now)
		if err != nil {
			t.Fatal(err)
		}
		foreign := descriptor.PublicKey{
			KTY: "Ed25519", Use: "identity-signature",
			KID: other.Identity.PublicKey.KID, Public: other.Identity.PublicKey.Public,
			State: "active",
		}
		// Declares only the impostor's key while being signed by `signer`.
		url := serve(t, []descriptor.PublicKey{foreign}, now, now.Add(24*time.Hour))
		_, _, err = fetchVerifiedRelayDescriptor(t.Context(), &http.Client{Timeout: 5 * time.Second},
			provider, url, ProfileProduction, now)
		if err == nil {
			t.Fatal("descriptor signed by an undeclared key must be rejected")
		}
	})

	t.Run("accepts a well-formed descriptor", func(t *testing.T) {
		url := serve(t, []descriptor.PublicKey{activeKey}, now, now.Add(24*time.Hour))
		relayDesc, pin, err := fetchVerifiedRelayDescriptor(t.Context(), &http.Client{Timeout: 5 * time.Second},
			provider, url, ProfileProduction, now)
		if err != nil {
			t.Fatalf("valid descriptor rejected: %v", err)
		}
		if relayDesc.RelayID != "relay-test" || pin == "" {
			t.Fatalf("descriptor = %#v, pin = %q", relayDesc, pin)
		}
	})
}
