package iscpbridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func TestCredentialOnlyRelayRefreshPreservesCloudTrust(t *testing.T) {
	now := time.Now().UTC()
	provider := iscpcrypto.NewProvider()
	device, err := identity.NewDevice(provider, "domain", "device", now)
	if err != nil {
		t.Fatal(err)
	}
	cloud, err := identity.NewDevice(provider, "cloud", "cloud-root", now)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != relayRefreshPath {
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access": RelayCredential{DomainID: "domain", DeviceID: "device", Token: "rotated-access", ExpiresAt: now.Add(time.Hour)}, "refresh": RelayCredential{DomainID: "domain", DeviceID: "device", Token: "rotated-refresh", ExpiresAt: now.Add(2 * time.Hour)}})
	}))
	defer server.Close()
	bundle := EnrollmentBundle{Type: EnrollmentBundleType, DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: server.URL, RelayWebSocketURL: "wss://relay.invalid", TrustRootIdentity: cloud.Identity, Access: RelayCredential{DomainID: "domain", DeviceID: "device", Token: "access", ExpiresAt: now.Add(-time.Second)}, Refresh: RelayCredential{DomainID: "domain", DeviceID: "device", Token: "refresh", ExpiresAt: now.Add(time.Hour)}, IssuedAt: now, ExpiresAt: now.Add(2 * time.Hour)}
	path := filepath.Join(t.TempDir(), "enrollment.json")
	client, err := NewRelayCredentialClient(ProfileProduction, path, bundle, device, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.client = server.Client()
	if err := client.ensureAccess(context.Background()); err != nil {
		t.Fatal(err)
	}
	rotated := client.Enrollment()
	if rotated.Access.Token != "rotated-access" || rotated.TrustRootIdentity.PublicKey.KID != cloud.Identity.PublicKey.KID || len(rotated.Peers) != 0 {
		t.Fatal("refresh altered cloud trust or inserted application grants")
	}
	if rotated.Validate(now) == nil {
		t.Fatal("legacy Bridge validation unexpectedly accepted credential-only bundle")
	}
	if rotated.ValidateCredentials(now) != nil {
		t.Fatal("credential-only rotated bundle rejected")
	}
	var saved EnrollmentBundle
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &saved) != nil || saved.Access.Token != "rotated-access" || !saved.ExpiresAt.Equal(bundle.ExpiresAt) || !reflect.DeepEqual(saved.TrustRootIdentity, bundle.TrustRootIdentity) {
		t.Fatal("credential rotation was not persisted")
	}
}
