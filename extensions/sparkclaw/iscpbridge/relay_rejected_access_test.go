package iscpbridge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func rejectedAccessFixture(t *testing.T, failure string) (*RelayClient, EnrollmentBundle, string, *atomic.Int32) {
	t.Helper()
	now := time.Now().UTC()
	signer, _ := identity.NewDevice(c.NewProvider(), "domain", "relay-signer", now)
	device, _ := identity.NewDevice(c.NewProvider(), "domain", "device", now)
	advertised := signer
	if failure == "changed-pin" {
		advertised, _ = identity.NewDevice(c.NewProvider(), "domain", "relay-signer", now)
	}
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/iscp/relay":
			desc := descriptor.RelayDescriptor{Type: "iscp.relay.descriptor.v2", RelayID: "relay", DomainID: "domain", BaseURL: "http://iscp-relay:8080", WebSocketURL: "ws://iscp-relay:8080/v2/relay/duplex", SigningKeys: []descriptor.PublicKey{{KTY: "Ed25519", Use: "descriptor-signature", KID: advertised.Identity.PublicKey.KID, Public: advertised.Identity.PublicKey.Public}}, IssuedAt: now, ExpiresAt: now.Add(48 * time.Hour)}
			signed, err := descriptor.Sign(c.NewProvider(), advertised, desc.Type, desc, now)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"descriptor": signed})
		case relayRefreshPath:
			calls.Add(1)
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["refresh"] != "original-refresh" {
				t.Error("refresh did not retain original credential")
				w.WriteHeader(400)
				return
			}
			if failure == "refresh-rejected" {
				w.WriteHeader(401)
				return
			}
			access := RelayCredential{"domain", "device", "next-access", now.Add(15 * time.Minute)}
			refresh := RelayCredential{"domain", "device", "next-refresh", now.Add(24 * time.Hour)}
			if failure == "foreign-response" {
				access.DeviceID = "foreign"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access": access, "refresh": refresh})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	bundle := EnrollmentBundle{Type: EnrollmentBundleType, Mode: BundleModeWorkbenchLocalLab, DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: server.URL, RelayWebSocketURL: "ws://iscp-relay:8080/v2/relay/duplex", RelaySignerIdentity: &signer.Identity, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Access: RelayCredential{"domain", "device", "observed-access", now.Add(15 * time.Minute)}, Refresh: RelayCredential{"domain", "device", "original-refresh", now.Add(time.Hour)}}
	path := filepath.Join(t.TempDir(), "enrollment.json")
	if err := SaveEnrollment(path, bundle); err != nil {
		t.Fatal(err)
	}
	client, err := NewRelayCredentialClient(ProfileLocalLab, path, bundle, device, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return client, bundle, path, calls
}

func TestRejectedLocalAccessRefreshesBeforeTTLAndCoalescesOldObservation(t *testing.T) {
	client, before, path, calls := rejectedAccessFixture(t, "")
	if err := client.ensureAccess(t.Context()); err != nil || calls.Load() != 0 {
		t.Fatal("ordinary access check unexpectedly rotated", err)
	}
	var workers sync.WaitGroup
	errs := make(chan error, 12)
	for range 12 {
		workers.Add(1)
		go func() { defer workers.Done(); errs <- client.refreshRejectedAccess(t.Context(), before.Access.Token) }()
	}
	workers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	after := client.Enrollment()
	if calls.Load() != 1 || after.Access.Token != "next-access" || after.Refresh.Token != "next-refresh" || after.DeviceID != before.DeviceID || after.DomainID != before.DomainID || after.RelayID != before.RelayID || !reflect.DeepEqual(after.RelaySignerIdentity, before.RelaySignerIdentity) {
		t.Fatal("refresh changed identity or rotated twice")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted EnrollmentBundle
	if json.Unmarshal(raw, &persisted) != nil || !reflect.DeepEqual(persisted, after) {
		t.Fatal("successful refresh was not persisted")
	}
	if err := client.refreshRejectedAccess(t.Context(), before.Access.Token); err != nil || calls.Load() != 1 {
		t.Fatal("stale authentication failure rotated newer credential", err)
	}
}

func TestRejectedLocalAccessRefreshPreservesFencesAndOriginalState(t *testing.T) {
	for _, failure := range []string{"changed-pin", "refresh-rejected", "foreign-response", "expired-refresh", "managed-mode", "production-profile", "provider-installed", "empty-observation"} {
		t.Run(failure, func(t *testing.T) {
			client, bundle, path, calls := rejectedAccessFixture(t, failure)
			switch failure {
			case "expired-refresh":
				client.enrollment.Refresh.ExpiresAt = time.Now().Add(-time.Second)
			case "managed-mode":
				client.enrollment.Mode = BundleModeWorkbenchNodeManaged
			case "production-profile":
				client.profile = ProfileProduction
			case "provider-installed":
				client.credentialProvider = &managedCredentialProvider{}
			}
			prior := client.Enrollment()
			disk, _ := os.ReadFile(path)
			observed := bundle.Access.Token
			if failure == "empty-observation" {
				observed = ""
			}
			if err := client.refreshRejectedAccess(t.Context(), observed); err == nil {
				t.Fatal("failed refresh accepted")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(disk, after) || !reflect.DeepEqual(client.Enrollment(), prior) {
				t.Fatal("failed refresh changed credential state")
			}
			expected := int32(0)
			if failure == "refresh-rejected" || failure == "foreign-response" {
				expected = 1
			}
			if calls.Load() != expected {
				t.Fatalf("refresh calls=%d want=%d", calls.Load(), expected)
			}
		})
	}
}
