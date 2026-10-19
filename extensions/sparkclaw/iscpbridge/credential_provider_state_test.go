package iscpbridge

import (
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func TestCredentialProviderSharedFlightDurableCASAndInvalidation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	device, _ := identity.NewDevice(c.NewProvider(), "domain", "device", now)
	signer, _ := identity.NewDevice(c.NewProvider(), "domain", "relay-signer", now)
	inviter, _ := identity.NewDevice(c.NewProvider(), "domain", "inviter", now)
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	bundle := EnrollmentBundle{Type: EnrollmentBundleType, Mode: BundleModeWorkbenchNodeManaged, DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: server.URL, RelayWebSocketURL: "wss" + strings.TrimPrefix(server.URL, "https") + "/v2/relay/connect", RelaySignerIdentity: &signer.Identity, InvitationSignerIdentity: &inviter.Identity, TLSCertificatePEM: certificate, IssuedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour), Access: RelayCredential{"domain", "device", "expired-access", now.Add(-time.Hour)}, Refresh: RelayCredential{"domain", "device", "expired-refresh", now.Add(-time.Hour)}}
	path := filepath.Join(t.TempDir(), "enrollment.json")
	client, e := NewRelayCredentialClient(ProfileProduction, path, bundle, device, time.Second)
	if e != nil {
		t.Fatalf("expired short credentials blocked cold recovery: %v", e)
	}
	binding := CredentialBinding{DomainID: "domain", DeviceID: "device", ResourceBindingID: "client", TargetServiceID: "relay", IssuerPublicKey: inviter.Identity.PublicKey.Public, RelayPublicKey: signer.Identity.PublicKey.Public, TLSCertificateSHA256: c.Base64URL(c.SHA256([]byte(certificate)))}
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	recover := func(ctx context.Context, got CredentialBinding, expected CredentialGeneration) (CredentialLease, error) {
		n := calls.Add(1)
		if n == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return CredentialLease{}, ctx.Err()
			}
		}
		next := bundle
		next.IssuedAt = now
		next.ExpiresAt = now.Add(time.Hour)
		next.Access = RelayCredential{"domain", "device", "private-access-new", now.Add(30 * time.Minute)}
		next.Refresh = RelayCredential{"domain", "device", "private-refresh-new", now.Add(time.Hour)}
		gen := CredentialGeneration("2")
		if expected == "2" {
			gen = "3"
		}
		if expected == "3" {
			gen = "4"
		}
		revision := "7"
		if gen == "4" {
			revision = "8"
		}
		return CredentialLease{Binding: got, Enrollment: next, CredentialGeneration: gen, AuthorizationRevision: revision, ExpiresAt: next.Access.ExpiresAt}, nil
	}
	if e = client.ConfigureCredentialProvider(binding, recover); e != nil {
		t.Fatal(e)
	}
	provider := client.CredentialProvider()
	defer provider.Close()
	events := provider.Subscribe(t.Context(), binding)
	select {
	case <-events:
		t.Fatal("fabricated cold initial authority")
	default:
	}
	waiter, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := provider.EnsureAccess(waiter, binding); done <- e }()
	<-started
	cancel()
	if e = <-done; e != context.Canceled {
		t.Fatalf("waiter cancellation %v", e)
	}
	other := make(chan CredentialLease, 1)
	go func() {
		v, e := provider.EnsureAccess(context.Background(), binding)
		if e != nil {
			done <- e
		}
		other <- v
	}()
	close(release)
	lease := <-other
	if lease.CredentialGeneration != "2" || calls.Load() != 1 {
		t.Fatal("waiter canceled shared recovery")
	}
	event := <-events
	if event.CredentialGeneration != "2" || event.StateVersion == 0 {
		t.Fatal("invalid state event")
	}
	raw, e := os.ReadFile(path + ".credentials.v2")
	if e != nil || bytes.Contains(raw, []byte("private-access-new")) {
		t.Fatal("credential checkpoint plaintext or absent")
	}
	if e = provider.Invalidate(binding, "1", AuthenticationRequired); e != nil {
		t.Fatal(e)
	}
	_, _ = provider.EnsureAccess(context.Background(), binding)
	if calls.Load() != 1 {
		t.Fatal("stale invalidation changed current generation")
	}
	if e = provider.Invalidate(binding, "2", AccessRejected); e != nil {
		t.Fatal(e)
	}
	next, e := provider.EnsureAccess(context.Background(), binding)
	if e != nil || next.CredentialGeneration != "3" || calls.Load() != 2 {
		t.Fatalf("preTTL rejection looped same token: %v", e)
	}
	if err := provider.Invalidate(binding, "3", RotationRequired); err != nil {
		t.Fatal(err)
	}
	scoped, err := provider.EnsureAccess(context.Background(), binding)
	if err != nil || scoped.AuthorizationRevision != "8" {
		t.Fatal("scope transition", err)
	}
	scopeEvent := <-events
	if scopeEvent.Reason != ScopeChanged || scopeEvent.AuthorizationRevision != "8" {
		t.Fatalf("scope change mislabeled as in-place rotation: %#v", scopeEvent)
	}
	_ = provider.Close()
	reopened, e := NewRelayCredentialClient(ProfileProduction, path, bundle, device, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = reopened.ConfigureCredentialProvider(binding, recover); e != nil {
		t.Fatal(e)
	}
	defer reopened.CredentialProvider().Close()
	current, e := reopened.CredentialProvider().EnsureAccess(context.Background(), binding)
	if e != nil || current.CredentialGeneration != "4" || calls.Load() != 3 {
		t.Fatalf("restart lost durable credential CAS: %v", e)
	}
}
