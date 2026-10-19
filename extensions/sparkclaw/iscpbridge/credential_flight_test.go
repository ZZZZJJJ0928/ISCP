package iscpbridge

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func TestCredentialInvalidationDuringInstallDoesNotJoinRejectedFlight(t *testing.T) {
	testCredentialInvalidationDuringInstallation(t, false)
}
func TestCredentialInvalidationDuringCachedInstallationRechecksDurableState(t *testing.T) {
	testCredentialInvalidationDuringInstallation(t, true)
}
func testCredentialInvalidationDuringInstallation(t *testing.T, cachedFlight bool) {
	now := time.Now().UTC().Truncate(time.Second)
	device, _ := identity.NewDevice(c.NewProvider(), "domain", "device", now)
	signer, _ := identity.NewDevice(c.NewProvider(), "domain", "relay-signer", now)
	issuer, _ := identity.NewDevice(c.NewProvider(), "domain", "issuer", now)
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	bundle := EnrollmentBundle{Type: EnrollmentBundleType, Mode: BundleModeWorkbenchNodeManaged, DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: server.URL, RelayWebSocketURL: "wss" + strings.TrimPrefix(server.URL, "https") + "/v2/relay/duplex", RelaySignerIdentity: &signer.Identity, InvitationSignerIdentity: &issuer.Identity, TLSCertificatePEM: cert, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Access: RelayCredential{"domain", "device", "access", now.Add(time.Hour)}, Refresh: RelayCredential{"domain", "device", "refresh", now.Add(time.Hour)}}
	binding := CredentialBinding{DomainID: "domain", DeviceID: "device", ResourceBindingID: "client", TargetServiceID: "relay", IssuerPublicKey: issuer.Identity.PublicKey.Public, RelayPublicKey: signer.Identity.PublicKey.Public, TLSCertificateSHA256: c.Base64URL(c.SHA256([]byte(cert)))}
	r, err := NewRelayCredentialClient(ProfileProduction, filepath.Join(t.TempDir(), "enrollment"), bundle, device, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	installing, release := make(chan struct{}), make(chan struct{})
	var installs, calls atomic.Int32
	err = r.ConfigureCredentialProviderWithInstallation(binding, func(_ context.Context, _ CredentialBinding, expected CredentialGeneration) (CredentialLease, error) {
		calls.Add(1)
		gen := CredentialGeneration("2")
		if expected == "2" {
			gen = "3"
		}
		next := bundle
		next.Access.Token = "access-" + string(gen)
		next.Refresh.Token = "refresh-" + string(gen)
		return CredentialLease{Binding: binding, Enrollment: next, CredentialGeneration: gen, AuthorizationRevision: "1", ExpiresAt: next.Access.ExpiresAt}, nil
	}, func(ctx context.Context, _ CredentialLease) error {
		blockAt := int32(1)
		if cachedFlight {
			blockAt = 2
		}
		if installs.Add(1) == blockAt {
			close(installing)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	p := r.CredentialProvider()
	defer p.Close()
	if cachedFlight {
		if _, err := p.EnsureAccess(t.Context(), binding); err != nil {
			t.Fatal(err)
		}
	}
	firstLease := make(chan CredentialLease, 1)
	first := make(chan error, 1)
	go func() { lease, err := p.EnsureAccess(t.Context(), binding); firstLease <- lease; first <- err }()
	<-installing
	// Another caller obtains the installed cache while its durable ACK is held.
	cached, err := p.EnsureAccess(t.Context(), binding)
	if err != nil || cached.CredentialGeneration != "2" {
		t.Fatal(err)
	}
	if err = p.Invalidate(binding, "2", AccessRejected); err != nil {
		t.Fatal(err)
	}
	result := make(chan CredentialLease, 1)
	errs := make(chan error, 1)
	go func() { lease, err := p.EnsureAccess(t.Context(), binding); result <- lease; errs <- err }()
	close(release)
	if err = <-first; err != nil {
		t.Fatal(err)
	}
	if lease := <-firstLease; lease.CredentialGeneration != "3" {
		t.Fatalf("initial waiter returned rejected lease: %s", lease.CredentialGeneration)
	}
	lease, err := <-result, <-errs
	if err != nil || lease.CredentialGeneration != "3" || calls.Load() != 2 {
		t.Fatalf("returned rejected completed flight: generation=%s calls=%d err=%v", lease.CredentialGeneration, calls.Load(), err)
	}
}
