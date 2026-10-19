package iscprelayadapter

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	bridge "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
)

func TestControlServiceHTTPSRecoversExpiredOperatorPeerAndRetainsACK(t *testing.T) {
	pool := database(t)
	ctx := t.Context()
	inviter, issuer, responder, relaySigner, serviceActor := device(t, "service-inviter"), device(t, "service-issuer"), device(t, "operator-responder"), device(t, "relay-signer"), device(t, "issuer-service")
	a, err := New(ctx, pool, Config{DomainID: "test-domain", RelayID: "test-relay", InvitationSigner: inviter.Identity, GrantSigner: issuer.Identity, Responder: responder.Identity, ServicePeers: []identity.DeviceIdentity{responder.Identity, serviceActor.Identity}, ControlIssuerActor: &serviceActor.Identity})
	if err != nil {
		t.Fatal(err)
	}
	// Model already operator-enrolled service identities, not invitation clients.
	for _, id := range []identity.DeviceIdentity{responder.Identity, serviceActor.Identity} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = a.claim(ctx, tx, id, false); err == nil {
			err = a.createDevice(ctx, tx, id)
		}
		if err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = a.OperatorBind(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = authority.BootstrapEmpty(ctx, tx, "test-relay", "test-domain", control.RandomID(), control.RandomID(), true); err != nil {
		tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	service, err := NewControlService(ctx, []ScopedNode{{Adapter: a}}, relaySigner, "1")
	if err != nil {
		t.Fatal(err)
	}
	handler := service.Handler()
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v2/control/") && r.URL.Path != control.AuthorityPath {
			t.Errorf("recovery depended on non-control endpoint %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		requests.Add(1)
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	now := time.Now().UTC()
	bundle := bridge.EnrollmentBundle{Type: bridge.EnrollmentBundleType, Mode: bridge.BundleModeWorkbenchNodeManaged, DomainID: responder.Identity.DomainID, DeviceID: responder.Identity.DeviceID, RelayID: "test-relay", RelayBaseURL: server.URL, RelayWebSocketURL: "wss" + strings.TrimPrefix(server.URL, "https") + "/v2/relay/duplex", RelaySignerIdentity: &relaySigner.Identity, InvitationSignerIdentity: &inviter.Identity, TLSCertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), IssuedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour), Access: bridge.RelayCredential{DomainID: responder.Identity.DomainID, DeviceID: responder.Identity.DeviceID, Token: "expired-access", ExpiresAt: now.Add(-time.Hour)}, Refresh: bridge.RelayCredential{DomainID: responder.Identity.DomainID, DeviceID: responder.Identity.DeviceID, Token: "expired-refresh", ExpiresAt: now.Add(-time.Hour)}}
	path := filepath.Join(t.TempDir(), "service.enrollment")
	r, err := bridge.NewRelayCredentialClient(bridge.ProfileProduction, path, bundle, responder, time.Second*5)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.ConfigureServiceCredentialProvider(issuer.Identity); err != nil {
		t.Fatal(err)
	}
	provider := r.CredentialProvider()
	lease, err := provider.EnsureAccess(ctx, r.CredentialBinding())
	if err != nil {
		t.Fatal(err)
	}
	if lease.CredentialGeneration != "2" || lease.Enrollment.DeviceID != responder.Identity.DeviceID || lease.Enrollment.Access.Token == "expired-access" {
		t.Fatal("service identity/generation recovery failed")
	}
	if err = provider.Close(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM iscp_relay.node_grants WHERE device_id=$1", responder.Identity.DeviceID).Scan(&count); err != nil || count != 0 {
		t.Fatal("service recovery manufactured a business Grant", err)
	}
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM iscp_relay.control_operations WHERE actor_device=$1", responder.Identity.DeviceID).Scan(&count); err != nil || count != 1 {
		t.Fatal("service recovery did not retain original ledger", err)
	}
	before := requests.Load()
	reopened, err := bridge.NewRelayCredentialClient(bridge.ProfileProduction, path, lease.Enrollment, responder, time.Second*5)
	if err != nil {
		t.Fatal(err)
	}
	if err = reopened.ConfigureServiceCredentialProvider(issuer.Identity); err != nil {
		t.Fatal(err)
	}
	defer reopened.CredentialProvider().Close()
	again, err := reopened.CredentialProvider().EnsureAccess(ctx, reopened.CredentialBinding())
	if err != nil {
		t.Fatal(err)
	}
	if again.CredentialGeneration != lease.CredentialGeneration || again.Enrollment.Access.Token != lease.Enrollment.Access.Token || requests.Load() != before {
		t.Fatal("restart reissued acknowledged credentials")
	}
}
