package iscpworkbench

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeclient"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

func nodeConfigurationFixture(t *testing.T) (string, Config) {
	t.Helper()
	m, _ := testMaterials(t)
	now := time.Now().UTC()
	provider := c.NewProvider()
	issuer, _ := identity.NewDevice(provider, m.device.Identity.DomainID, "node-grant-signer", now)
	invitation, _ := identity.NewDevice(provider, m.device.Identity.DomainID, "node-invitation-signer", now)
	relay, _ := identity.NewDevice(provider, m.device.Identity.DomainID, "node-relay-signer", now)
	m.issuer = issuer.Identity
	m.grant, _ = trust.SignGrant(provider, issuer, trust.Grant{GrantID: newUUID(), RevocationEpoch: 1, SubjectDeviceID: m.device.Identity.DeviceID, Audience: m.peer.DeviceID, ConfirmationThumbprint: m.device.Identity.PublicKey.KID, Permissions: []string{Permission}, RelayConstraints: []string{m.enrollment.RelayID}, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	m.enrollment.Mode = iscpbridge.BundleModeWorkbenchNodeManaged
	m.enrollment.TrustRootIdentity = identity.DeviceIdentity{}
	m.enrollment.InvitationSignerIdentity = &invitation.Identity
	m.enrollment.RelaySignerIdentity = &relay.Identity
	m.enrollment.TLSCertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	m.enrollment.RelayBaseURL = "https://127.0.0.1:443"
	m.enrollment.RelayWebSocketURL = "wss://127.0.0.1:443/v2/relay/connect"
	path := writeFixtureConfig(t, m, RoleInitiator)
	base := filepath.Dir(path)
	write := func(name string, v any) {
		raw, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(base, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{SchemaVersion: 2, Mode: "node-managed", Role: RoleInitiator, RelayProfile: iscpbridge.ProfileProduction, ExpectedInstallationID: newUUID(), IdentityDirectory: base, IdentityKeyBackend: "file", EnrollmentFile: filepath.Join(base, "enrollment.json"), PeerIdentityFile: filepath.Join(base, "peer.json"), IssuerIdentityFile: filepath.Join(base, "issuer.json"), GrantFile: filepath.Join(base, "grant.json"), InvitationIdentityFile: filepath.Join(base, "invitation.json"), IssuerControlFile: filepath.Join(base, "issuer-control.json"), Binding: &Binding{"deployment", "owner", "client"}}
	write("invitation.json", invitation.Identity)
	stored := iscpnodeclient.StoredConfig{Origin: m.enrollment.RelayBaseURL, TLSCertificatePEM: m.enrollment.TLSCertificatePEM, IssuerRoute: "node", InvitationID: "invitation", IssuerIdentity: issuer.Identity, RelaySignerIdentity: relay.Identity, ResponderIdentity: m.peer, Binding: iscpnodeissuer.Binding{DeploymentID: "deployment", OwnerID: "owner", ClientID: "client"}, Revision: 1, Scopes: []string{"workbench.read"}, RelayID: m.enrollment.RelayID}
	write("issuer-control.json", stored)
	write("profile.json", cfg)
	return path, cfg
}

func TestNodeManagedConfigurationHasSeparateAuthoritiesAndNativeBinding(t *testing.T) {
	path, _ := nodeConfigurationFixture(t)
	if _, err := LoadConfig(path); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"local-relabel", "missing-invitation", "authority-reuse", "changed-control-peer", "changed-installation", "public-control-file"} {
		t.Run(scenario, func(t *testing.T) {
			path, cfg := nodeConfigurationFixture(t)
			var b iscpbridge.EnrollmentBundle
			raw, _ := os.ReadFile(cfg.EnrollmentFile)
			if json.Unmarshal(raw, &b) != nil {
				t.Fatal("fixture")
			}
			switch scenario {
			case "local-relabel":
				b.Mode = iscpbridge.BundleModeWorkbenchLocalLab
			case "missing-invitation":
				b.InvitationSignerIdentity = nil
			case "authority-reuse":
				b.InvitationSignerIdentity = b.RelaySignerIdentity
				raw, _ := json.Marshal(b.RelaySignerIdentity)
				_ = os.WriteFile(cfg.InvitationIdentityFile, raw, 0600)
			case "changed-control-peer":
				var stored iscpnodeclient.StoredConfig
				raw, _ := os.ReadFile(cfg.IssuerControlFile)
				_ = json.Unmarshal(raw, &stored)
				stored.ResponderIdentity.DeviceID = "other-peer"
				raw, _ = json.Marshal(stored)
				_ = os.WriteFile(cfg.IssuerControlFile, raw, 0600)
			case "changed-installation":
				cfg.ExpectedInstallationID = ""
				raw, _ := json.Marshal(cfg)
				_ = os.WriteFile(path, raw, 0600)
			case "public-control-file":
				_ = os.Chmod(cfg.IssuerControlFile, 0644)
			}
			raw, _ = json.Marshal(b)
			_ = os.WriteFile(cfg.EnrollmentFile, raw, 0600)
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("invalid self-hosted trust profile accepted")
			}
		})
	}
}
