package iscpnodeclient

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type management struct {
	mu     sync.Mutex
	active map[string]bool
}

func (m *management) Identity(context.Context) (n.Binding, error) {
	return n.Binding{DeploymentID: "deployment", OwnerID: "owner"}, nil
}
func (m *management) Client(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active[id], nil
}
func (m *management) CreateClient(_ context.Context, _, key string) (string, error) {
	id := n.StableClientID("owner", key)
	m.mu.Lock()
	m.active[id] = true
	m.mu.Unlock()
	return id, nil
}
func (m *management) RevokeManagedClient(_ context.Context, id string) error {
	m.mu.Lock()
	m.active[id] = false
	m.mu.Unlock()
	return nil
}

type registration struct {
	mu       sync.Mutex
	preps    map[string]n.RegistrationPreparation
	receipts map[string]n.RegistrationReceipt
	commits  int
}

func (r *registration) Prepare(_ context.Context, p n.RegistrationPreparation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.preps[p.OperationID] = p
	return nil
}
func (r *registration) Commit(_ context.Context, p n.RegistrationCommit) (n.RegistrationReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.receipts[p.OperationID]; ok {
		return v, nil
	}
	prep := r.preps[p.OperationID]
	r.commits++
	v, e := n.SealRegistrationReceipt(n.RegistrationReceipt{OperationID: p.OperationID, BindingDigest: p.BindingDigest, IssuedAt: time.Now().UTC()}, prep.ReceiptWrapPublicKey, prep.Identity, n.RelayCredentials{Access: iscpbridge.RelayCredential{DomainID: prep.Identity.DomainID, DeviceID: prep.Identity.DeviceID, Token: "syntheticaccess", ExpiresAt: time.Now().Add(time.Hour)}, Refresh: iscpbridge.RelayCredential{DomainID: prep.Identity.DomainID, DeviceID: prep.Identity.DeviceID, Token: "syntheticrefresh", ExpiresAt: time.Now().Add(time.Hour)}})
	r.receipts[p.OperationID] = v
	return v, e
}
func (r *registration) Status(_ context.Context, op, _ string) (n.RegistrationReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.receipts[op]
	if !ok {
		return v, n.ErrDenied
	}
	return v, nil
}
func (r *registration) Revoke(context.Context, string, string, uint64) error { return nil }
func (r *registration) Recover(_ context.Context, p n.RegistrationRecovery) (n.RegistrationReceipt, error) {
	return n.SealRegistrationReceipt(n.RegistrationReceipt{OperationID: p.OperationID, BindingDigest: p.BindingDigest, IssuedAt: time.Now().UTC()}, p.ReceiptWrapPublicKey, p.Identity, n.RelayCredentials{Access: iscpbridge.RelayCredential{DomainID: p.Identity.DomainID, DeviceID: p.Identity.DeviceID, Token: "recoveredaccess", ExpiresAt: time.Now().Add(time.Hour)}, Refresh: iscpbridge.RelayCredential{DomainID: p.Identity.DomainID, DeviceID: p.Identity.DeviceID, Token: "recoveredrefresh", ExpiresAt: time.Now().Add(time.Hour)}})
}
func testDevice(t *testing.T, id string) identity.Device {
	d, e := identity.NewDevice(c.NewProvider(), "test-domain", id, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func setupClient(t *testing.T) (*Client, *n.Issuer, *registration, string, *bool) {
	return setupClientTTL(t, time.Minute)
}
func setupClientTTL(t *testing.T, ttl time.Duration) (*Client, *n.Issuer, *registration, string, *bool) {
	return setupClientStore(t, ttl, n.NewMemoryStore(), "create-invite-operation")
}
func setupClientStore(t *testing.T, ttl time.Duration, store n.Store, operation string) (*Client, *n.Issuer, *registration, string, *bool) {
	t.Helper()
	var issuer *n.Issuer
	drop := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var x n.Exchange
		if n.StrictDecode(raw, &x) != nil || r.URL.Path != n.ExchangePath {
			w.WriteHeader(400)
			return
		}
		out, e := issuer.Exchange(r.Context(), x)
		if e != nil {
			status := 503
			if errors.Is(e, n.ErrDenied) {
				status = 403
			}
			w.WriteHeader(status)
			return
		}
		if drop && x.Step == "redeem" {
			drop = false
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(server.Close)
	signer, inviter, responder, relay := testDevice(t, "issuer"), testDevice(t, "inviter"), testDevice(t, "responder"), testDevice(t, "relay")
	template := n.Credential{Origin: server.URL, TLSCertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), DomainID: "test-domain", RelayID: "test-relay", RelaySignerIdentity: relay.Identity, IssuerIdentity: signer.Identity, InvitationSignerIdentity: inviter.Identity, IssuerRoute: "node-route", ResponderIdentity: responder.Identity, DeploymentID: "deployment", OwnerID: "owner"}
	m := &management{active: map[string]bool{}}
	reg := &registration{preps: map[string]n.RegistrationPreparation{}, receipts: map[string]n.RegistrationReceipt{}}
	var e error
	issuer, e = n.New(n.Config{Template: template, Issuer: signer, InvitationSigner: inviter, GrantTTL: ttl}, store, m, reg)
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := issuer.CreateInvitation(context.Background(), "SparkX", 10*time.Minute, []string{"settings.read"}, operation)
	if e != nil {
		t.Fatal("invitation", e)
	}
	parsed, pe := n.ParseCredential(encoded, time.Now().UTC(), true)
	if pe != nil {
		t.Fatal("parse", pe)
	}
	_ = parsed
	directory := privateTestDir(t)
	cl, e := New(encoded, testDevice(t, "desktop-client"), directory)
	if e != nil {
		t.Fatal("client-construction", e)
	}
	if e = cl.SetInstallationID("original-native-installation-uuid"); e != nil {
		t.Fatal(e)
	}
	return cl, issuer, reg, encoded, &drop
}
func TestTLSProvisioningRestartReplayAndLifecycle(t *testing.T) {
	cl, i, reg, encoded, drop := setupClient(t)
	*drop = true
	if _, e := cl.Enroll(context.Background()); e == nil {
		t.Fatal("lost response should remain pending")
	}
	again, e := New(encoded, cl.device, cl.directory)
	if e != nil {
		t.Fatal(e)
	}
	_ = again.SetInstallationID("original-native-installation-uuid")
	result, e := again.Enroll(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if result.InstallationID != "original-native-installation-uuid" || result.Enrollment.Access.Token != "syntheticaccess" || reg.commits != 1 {
		t.Fatal("result/receipt/device binding")
	}
	v, _ := n.ParseCredential(encoded, time.Now(), false)
	pending, e := os.ReadFile(filepath.Join(cl.directory, "enrollment.pending"))
	if e != nil || bytes.Contains(pending, []byte(v.BootstrapSecret)) || bytes.Contains(pending, []byte("syntheticaccess")) {
		t.Fatal("pending state exposed enrollment secret")
	}
	grant, e := again.Renew(context.Background(), result.Grant)
	if e != nil {
		t.Fatal(e)
	}
	if e = again.AcceptGrant(grant); e != nil {
		t.Fatal(e)
	}
	if e = again.CommitRenewal(); e != nil {
		t.Fatal(e)
	}
	if again.HasPendingRenewal() {
		t.Fatal("renewal result not committed")
	}
	policy, e := again.AuthorizationPolicy(context.Background())
	if e != nil || policy.Revision != 1 || !policy.Allows("settings.read") {
		t.Fatal("standing policy", e)
	}
	if e = i.Revoke(context.Background(), v.InvitationID, "owner-revoke-operation", 1); e != nil {
		t.Fatal(e)
	}
	if _, e = again.AuthorizationPolicy(context.Background()); !errors.Is(e, iscpbridge.ErrAuthorizationRevoked) {
		t.Fatal("signed revocation not classified", e)
	}
	if _, e = again.Renew(context.Background(), grant); e == nil {
		t.Fatal("revoked grant renewed")
	}
}
func TestWrongOriginCertificateAndConsumedCredentialDeviceRejected(t *testing.T) {
	cl, _, _, encoded, _ := setupClient(t)
	result, e := cl.Enroll(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	other, e := New(encoded, testDevice(t, "another-device"), privateTestDir(t))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = other.Enroll(context.Background()); e == nil {
		t.Fatal("consumed credential enrolled second device")
	}
	cfg := cl.StoredConfig()
	cfg.TLSCertificatePEM = "invalid-certificate"
	if _, e = NewStored(cfg, cl.device, privateTestDir(t), result.Grant); e == nil {
		t.Fatal("invalid TLS pin accepted")
	}
}
func TestDeletionAndBothExpiredTransportRecovery(t *testing.T) {
	cl, _, _, _, _ := setupClient(t)
	result, e := cl.Enroll(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	cl.previous = result.Grant
	recovered, e := cl.RecoverTransport(context.Background())
	if e != nil || recovered.RelayCredentials == nil || recovered.RelayCredentials.Access.Token != "recoveredaccess" {
		t.Fatal("cold recovery", e)
	}
	if e = cl.AcceptGrant(*recovered.Grant); e != nil {
		t.Fatal(e)
	}
	if e = cl.CommitRenewal(); e != nil {
		t.Fatal(e)
	}
	receipt, e := cl.DeleteAuthorization(context.Background(), "self-delete-operation", 1)
	if e != nil || receipt.AuthorizationRevision != 2 {
		t.Fatal("delete", e)
	}
	again, e := cl.AuthorizationDeletionReceipt(context.Background(), "self-delete-operation", 1)
	if e != nil || again != receipt {
		t.Fatal("delete receipt replay", e)
	}
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "private")
	if e := os.Mkdir(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}

func TestExpiredKnownRenewalRetiresWithAppliedReceiptAndPendingKindIsolation(t *testing.T) {
	cl, _, _, _, _ := setupClientTTL(t, time.Second)
	result, e := cl.Enroll(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	grant, e := cl.Renew(context.Background(), result.Grant)
	if e != nil {
		t.Fatal(e)
	}
	kind, e := cl.PendingLifecycleKind()
	if e != nil || kind != "renew" {
		t.Fatal(kind, e)
	}
	if _, e = cl.RecoverTransport(context.Background()); e != n.ErrConflict {
		t.Fatal("pending renewal was mistaken for transport recovery", e)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, e = cl.ResolvePendingLifecycle(context.Background()); !errors.Is(e, iscpbridge.ErrGrantRenewalResultExpired) {
		t.Fatal("expired authenticated response not retired", e)
	}
	if cl.HasPendingRenewal() {
		t.Fatal("known retired operation remained pending")
	}
	fresh, e := cl.Renew(context.Background(), grant)
	if e != nil || fresh.GrantID == grant.GrantID {
		t.Fatal("fresh renewal did not resume", e)
	}
	if e = cl.AcceptGrant(fresh); e != nil {
		t.Fatal(e)
	}
	if e = cl.CommitRenewal(); e != nil {
		t.Fatal(e)
	}
}
