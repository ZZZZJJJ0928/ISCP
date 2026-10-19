package iscpworkbench

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeclient"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

type responseAuthorityGate struct {
	enabled atomic.Bool
	checks  atomic.Int32
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *responseAuthorityGate) unblock() { g.once.Do(func() { close(g.release) }) }

// This fixture exercises the real signed issuer protocol and the real
// iscpnodeclient.AuthorizationPolicy coordinator, rather than a test cache.
func signedResponseAuthority(t *testing.T, desktop, backend material) (*iscpnodeclient.Client, *responseAuthorityGate, identity.DeviceIdentity, trust.Grant) {
	t.Helper()
	gate := &responseAuthorityGate{started: make(chan struct{}, 32), release: make(chan struct{})}
	t.Cleanup(gate.unblock)
	var issuer *n.Issuer
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		var x n.Exchange
		if err != nil || n.StrictDecode(raw, &x) != nil || r.URL.Path != n.ExchangePath {
			w.WriteHeader(400)
			return
		}
		out, err := issuer.Exchange(r.Context(), x)
		if err != nil {
			code := 503
			if errors.Is(err, n.ErrDenied) {
				code = 403
			}
			w.WriteHeader(code)
			return
		}
		var check n.LifecycleRequest
		if gate.enabled.Load() && x.Step == "renew" && n.StrictDecode(x.Frame, &check) == nil && check.Kind == "check" {
			gate.checks.Add(1)
			gate.started <- struct{}{}
			select {
			case <-gate.release:
			case <-r.Context().Done():
				return
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(server.Close)
	device := func(id string) identity.Device {
		value, err := identity.NewDevice(iscpcrypto.NewProvider(), desktop.device.Identity.DomainID, id, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	signer, inviter, relay := device("response-issuer"), device("response-inviter"), device("response-relay")
	template := n.Credential{Origin: server.URL, TLSCertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), DomainID: desktop.device.Identity.DomainID, RelayID: desktop.enrollment.RelayID, RelaySignerIdentity: relay.Identity, IssuerIdentity: signer.Identity, InvitationSignerIdentity: inviter.Identity, IssuerRoute: "response-authority", ResponderIdentity: backend.device.Identity, DeploymentID: "deployment", OwnerID: "owner"}
	registration := &responseRegistration{preparations: make(map[string]n.RegistrationPreparation), receipts: make(map[string]n.RegistrationReceipt)}
	var err error
	issuer, err = n.New(n.Config{Template: template, Issuer: signer, InvitationSigner: inviter, GrantTTL: 15 * time.Minute}, n.NewMemoryStore(), &responseManagement{}, registration)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := issuer.CreateInvitation(t.Context(), "response test", 10*time.Minute, []string{"workbench.read"}, "response-authority-invitation")
	if err != nil {
		t.Fatal(err)
	}
	client, err := iscpnodeclient.New(encoded, desktop.device, filepath.Join(t.TempDir(), "private-client"))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetInstallationID(newUUID()); err != nil {
		t.Fatal(err)
	}
	enrollment, err := client.Enroll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return client, gate, signer.Identity, enrollment.Grant
}

type responseManagement struct{ active atomic.Bool }

func (*responseManagement) Identity(context.Context) (n.Binding, error) {
	return n.Binding{DeploymentID: "deployment", OwnerID: "owner"}, nil
}
func (m *responseManagement) Client(context.Context, string) (bool, error) {
	return m.active.Load(), nil
}
func (m *responseManagement) CreateClient(_ context.Context, _, key string) (string, error) {
	m.active.Store(true)
	return n.StableClientID("owner", key), nil
}
func (m *responseManagement) RevokeManagedClient(context.Context, string) error {
	m.active.Store(false)
	return nil
}

type responseRegistration struct {
	mu           sync.Mutex
	preparations map[string]n.RegistrationPreparation
	receipts     map[string]n.RegistrationReceipt
}

func (r *responseRegistration) Prepare(_ context.Context, p n.RegistrationPreparation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.preparations[p.OperationID] = p
	return nil
}
func (r *responseRegistration) Commit(_ context.Context, p n.RegistrationCommit) (n.RegistrationReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if receipt, ok := r.receipts[p.OperationID]; ok {
		return receipt, nil
	}
	prep := r.preparations[p.OperationID]
	receipt, err := n.SealRegistrationReceipt(n.RegistrationReceipt{OperationID: p.OperationID, BindingDigest: p.BindingDigest, IssuedAt: time.Now().UTC()}, prep.ReceiptWrapPublicKey, prep.Identity, responseRelayCredentials(prep.Identity))
	r.receipts[p.OperationID] = receipt
	return receipt, err
}
func (r *responseRegistration) Status(_ context.Context, operation, _ string) (n.RegistrationReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	receipt, ok := r.receipts[operation]
	if !ok {
		return receipt, n.ErrDenied
	}
	return receipt, nil
}
func (*responseRegistration) Revoke(context.Context, string, string, uint64) error { return nil }
func (*responseRegistration) Recover(_ context.Context, p n.RegistrationRecovery) (n.RegistrationReceipt, error) {
	return n.SealRegistrationReceipt(n.RegistrationReceipt{OperationID: p.OperationID, BindingDigest: p.BindingDigest, IssuedAt: time.Now().UTC()}, p.ReceiptWrapPublicKey, p.Identity, responseRelayCredentials(p.Identity))
}
func responseRelayCredentials(device identity.DeviceIdentity) n.RelayCredentials {
	return n.RelayCredentials{Access: iscpbridge.RelayCredential{DomainID: device.DomainID, DeviceID: device.DeviceID, Token: "synthetic-access", ExpiresAt: time.Now().Add(time.Hour)}, Refresh: iscpbridge.RelayCredential{DomainID: device.DomainID, DeviceID: device.DeviceID, Token: "synthetic-refresh", ExpiresAt: time.Now().Add(time.Hour)}}
}

// AuthorizationPolicy evaluates Done after registering its in-flight waiter.
// Observing this point makes the coalescing test deterministic without sleeps.
type responseWaiterContext struct {
	context.Context
	once   sync.Once
	joined chan<- struct{}
}

func (c *responseWaiterContext) Done() <-chan struct{} {
	c.once.Do(func() { c.joined <- struct{}{} })
	return c.Context.Done()
}
