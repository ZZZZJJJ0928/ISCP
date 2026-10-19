package iscpnodeissuer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func device(t *testing.T, id string) identity.Device {
	t.Helper()
	d, e := identity.NewDevice(c.NewProvider(), "test-domain", id, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func certificate(t *testing.T) string {
	t.Helper()
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type fakeManagement struct {
	mu      sync.Mutex
	active  map[string]bool
	binding Binding
	creates int
}

func (m *fakeManagement) Identity(context.Context) (Binding, error) { return m.binding, nil }
func (m *fakeManagement) Client(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active[id], nil
}
func (m *fakeManagement) CreateClient(_ context.Context, name, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := StableClientID(m.binding.OwnerID, key)
	if !m.active[id] {
		m.creates++
		m.active[id] = true
	}
	return id, nil
}
func (m *fakeManagement) RevokeManagedClient(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active[id] = false
	return nil
}

type fakeRelay struct {
	mu          sync.Mutex
	prepared    map[string]RegistrationPreparation
	receipts    map[string]RegistrationReceipt
	commits     int
	revocations int
	lose        bool
}

func (r *fakeRelay) Prepare(_ context.Context, p RegistrationPreparation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.prepared[p.OperationID]; ok && old.BindingDigest != p.BindingDigest {
		return ErrConflict
	}
	r.prepared[p.OperationID] = p
	return nil
}
func (r *fakeRelay) Commit(_ context.Context, p RegistrationCommit) (RegistrationReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.receipts[p.OperationID]; ok {
		return old, nil
	}
	prep := r.prepared[p.OperationID]
	if prep.OperationID == "" {
		return RegistrationReceipt{}, ErrDenied
	}
	if identity.VerifyProof(c.NewProvider(), prep.Identity, p.IdentityProof, prep.TicketV3.RelayID, prep.TicketV3.TicketID, time.Now().UTC(), 5*time.Minute) != nil {
		return RegistrationReceipt{}, ErrDenied
	}
	r.commits++
	v, e := SealRegistrationReceipt(RegistrationReceipt{OperationID: p.OperationID, BindingDigest: p.BindingDigest, IssuedAt: time.Now().UTC()}, prep.ReceiptWrapPublicKey, prep.Identity, RelayCredentials{Access: relayToken(prep.Identity, "access"), Refresh: relayToken(prep.Identity, "refresh")})
	r.receipts[p.OperationID] = v
	if r.lose {
		return RegistrationReceipt{}, ErrUnknownOutcome
	}
	return v, e
}
func relayToken(id identity.DeviceIdentity, kind string) iscpbridge.RelayCredential {
	return iscpbridge.RelayCredential{DomainID: id.DomainID, DeviceID: id.DeviceID, Token: kind + "-synthetic-token", ExpiresAt: time.Now().Add(time.Hour).UTC()}
}
func (r *fakeRelay) Status(_ context.Context, id, digest string) (RegistrationReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.receipts[id]
	if !ok || v.BindingDigest != digest {
		return v, ErrDenied
	}
	return v, nil
}
func (r *fakeRelay) Revoke(context.Context, string, string, uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revocations++
	return nil
}
func (r *fakeRelay) Recover(_ context.Context, p RegistrationRecovery) (RegistrationReceipt, error) {
	return SealRegistrationReceipt(RegistrationReceipt{OperationID: p.OperationID, BindingDigest: p.BindingDigest, IssuedAt: time.Now().UTC()}, p.ReceiptWrapPublicKey, p.Identity, RelayCredentials{Access: relayToken(p.Identity, "recovered-access"), Refresh: relayToken(p.Identity, "recovered-refresh")})
}

type fixture struct {
	issuer     *Issuer
	cfg        Config
	store      Store
	management *fakeManagement
	relay      *fakeRelay
	credential Credential
	client     identity.Device
}

func setup(t *testing.T, store Store) *fixture {
	t.Helper()
	signer, inviter, responder, relaysigner := device(t, "grant-signer"), device(t, "invitation-signer"), device(t, "responder"), device(t, "relay-signer")
	v := Credential{Origin: "https://127.0.0.1", TLSCertificatePEM: certificate(t), DomainID: "test-domain", RelayID: "test-relay", RelaySignerIdentity: relaysigner.Identity, IssuerIdentity: signer.Identity, InvitationSignerIdentity: inviter.Identity, IssuerRoute: "test-route", ResponderIdentity: responder.Identity, DeploymentID: "test-deployment", OwnerID: "test-owner"}
	m := &fakeManagement{active: map[string]bool{}, binding: Binding{DeploymentID: v.DeploymentID, OwnerID: v.OwnerID}}
	r := &fakeRelay{prepared: map[string]RegistrationPreparation{}, receipts: map[string]RegistrationReceipt{}}
	cfg := Config{Template: v, Issuer: signer, InvitationSigner: inviter, GrantTTL: time.Minute}
	i, e := New(cfg, store, m, r)
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := i.CreateInvitation(context.Background(), "SparkX", 15*time.Minute, []string{"settings.read"}, "test-operation-creation")
	if e != nil {
		t.Fatal(e)
	}
	credential, e := ParseCredential(encoded, time.Now().UTC(), false)
	if e != nil {
		t.Fatal(e)
	}
	return &fixture{i, cfg, store, m, r, credential, device(t, "sparkx-device")}
}
func exchange(t *testing.T, i *Issuer, cred Credential, op, step string, in, out any) error {
	t.Helper()
	b, _ := json.Marshal(in)
	res, e := i.Exchange(context.Background(), Exchange{1, cred.IssuerRoute, op, cred.InvitationID, step, b})
	if e == nil {
		e = StrictDecode(res.Frame, out)
	}
	return e
}
func provision(t *testing.T, f *fixture) (string, Channel, SealedFrame) {
	t.Helper()
	op := "enrollment-test-operation"
	h, priv, e := NewClientHello(f.credential, f.client, op, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	var server ServerHello
	if e = exchange(t, f.issuer, f.credential, op, "hello", h, &server); e != nil {
		t.Fatal(e)
	}
	ch, e := AcceptServerHello(f.credential, h, server, priv, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	var sf Finished
	if e = exchange(t, f.issuer, f.credential, op, "finish", ch.Finished("client", op), &sf); e != nil {
		t.Fatal(e)
	}
	if ch.VerifyFinished(sf, "server", op) != nil {
		t.Fatal("server did not prove transcript")
	}
	ch.Ready = true
	proof, _ := f.client.CreateProof(c.NewProvider(), f.credential.RelayID, f.credential.InvitationID, c.Base64URL(c.RandomBytes(24)), time.Now().UTC())
	frame, e := SealFrame(ch, op, "client", 1, RedeemRequest{proof, "installation-test-uuid"})
	if e != nil {
		t.Fatal(e)
	}
	return op, ch, frame
}
func TestDistributedChannelKeyConfirmationAndTampering(t *testing.T) {
	f := setup(t, NewMemoryStore())
	op := "channel-test-operation"
	h, priv, e := NewClientHello(f.credential, f.client, op, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	server, chServer, e := NewServerHello(f.credential, h, f.cfg.Issuer, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	ch, e := AcceptServerHello(f.credential, h, server, priv, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	if !c.EqualMAC(ch.Key, chServer.Key) || ch.Ready || chServer.Ready {
		t.Fatal("independent keys failed or Ready prematurely")
	}
	if _, e = SealFrame(ch, op, "client", 1, map[string]string{"x": "y"}); e == nil {
		t.Fatal("not ready channel published plaintext")
	}
	if chServer.VerifyFinished(ch.Finished("client", op), "server", op) == nil {
		t.Fatal("role reflection accepted")
	}
	wrong := f.credential
	wrong.BootstrapSecret = c.Base64URL(c.RandomBytes(32))
	if VerifyClientHello(wrong, h, time.Now()) == nil {
		t.Fatal("wrong secret accepted")
	}
	server.EphemeralPublic = c.Base64URL(c.RandomBytes(32))
	if _, e = AcceptServerHello(f.credential, h, server, priv, time.Now()); e == nil {
		t.Fatal("tampered server accepted")
	}
	ch.Ready = true
	sealed, e := SealFrame(ch, op, "server", 1, map[string]string{"value": "sealed"})
	if e != nil {
		t.Fatal(e)
	}
	var out map[string]string
	if OpenFrame(ch, sealed, op, "client", 1, &out) == nil {
		t.Fatal("wrong direction accepted")
	}
	if OpenFrame(ch, sealed, op, "server", 2, &out) == nil {
		t.Fatal("wrong sequence accepted")
	}
}
func TestConcurrentRedemptionLostResponseAndRestartReplay(t *testing.T) {
	f := setup(t, NewMemoryStore())
	op, ch, req := provision(t, f)
	f.relay.lose = true
	var wg sync.WaitGroup
	responses := make(chan SealedFrame, 12)
	errs := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out SealedFrame
			e := exchange(t, f.issuer, f.credential, op, "redeem", req, &out)
			if e != nil {
				errs <- e
			} else {
				responses <- out
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	close(responses)
	var digest string
	for sealed := range responses {
		if digest == "" {
			digest = Digest(sealed)
		} else if Digest(sealed) != digest {
			t.Fatal("result replay changed")
		}
		var result EnrollmentResult
		if OpenFrame(ch, sealed, op, "server", 1, &result) != nil || VerifyObject("sparkclaw.iscp.enrollment-result.v1", result, f.cfg.Issuer.Identity, result.Signature) != nil || result.InstallationID != "installation-test-uuid" {
			t.Fatal("result signature/binding failed")
		}
	}
	if f.relay.commits != 1 || f.management.creates != 1 {
		t.Fatal("duplicated side effects", f.relay.commits, f.management.creates)
	}
	restarted, e := New(f.cfg, f.store, f.management, f.relay)
	if e != nil {
		t.Fatal(e)
	}
	var again SealedFrame
	if e = exchange(t, restarted, f.credential, op, "redeem", req, &again); e != nil || Digest(again) != digest {
		t.Fatal("restart replay failed", e)
	}
	other := device(t, "other-sparkx")
	h, _, _ := NewClientHello(f.credential, other, "other-operation", time.Now().UTC())
	var sh ServerHello
	if exchange(t, restarted, f.credential, "other-operation", "hello", h, &sh) == nil {
		t.Fatal("credential consumed twice")
	}
	req.Ciphertext = c.Base64URL(c.RandomBytes(64))
	if exchange(t, restarted, f.credential, op, "redeem", req, &again) == nil {
		t.Fatal("different input accepted")
	}
}
func TestRenewRecoveryAndRevocationDoNotWidenAuthority(t *testing.T) {
	f := setup(t, NewMemoryStore())
	op, _, req := provision(t, f)
	var sealed SealedFrame
	if exchange(t, f.issuer, f.credential, op, "redeem", req, &sealed) != nil {
		t.Fatal("enroll failed")
	}
	renew, priv, e := NewLifecycleRequest("renew", "renew-operation", f.credential.InvitationID, 1, "", f.client, f.cfg.Issuer.Identity.DeviceID, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	var wire LifecycleResponse
	if e = exchange(t, f.issuer, f.credential, renew.OperationID, "renew", renew, &wire); e != nil {
		t.Fatal(e)
	}
	result, e := OpenLifecycle(renew, wire, priv)
	if e != nil || result.Grant == nil || result.Grant.Audience != f.credential.ResponderIdentity.DeviceID || result.Grant.ConfirmationThumbprint != f.client.Identity.PublicKey.KID || len(result.Scopes) != 1 {
		t.Fatal("renew bindings", e)
	}
	original := Digest(wire)
	if exchange(t, f.issuer, f.credential, renew.OperationID, "renew", renew, &wire) != nil || Digest(wire) != original {
		t.Fatal("renew replay changed")
	}
	if e = f.issuer.Revoke(context.Background(), f.credential.InvitationID, "revoke-operation", 1); e != nil {
		t.Fatal(e)
	}
	if e := exchange(t, f.issuer, f.credential, renew.OperationID, "renew", renew, &wire); e != nil {
		t.Fatal(e)
	}
	revoked, e := OpenLifecycle(renew, wire, priv)
	if e != nil || revoked.State != "revoked" || revoked.Grant != nil {
		t.Fatal("old renewal revived revocation")
	}
	registry, e := f.issuer.Registry(context.Background())
	if e != nil || !registry.Peers[0].Revoked || registry.Peers[0].AuthorizationRevision != 2 || f.relay.revocations != 1 {
		t.Fatal("revocation tombstone", e)
	}
}
func TestExpiredAndWrongKeyFailClosed(t *testing.T) {
	f := setup(t, NewMemoryStore())
	v := f.credential
	v.ExpiresAt = v.IssuedAt.Add(time.Second)
	v, _ = SignCredential(v, f.cfg.InvitationSigner)
	if v.Validate(v.ExpiresAt, false) != ErrExpired {
		t.Fatal("expired credential admitted")
	}
	h, _, _ := NewClientHello(f.credential, f.client, "hello-expired-proof", time.Now().Add(-time.Hour))
	if VerifyClientHello(f.credential, h, time.Now()) == nil {
		t.Fatal("expired proof admitted")
	}
	h, _, _ = NewClientHello(f.credential, f.client, "hello-wrong-key", time.Now())
	h.Identity = device(t, "wrong-device").Identity
	if VerifyClientHello(f.credential, h, time.Now()) == nil {
		t.Fatal("identity substitution accepted")
	}
}
func TestPostgresEncryptedRestartAndConcurrentConsumption(t *testing.T) {
	dsn := os.Getenv("SC_ISCP_NODE_TEST_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL integration DB required")
	}
	key := c.RandomBytes(32)
	store, e := NewPostgresStore(context.Background(), dsn, key)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	f := setup(t, store)
	op, _, req := provision(t, f)
	var out SealedFrame
	if e = exchange(t, f.issuer, f.credential, op, "redeem", req, &out); e != nil {
		t.Fatal(e)
	}
	store.Close()
	reopened, e := NewPostgresStore(context.Background(), dsn, key)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	i, e := New(f.cfg, reopened, f.management, f.relay)
	if e != nil {
		t.Fatal(e)
	}
	var replay SealedFrame
	if e = exchange(t, i, f.credential, op, "redeem", req, &replay); e != nil || Digest(out) != Digest(replay) {
		t.Fatal("PG restart lost receipt", e)
	}
	var ciphertext []byte
	if e = reopened.pool.QueryRow(context.Background(), `SELECT ciphertext FROM sparkclaw_iscp_issuer_state WHERE id=$1`, f.credential.InvitationID).Scan(&ciphertext); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(ciphertext, []byte(f.credential.BootstrapSecret)) || bytes.Contains(ciphertext, []byte("synthetic-token")) {
		t.Fatal("secret persisted in plaintext")
	}
	_, _ = reopened.pool.Exec(context.Background(), `DELETE FROM sparkclaw_iscp_issuer_state WHERE id=$1`, f.credential.InvitationID)
}
