package iscprelayadapter

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	gate "github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	ref "github.com/Infinimesh-ai/ISCP/pkg/server/relay"
	"github.com/jackc/pgx/v5/pgxpool"
)

type nodeFixture struct {
	cfg                                NodeConfig
	invite, signer, responder, service identity.Device
}

func multiNode(t *testing.T, label string) nodeFixture {
	t.Helper()
	f := nodeFixture{invite: device(t, "invite-"+label), signer: device(t, "grant-"+label), responder: device(t, "responder-"+label), service: device(t, "control-"+label)}
	f.cfg = NodeConfig{IssuerRoute: "node-" + label, ManagedSocket: "/run/iscp-relay/" + label + ".sock", InvitationSigner: f.invite.Identity, GrantSigner: f.signer.Identity, Responder: f.responder.Identity, ServicePeers: []identity.DeviceIdentity{f.responder.Identity, f.service.Identity}}
	return f
}
func multiConfig(nodes ...nodeFixture) MultiConfig {
	out := MultiConfig{SchemaVersion: 2, DomainID: "test-domain", RelayID: "test-relay"}
	for _, n := range nodes {
		out.Nodes = append(out.Nodes, n.cfg)
	}
	return out
}
func adapterFor(t *testing.T, m *Manager, route string) *Adapter {
	t.Helper()
	for _, n := range m.Nodes() {
		if n.IssuerRoute == route {
			return n.Adapter
		}
	}
	t.Fatal("missing adapter")
	return nil
}
func commitClient(t *testing.T, a *Adapter, f nodeFixture, d identity.Device, op string) (node.RegistrationPreparation, node.RegistrationReceipt, node.RelayCredentials) {
	t.Helper()
	p, key := prep(t, a, f.invite, f.signer, d, op)
	if e := a.Prepare(t.Context(), p); e != nil {
		t.Fatal(e)
	}
	r, e := a.Commit(t.Context(), node.RegistrationCommit{OperationID: op, BindingDigest: p.BindingDigest, IdentityProof: proof(t, d, p.TicketV3.TicketID), TicketV3: p.TicketV3})
	if e != nil {
		t.Fatal(e)
	}
	tokens, e := node.OpenRegistrationReceipt(r, key, d.Identity)
	if e != nil {
		t.Fatal(e)
	}
	return p, r, tokens
}
func managedRefresh(t *testing.T, manager interface {
	Refresh(*http.Request) (json.RawMessage, error)
}, d identity.Device, token, op string) (json.RawMessage, []byte, error) {
	t.Helper()
	request, key := refreshBuilder(t, d, token, op)
	raw, e := manager.Refresh(request())
	return raw, key, e
}
func refreshBuilder(t *testing.T, d identity.Device, token, op string) (func() *http.Request, []byte) {
	t.Helper()
	_, reader, proof, wrap, key := refreshRequest(t, d, token, op)
	body, _ := io.ReadAll(reader)
	pr, _ := json.Marshal(proof)
	return func() *http.Request {
		req := httptest.NewRequest("POST", "/v2/relay/devices/refresh-access", bytes.NewReader(body))
		req.Header.Set("Idempotency-Key", op)
		req.Header.Set("X-SparkClaw-Refresh-Wrap-Key", wrap)
		req.Header.Set("X-SparkClaw-Refresh-Proof", c.Base64URL(pr))
		req.Header.Set("X-SparkClaw-Authority", "node-b")
		return req
	}, key
}
func recoveryFixture(t *testing.T, a *Adapter, signer, client identity.Device, op string) (node.RegistrationRecovery, []byte) {
	t.Helper()
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	g, e := trust.SignGrant(c.NewProvider(), signer, trust.Grant{GrantID: "recovered-" + op, SubjectDeviceID: client.Identity.DeviceID, ConfirmationThumbprint: client.Identity.PublicKey.KID, Audience: a.cfg.Responder.DeviceID, Permissions: []string{node.Permission}, RelayConstraints: []string{a.cfg.RelayID}, RevocationEpoch: 2, NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	p := node.RegistrationRecovery{OperationID: op, Identity: client.Identity, Grant: g, Revision: 2, ReceiptWrapPublicKey: c.Base64URL(k.PublicKey().Bytes())}
	p.Proof = proof(t, client, op+"\x00"+p.ReceiptWrapPublicKey)
	p.BindingDigest = node.Digest(p)
	return p, k.Bytes()
}
func operatorDevice(t *testing.T, pool *pgxpool.Pool, id identity.DeviceIdentity, status string) {
	t.Helper()
	raw, _ := json.Marshal(id)
	canon, _ := node.Canonical(id)
	tp, _ := identity.Thumbprint(id)
	uid, _ := postgres.NewUUIDv7Like(time.Now())
	_, e := pool.Exec(t.Context(), "INSERT INTO iscp_relay.devices(id,domain_id,device_id,identity_raw,identity_canonical,public_key_thumbprint,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8)", postgres.UUIDString(uid), id.DomainID, id.DeviceID, raw, canon, tp, status, time.Now())
	if e != nil {
		t.Fatal(e)
	}
}
func serviceRequest(t *testing.T, d identity.Device, op string) (ServiceRecovery, []byte) {
	t.Helper()
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	p := ServiceRecovery{OperationID: op, Identity: d.Identity, ReceiptWrapPublicKey: c.Base64URL(k.PublicKey().Bytes())}
	p.Proof = proof(t, d, strings.Join([]string{"sparkclaw/iscp-node/service-recovery/v1", op, p.ReceiptWrapPublicKey}, "\x00"))
	return p, k.Bytes()
}
func serviceCall(m interface {
	ServiceRecover(*http.Request) (json.RawMessage, error)
}, p ServiceRecovery) (json.RawMessage, error) {
	raw, _ := json.Marshal(p)
	return m.ServiceRecover(httptest.NewRequest("POST", "/api/sparkclaw/iscp-control/v1/service-recover", bytes.NewReader(raw)))
}

func TestMultiAuthorityLifecycleIsolationAndRestart(t *testing.T) {
	pool := database(t)
	ctx := t.Context()
	fa, fb := multiNode(t, "a"), multiNode(t, "b")
	cfg := multiConfig(fa, fb)
	m, e := NewManager(ctx, pool, cfg)
	if e != nil {
		t.Fatal(e)
	}
	a, b := adapterFor(t, m, fa.cfg.IssuerRoute), adapterFor(t, m, fb.cfg.IssuerRoute)
	da, db := device(t, "client-a"), device(t, "client-b")
	pa, _, ta := commitClient(t, a, fa, da, "same-register-operation")
	pb, _, tb := commitClient(t, b, fb, db, "same-register-operation")
	if _, e = a.Status(ctx, pb.OperationID, pb.BindingDigest); e == nil {
		t.Fatal("foreign receipt disclosed")
	}
	if e = a.Revoke(ctx, "foreign-revoke-operation", db.Identity.DeviceID, 2); e == nil {
		t.Fatal("cross-authority revoke accepted")
	}
	if e = b.Revoke(ctx, "foreign-revoke-operation", da.Identity.DeviceID, 2); e == nil {
		t.Fatal("reverse revoke accepted")
	}
	hostile, _ := prep(t, b, fb.invite, fb.signer, da, "foreign-claim-operation")
	if e = b.Prepare(ctx, hostile); e == nil {
		t.Fatal("foreign authority took a known device")
	}
	if _, _, e = managedRefresh(t, b, da, ta.Refresh.Token, "foreign-refresh-operation"); e == nil {
		t.Fatal("foreign direct adapter refreshed a device")
	}
	// An attacker-controlled routing header cannot override durable token ownership.
	retryA, ka := refreshBuilder(t, da, ta.Refresh.Token, "same-refresh-operation")
	ra, e := m.Refresh(retryA())
	if e != nil {
		t.Fatal(e)
	}
	rb, kb, e := managedRefresh(t, m, db, tb.Refresh.Token, "same-refresh-operation")
	if e != nil {
		t.Fatal(e)
	}
	var ar, br node.RegistrationReceipt
	json.Unmarshal(ra, &ar)
	json.Unmarshal(rb, &br)
	if _, e = node.OpenRegistrationReceipt(ar, ka, da.Identity); e != nil {
		t.Fatal(e)
	}
	if _, e = node.OpenRegistrationReceipt(br, kb, db.Identity); e != nil {
		t.Fatal(e)
	}
	restarted, e := NewManager(ctx, pool, cfg)
	if e != nil {
		t.Fatal(e)
	}
	// Exact retry, including an expired original proof, remains sealed and node-owned.
	a = adapterFor(t, restarted, fa.cfg.IssuerRoute)
	a.Now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if replay, e := restarted.Refresh(retryA()); e != nil || !bytes.Equal(ra, replay) {
		t.Fatal("sealed refresh replay lost scoped receipt after proof expiry", e)
	}
	if r, e := a.Status(ctx, pa.OperationID, pa.BindingDigest); e != nil || r.DeviceID != da.Identity.DeviceID {
		t.Fatal("registration receipt lost", e)
	}
	a.Now = time.Now
	if bytes.Equal(ra, rb) || ar.DeviceID == br.DeviceID {
		t.Fatal("two authorities shared a receipt")
	}
	b = adapterFor(t, restarted, fb.cfg.IssuerRoute)
	foreign, _ := recoveryFixture(t, b, fb.signer, da, "foreign-recovery-operation")
	if _, e = b.Recover(ctx, foreign); e == nil || e.Error() != "device_not_owned" {
		t.Fatal("foreign issuer's fully signed recovery crossed ownership", e)
	}
	for _, x := range []struct {
		a              *Adapter
		signer, client identity.Device
	}{{a, fa.signer, da}, {b, fb.signer, db}} {
		p, key := recoveryFixture(t, x.a, x.signer, x.client, "same-recovery-operation")
		receipt, e := x.a.Recover(ctx, p)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = node.OpenRegistrationReceipt(receipt, key, x.client.Identity); e != nil {
			t.Fatal(e)
		}
		if replay, e := x.a.Recover(ctx, p); e != nil || !bytes.Equal(canonical(receipt), canonical(replay)) {
			t.Fatal("recovery replay changed", e)
		}
	}
	operatorDevice(t, pool, fa.service.Identity, "active")
	operatorDevice(t, pool, fb.service.Identity, "active")
	sa, ska := serviceRequest(t, fa.service, "same-service-operation")
	sb, skb := serviceRequest(t, fb.service, "same-service-operation")
	sra, e := serviceCall(restarted, sa)
	if e != nil {
		t.Fatal(e)
	}
	srb, e := serviceCall(restarted, sb)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = serviceCall(adapterFor(t, restarted, fb.cfg.IssuerRoute), sa); e == nil {
		t.Fatal("service recovery crossed authority")
	}
	var sr node.RegistrationReceipt
	json.Unmarshal(sra, &sr)
	if _, e = node.OpenRegistrationReceipt(sr, ska, fa.service.Identity); e != nil {
		t.Fatal(e)
	}
	json.Unmarshal(srb, &sr)
	if _, e = node.OpenRegistrationReceipt(sr, skb, fb.service.Identity); e != nil {
		t.Fatal(e)
	}
	a.Now = time.Now
	b = adapterFor(t, restarted, fb.cfg.IssuerRoute)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, x := range []struct {
		a   *Adapter
		dev string
	}{{a, da.Identity.DeviceID}, {b, db.Identity.DeviceID}} {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- x.a.Revoke(ctx, "same-revoke-operation", x.dev, 3) }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if _, e = a.Status(ctx, pa.OperationID, pa.BindingDigest); e == nil {
		t.Fatal("revoked receipt replayed")
	}
	if _, e = b.Status(ctx, pb.OperationID, pb.BindingDigest); e == nil {
		t.Fatal("other revoked receipt replayed")
	}
	var count int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM iscp_relay.node_revocations WHERE operation_id='same-revoke-operation'").Scan(&count); e != nil || count != 2 {
		t.Fatal("operation namespaces collapsed", e, count)
	}
}

func TestLegacyMigrationRequiresExplicitPinsPreservesUnknownAndExpiredReceipts(t *testing.T) {
	pool := database(t)
	ctx := t.Context()
	fa, fb := multiNode(t, "legacy"), multiNode(t, "new")
	cfg := Config{DomainID: "test-domain", RelayID: "test-relay", InvitationSigner: fa.invite.Identity, GrantSigner: fa.signer.Identity, Responder: fa.responder.Identity, ServicePeers: fa.cfg.ServicePeers}
	a, e := New(ctx, pool, cfg)
	if e != nil {
		t.Fatal(e)
	}
	d := device(t, "legacy-client")
	p, key := prep(t, a, fa.invite, fa.signer, d, "legacy-registration-operation")
	at := time.Now().UTC().Add(-2 * time.Hour)
	p.Grant.NotBefore = at
	p.Grant.ExpiresAt = at.Add(time.Hour)
	p.Grant, e = trust.SignGrant(c.NewProvider(), fa.signer, p.Grant)
	if e != nil {
		t.Fatal(e)
	}
	p.TicketV3.IssuedAt = at
	p.TicketV3.ExpiresAt = at.Add(time.Hour)
	p.TicketV3, e = provisioning.SignTicketV3(c.NewProvider(), fa.invite, p.TicketV3)
	if e != nil {
		t.Fatal(e)
	}
	p.BindingDigest = ""
	p.BindingDigest = node.Digest(p)
	a.Now = func() time.Time { return at.Add(time.Second) }
	if e = a.Prepare(ctx, p); e != nil {
		t.Fatal(e)
	}
	pop, e := d.CreateProof(c.NewProvider(), "test-relay", p.TicketV3.TicketID, "legacy-proof-nonce", at.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	r, e := a.Commit(ctx, node.RegistrationCommit{OperationID: p.OperationID, BindingDigest: p.BindingDigest, IdentityProof: pop, TicketV3: p.TicketV3})
	if e != nil {
		t.Fatal(e)
	}
	tokens, e := node.OpenRegistrationReceipt(r, key, d.Identity)
	if e != nil {
		t.Fatal(e)
	}
	unused := device(t, "old-operator-test-revoked")
	operatorDevice(t, pool, unused.Identity, "revoked")
	// Restore the exact old table shape, while retaining real signed/sealed rows.
	_, e = pool.Exec(ctx, "DROP TABLE iscp_relay.node_device_ownership; DROP TABLE iscp_relay.node_authorities; DROP TABLE iscp_relay.node_scope_migration;")
	if e != nil {
		t.Fatal(e)
	}
	for _, table := range scopedTables {
		if _, e = pool.Exec(ctx, "ALTER TABLE iscp_relay."+table+" DROP COLUMN authority_id CASCADE"); e != nil {
			t.Fatal(e)
		}
	}
	_, e = pool.Exec(ctx, `ALTER TABLE iscp_relay.node_preparations ADD PRIMARY KEY(operation_id), ADD UNIQUE(ticket_id);
ALTER TABLE iscp_relay.node_ticket_uses ADD PRIMARY KEY(ticket_id), ADD UNIQUE(operation_id);
ALTER TABLE iscp_relay.node_receipts ADD PRIMARY KEY(operation_id);
CREATE UNIQUE INDEX node_revocations_operation ON iscp_relay.node_revocations(operation_id);`)
	if e != nil {
		t.Fatal(e)
	}
	before := canonical(r)
	multi := multiConfig(fb, fa)
	if _, e = NewManager(ctx, pool, multi); e == nil {
		t.Fatal("unknown legacy rows silently adopted")
	}
	var ownerTable *string
	if e = pool.QueryRow(ctx, "SELECT to_regclass('iscp_relay.node_device_ownership')::text").Scan(&ownerTable); e != nil || ownerTable != nil {
		t.Fatal("failed startup partially migrated database", e)
	}
	multi.LegacyIssuerRoute = fa.cfg.IssuerRoute
	m, e := NewManager(ctx, pool, multi)
	if e != nil {
		t.Fatal(e)
	}
	legacy := adapterFor(t, m, fa.cfg.IssuerRoute)
	recovered, e := legacy.Status(ctx, p.OperationID, p.BindingDigest)
	if e != nil || !bytes.Equal(before, canonical(recovered)) {
		t.Fatal("historical sealed receipt changed", e)
	}
	if _, e = NewManager(ctx, pool, multi); e != nil {
		t.Fatal("restart lost ownership", e)
	}
	var owned int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM iscp_relay.node_device_ownership WHERE device_id=$1", unused.Identity.DeviceID).Scan(&owned); e != nil || owned != 0 {
		t.Fatal("unrelated operator device adopted", e)
	}
	if e = legacy.Revoke(ctx, "unrelated-device-revoke", unused.Identity.DeviceID, 2); e == nil {
		t.Fatal("unowned device became managed")
	}
	if _, _, e = managedRefresh(t, m, d, tokens.Refresh.Token, "legacy-refresh-after-migration"); e != nil {
		t.Fatal("old refresh credentials changed", e)
	}
	future := device(t, "future-operator-unowned")
	operatorDevice(t, pool, future.Identity, "active")
	malicious, _ := prep(t, legacy, fa.invite, fa.signer, future, "future-device-adoption")
	if e = legacy.Prepare(ctx, malicious); e == nil {
		t.Fatal("one-time migration became a future fallback")
	}
}

func TestOperatorBindScopesApprovedServicesAndPreservesAdminBootstrap(t *testing.T) {
	pool := database(t)
	ctx := t.Context()
	fa, fb := multiNode(t, "operator-a"), multiNode(t, "operator-b")
	m, e := NewManager(ctx, pool, multiConfig(fa, fb))
	if e != nil {
		t.Fatal(e)
	}
	relay, e := ref.New(ref.Config{DomainID: "test-domain", RelayID: "test-relay", BaseURL: "https://127.0.0.1", WebSocketURL: "wss://127.0.0.1/v2/relay/connect", AdminToken: "operator-test-only", AllowedOrigins: []string{"https://127.0.0.1"}, ProfileGate: gate.DefaultGate(gate.ProfileProduction), DB: pool, Managed: m})
	if e != nil {
		t.Fatal(e)
	}
	bind := func(d identity.Device, admin bool) int {
		pr := proof(t, d, "operator-service-bootstrap")
		body, _ := json.Marshal(map[string]any{"identity": d.Identity, "proof": pr})
		req := httptest.NewRequest("POST", "/v2/relay/devices/bind-self", bytes.NewReader(body))
		if admin {
			req.Header.Set("Authorization", "Bearer operator-test-only")
		}
		w := httptest.NewRecorder()
		relay.Handler().ServeHTTP(w, req)
		return w.Code
	}
	if status := bind(fa.service, false); status != 401 {
		t.Fatal("unprivileged bootstrap succeeded", status)
	}
	if status := bind(fa.service, true); status != 200 {
		t.Fatal("approved service bootstrap failed", status)
	}
	a, b := adapterFor(t, m, fa.cfg.IssuerRoute), adapterFor(t, m, fb.cfg.IssuerRoute)
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if e = a.owned(ctx, tx, fa.service.Identity.DeviceID); e != nil {
		t.Fatal(e)
	}
	if e = b.owned(ctx, tx, fa.service.Identity.DeviceID); e == nil {
		t.Fatal("operator assigned service to every node")
	}
	tx.Rollback(ctx)
	unknown := device(t, "unmanaged-operator-identity")
	if status := bind(unknown, true); status != 200 {
		t.Fatal("original admin enrollment blocked", status)
	}
	var n int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM iscp_relay.node_device_ownership WHERE device_id=$1", unknown.Identity.DeviceID).Scan(&n); e != nil || n != 0 {
		t.Fatal("unknown operator identity received managed authority")
	}
}

func TestMultiConfigRejectsDuplicatePinsRoutesSocketsAndUnknownLegacy(t *testing.T) {
	fa, fb := multiNode(t, "config-a"), multiNode(t, "config-b")
	base := multiConfig(fa, fb)
	cases := []func(*MultiConfig){func(c *MultiConfig) { c.Nodes[1].IssuerRoute = c.Nodes[0].IssuerRoute }, func(c *MultiConfig) { c.Nodes[1].ManagedSocket = c.Nodes[0].ManagedSocket }, func(c *MultiConfig) { c.Nodes[1].GrantSigner = c.Nodes[0].GrantSigner }, func(c *MultiConfig) {
		c.Nodes[1].ServicePeers = append(c.Nodes[1].ServicePeers, c.Nodes[0].ServicePeers[0])
	}, func(c *MultiConfig) { c.LegacyIssuerRoute = "unknown-node" }}
	for i, change := range cases {
		raw, _ := json.Marshal(base)
		var cfg MultiConfig
		json.Unmarshal(raw, &cfg)
		change(&cfg)
		if ValidateMultiConfig(cfg) == nil {
			t.Fatalf("invalid config %d accepted", i)
		}
	}
}
