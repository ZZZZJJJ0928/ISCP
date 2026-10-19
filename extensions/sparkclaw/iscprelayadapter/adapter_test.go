package iscprelayadapter

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func database(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SC_RELAY_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture required")
	}
	ctx := t.Context()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	name := "relay_validation_" + strings.ToLower(c.Base64URL(c.RandomBytes(12)))
	name = strings.ReplaceAll(strings.ReplaceAll(name, "-", "a"), "_", "b")
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+name); e != nil {
		admin.Close()
		t.Fatal(e)
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.Database = name
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		admin.Close()
	})
	m, e := postgres.EmbeddedMigrations()
	if e != nil {
		t.Fatal(e)
	}
	if e = postgres.ApplyMigrations(ctx, pool, m); e != nil {
		t.Fatal(e)
	}
	return pool
}
func device(t *testing.T, name string) identity.Device {
	t.Helper()
	d, e := identity.NewDevice(c.NewProvider(), "test-domain", name, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func proof(t *testing.T, d identity.Device, challenge string) identity.DeviceProof {
	t.Helper()
	p, e := d.CreateProof(c.NewProvider(), "test-relay", challenge, c.Base64URL(c.RandomBytes(18)), time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func prep(t *testing.T, a *Adapter, invite, signer, client identity.Device, op string) (node.RegistrationPreparation, []byte) {
	t.Helper()
	now := time.Now().UTC()
	wrap, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	grant, e := trust.SignGrant(c.NewProvider(), signer, trust.Grant{GrantID: "grant-" + op, SubjectDeviceID: client.Identity.DeviceID, Audience: a.cfg.Responder.DeviceID, ConfirmationThumbprint: client.Identity.PublicKey.KID, Permissions: []string{node.Permission}, RelayConstraints: []string{a.cfg.RelayID}, NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Hour), RevocationEpoch: 1})
	if e != nil {
		t.Fatal(e)
	}
	ticket, e := provisioning.SignTicketV3(c.NewProvider(), invite, provisioning.PairingTicketV3{TicketID: "ticket-" + op, DomainID: a.cfg.DomainID, RelayID: a.cfg.RelayID, TrustRootID: invite.Identity.DeviceID, Purpose: provisioning.PurposeInvite, ConsumerRole: "sparkx_workbench_client", GrantAudience: a.cfg.Responder.DeviceID, GrantPermissions: []string{node.Permission}, GrantTTLSeconds: 3600, MaxUses: 1, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	p := node.RegistrationPreparation{OperationID: op, InvitationID: ticket.TicketID, Identity: client.Identity, Grant: grant, TicketV3: ticket, Binding: node.Binding{DeploymentID: "deployment", OwnerID: "owner", ClientID: "client-" + op}, ReceiptWrapPublicKey: c.Base64URL(wrap.PublicKey().Bytes())}
	p.BindingDigest = node.Digest(p)
	return p, wrap.Bytes()
}
func refreshRequest(t *testing.T, d identity.Device, refresh, op string) (*httptest.ResponseRecorder, *strings.Reader, identity.DeviceProof, string, []byte) {
	t.Helper()
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	wrap := c.Base64URL(k.PublicKey().Bytes())
	p := proof(t, d, strings.Join([]string{"sparkclaw/iscp-node/refresh/v1", op, c.Base64URL(c.SHA256([]byte(refresh))), wrap}, "\x00"))
	raw, _ := json.Marshal(map[string]string{"refresh": refresh})
	return httptest.NewRecorder(), strings.NewReader(string(raw)), p, wrap, k.Bytes()
}

func TestDurableTransactionsReplayRefreshRecoveryAndRevocation(t *testing.T) {
	pool := database(t)
	ctx := t.Context()
	invite, signer, responder := device(t, "invitation"), device(t, "signer"), device(t, "responder")
	service := device(t, "service")
	cfg := Config{DomainID: "test-domain", RelayID: "test-relay", InvitationSigner: invite.Identity, GrantSigner: signer.Identity, Responder: responder.Identity, ServicePeers: []identity.DeviceIdentity{responder.Identity, service.Identity}}
	a, e := New(ctx, pool, cfg)
	if e != nil {
		t.Fatal(e)
	}
	client := device(t, "desktop-a")
	p, wrap := prep(t, a, invite, signer, client, "register-operation-1")
	if e = a.Prepare(ctx, p); e != nil {
		t.Fatal(e)
	}
	commit := node.RegistrationCommit{OperationID: p.OperationID, BindingDigest: p.BindingDigest, IdentityProof: proof(t, client, p.TicketV3.TicketID), TicketV3: p.TicketV3}
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	receipts := make(chan node.RegistrationReceipt, 12)
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); v, e := a.Commit(ctx, commit); errs <- e; receipts <- v }()
	}
	wg.Wait()
	close(errs)
	close(receipts)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var first node.RegistrationReceipt
	for r := range receipts {
		if first.OperationID == "" {
			first = r
		} else if node.Digest(r) != node.Digest(first) {
			t.Fatal("concurrent response changed")
		}
	}
	tokens, e := node.OpenRegistrationReceipt(first, wrap, client.Identity)
	if e != nil {
		t.Fatal(e)
	}
	var count int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM iscp_relay.access_tokens WHERE device_id=$1", client.Identity.DeviceID).Scan(&count); e != nil || count != 1 {
		t.Fatalf("registration not atomic: %d %v", count, e)
	}
	b, e := New(ctx, pool, cfg)
	if e != nil {
		t.Fatal(e)
	}
	replayed, e := b.Status(ctx, p.OperationID, p.BindingDigest)
	if e != nil || node.Digest(replayed) != node.Digest(first) {
		t.Fatal("restart lost sealed receipt")
	}
	var stored []byte
	if e = pool.QueryRow(ctx, "SELECT response FROM iscp_relay.node_receipts WHERE operation_id=$1", p.OperationID).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(stored, []byte(tokens.Access.Token)) || bytes.Contains(stored, []byte(tokens.Refresh.Token)) {
		t.Fatal("plaintext credential persisted in receipt")
	}
	if _, e = b.Register(ctx, client.Identity, commit.IdentityProof, p.TicketV3); e == nil {
		t.Fatal("public ticket replay returned tokens")
	}
	altered := commit
	altered.BindingDigest = "different-operation-digest"
	if _, e = b.Commit(ctx, altered); e == nil {
		t.Fatal("changed registration digest accepted")
	}
	// Force a failure after the access INSERT. Device, proof, ticket use and
	// credential rows must all roll back; retrying the same proof then succeeds.
	doomed := device(t, "desktop-rollback")
	bad, k := prep(t, a, invite, signer, doomed, "register-operation-rollback")
	if e = a.Prepare(ctx, bad); e != nil {
		t.Fatal(e)
	}
	_, e = pool.Exec(ctx, "CREATE FUNCTION iscp_relay.fail_refresh() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.device_id='desktop-rollback' THEN RAISE EXCEPTION 'fixture failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_refresh BEFORE INSERT ON iscp_relay.refresh_tokens FOR EACH ROW EXECUTE FUNCTION iscp_relay.fail_refresh();")
	if e != nil {
		t.Fatal(e)
	}
	badCommit := node.RegistrationCommit{OperationID: bad.OperationID, BindingDigest: bad.BindingDigest, IdentityProof: proof(t, doomed, bad.TicketV3.TicketID), TicketV3: bad.TicketV3}
	if _, e = a.Commit(ctx, badCommit); e == nil {
		t.Fatal("fixture fault ignored")
	}
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM iscp_relay.devices WHERE device_id='desktop-rollback'").Scan(&count); e != nil || count != 0 {
		t.Fatal("partial device persisted")
	}
	_, e = pool.Exec(ctx, "DROP TRIGGER fail_refresh ON iscp_relay.refresh_tokens; DROP FUNCTION iscp_relay.fail_refresh()")
	if e != nil {
		t.Fatal(e)
	}
	r, e := a.Commit(ctx, badCommit)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = node.OpenRegistrationReceipt(r, k, doomed.Identity); e != nil {
		t.Fatal(e)
	}
	// Exact managed refresh retries produce one sealed pair across restart.
	_, body, pop, wr, private := refreshRequest(t, client, tokens.Refresh.Token, "refresh-operation-1")
	bodyBytes, _ := io.ReadAll(body)
	bodyRaw := string(bodyBytes)
	proofRaw, _ := json.Marshal(pop)
	send := func(adapter *Adapter, op string) (json.RawMessage, error) {
		req := httptest.NewRequest("POST", "/v2/relay/devices/refresh-access", strings.NewReader(bodyRaw))
		req.Header.Set("Idempotency-Key", op)
		req.Header.Set("X-SparkClaw-Refresh-Wrap-Key", wr)
		req.Header.Set("X-SparkClaw-Refresh-Proof", c.Base64URL(proofRaw))
		return adapter.Refresh(req)
	}
	raw, e := send(a, "refresh-operation-1")
	if e != nil {
		t.Fatal(e)
	}
	raw2, e := send(b, "refresh-operation-1")
	if e != nil || !bytes.Equal(raw, raw2) {
		t.Fatal("refresh replay changed")
	}
	var rr node.RegistrationReceipt
	if json.Unmarshal(raw, &rr) != nil {
		t.Fatal("invalid receipt")
	}
	newTokens, e := node.OpenRegistrationReceipt(rr, private, client.Identity)
	if e != nil {
		t.Fatal(e)
	}
	if newTokens.Refresh.Token == tokens.Refresh.Token {
		t.Fatal("refresh did not rotate")
	}
	if _, e = send(a, "refresh-operation-2"); e == nil {
		t.Fatal("consumed refresh reused")
	}
	var rotated bool
	if e = pool.QueryRow(ctx, "SELECT revoked_at IS NOT NULL AND rotated_to IS NOT NULL FROM iscp_relay.refresh_tokens WHERE refresh_hash=$1", c.SHA256([]byte(tokens.Refresh.Token))).Scan(&rotated); e != nil || !rotated {
		t.Fatal("refresh lineage absent")
	}
	// Expired-proof exact receipts remain replayable only for the same wrap key.
	a.Now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, e = send(a, "refresh-operation-1"); e != nil {
		t.Fatal(e)
	}
	a.Now = time.Now
	if e = a.Revoke(ctx, "revoke-operation-1", client.Identity.DeviceID, 2); e != nil {
		t.Fatal(e)
	}
	if e = a.Revoke(ctx, "revoke-operation-1", client.Identity.DeviceID, 2); e != nil {
		t.Fatal(e)
	}
	if _, e = send(b, "refresh-operation-1"); e == nil {
		t.Fatal("revoked receipt replay succeeded")
	}
	if _, e = b.Status(ctx, p.OperationID, p.BindingDigest); e == nil {
		t.Fatal("revoked registration receipt succeeded")
	}
	if e = a.Revoke(ctx, "revoke-operation-1", doomed.Identity.DeviceID, 2); e == nil {
		t.Fatal("revocation operation reused for another device")
	}
	if e = a.Prepare(ctx, p); e == nil {
		t.Fatal("revoked device preparation revived")
	}
	// Operator peer recovery has no workbench Grant or invitation authority.
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	// This fixture is the operator-approved bootstrap; ordinary preparations
	// may not adopt an unrelated existing transport identity.
	if e = a.claim(ctx, tx, service.Identity, false); e != nil {
		t.Fatal(e)
	}
	if e = a.createDevice(ctx, tx, service.Identity); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	sk, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	sr := ServiceRecovery{OperationID: "service-recovery-1", Identity: service.Identity, ReceiptWrapPublicKey: c.Base64URL(sk.PublicKey().Bytes())}
	sr.Proof = proof(t, service, strings.Join([]string{"sparkclaw/iscp-node/service-recovery/v1", sr.OperationID, sr.ReceiptWrapPublicKey}, "\x00"))
	recovery := func(adapter *Adapter, p ServiceRecovery) (json.RawMessage, error) {
		raw, _ := json.Marshal(p)
		return adapter.ServiceRecover(httptest.NewRequest("POST", "/api/sparkclaw/iscp-control/v1/service-recover", bytes.NewReader(raw)))
	}
	sealed, e := recovery(a, sr)
	if e != nil {
		t.Fatal(e)
	}
	sealed2, e := recovery(b, sr)
	if e != nil || !bytes.Equal(sealed, sealed2) {
		t.Fatal("service recovery receipt lost")
	}
	json.Unmarshal(sealed, &rr)
	if _, e = node.OpenRegistrationReceipt(rr, sk.Bytes(), service.Identity); e != nil {
		t.Fatal(e)
	}
	foreign := sr
	foreign.Identity = doomed.Identity
	if _, e = recovery(a, foreign); e == nil {
		t.Fatal("ordinary peer used service recovery")
	}
	sv := ServiceVerification{Identity: service.Identity, Challenge: "sparkclaw/iscp-node/control-grant/v1\x00valid-fixture-digest"}
	sv.Proof, e = service.CreateProof(c.NewProvider(), responder.Identity.DeviceID, sv.Challenge, "service-proof-nonce", time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	if e = a.VerifyServicePeer(ctx, sv); e != nil {
		t.Fatal(e)
	}
	if e = b.VerifyServicePeer(ctx, sv); e != nil {
		t.Fatal(e)
	}
	changed := sv
	changed.Challenge += "-changed"
	if e = b.VerifyServicePeer(ctx, changed); e == nil {
		t.Fatal("changed proof replay accepted")
	}
	if _, e = pool.Exec(ctx, "UPDATE iscp_relay.devices SET status='revoked' WHERE device_id=$1", service.Identity.DeviceID); e != nil {
		t.Fatal(e)
	}
	if _, e = recovery(b, sr); e == nil {
		t.Fatal("revoked service revived")
	}
	if e = b.VerifyServicePeer(ctx, sv); e == nil {
		t.Fatal("revoked service proof replay acked")
	}
}
