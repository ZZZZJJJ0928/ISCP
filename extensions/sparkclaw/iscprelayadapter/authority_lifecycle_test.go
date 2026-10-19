package iscprelayadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"github.com/jackc/pgx/v5/pgxpool"
)

type lifecycleFixture struct {
	pool                          *pgxpool.Pool
	adapter                       *Adapter
	backend                       *ControlBackend
	invite, signer, actor, client identity.Device
	preparation                   node.RegistrationPreparation
	tokens                        node.RelayCredentials
}

func newLifecycleFixture(t *testing.T) lifecycleFixture {
	t.Helper()
	f := lifecycleFixture{pool: database(t), invite: device(t, "invitation"), signer: device(t, "signer"), actor: device(t, "issuer-service"), client: device(t, "lifecycle-client")}
	ctx := t.Context()
	responder, relaySigner := device(t, "responder"), device(t, "relay-signer")
	cfg := Config{DomainID: "test-domain", RelayID: "test-relay", InvitationSigner: f.invite.Identity, GrantSigner: f.signer.Identity, Responder: responder.Identity, ServicePeers: []identity.DeviceIdentity{f.actor.Identity}, ControlIssuerActor: &f.actor.Identity}
	var err error
	f.adapter, err = New(ctx, f.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.adapter.claim(ctx, tx, f.actor.Identity, false); err == nil {
		err = f.adapter.createDevice(ctx, tx, f.actor.Identity)
	}
	if err != nil {
		tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// Explicit test-only genesis activation; ordinary traffic cannot infer it.
	_, err = f.pool.Exec(ctx, `INSERT INTO iscp_relay.writer_scopes(scope_id,writer_role,writes_enabled) VALUES('test-relay',current_user,true); INSERT INTO iscp_relay.domain_authority(scope_id,domain_id,history_id,history_state,history_evidence_sha256,activated_at) VALUES('test-relay','test-domain',repeat('A',43),'continuous',repeat('B',43),now()); INSERT INTO iscp_relay.device_authority VALUES('test-relay','test-domain','issuer-service',1,1,1,'active'); INSERT INTO iscp_relay.connection_owners(scope_id,domain_id,device_id) VALUES('test-relay','test-domain','issuer-service')`)
	if err != nil {
		t.Fatal(err)
	}
	f.backend, err = f.adapter.EnableControlV2(ctx, relaySigner, "1")
	if err != nil {
		t.Fatal(err)
	}
	f.preparation, _ = prep(t, f.adapter, f.invite, f.signer, f.client, "active-register-operation")
	if err = f.adapter.Prepare(ctx, f.preparation); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM iscp_relay.device_authority WHERE device_id=$1`, f.client.Identity.DeviceID).Scan(&count); err != nil || count != 0 {
		t.Fatal("prepare activated device", count, err)
	}
	p := f.preparation
	commit := node.RegistrationCommit{OperationID: p.OperationID, BindingDigest: p.BindingDigest, TicketV3: p.TicketV3, IdentityProof: proof(t, f.client, p.TicketV3.TicketID)}
	_, f.tokens, _, err = f.adapter.commit(ctx, commit)
	if err != nil {
		t.Fatal(err)
	}
	assertLifecycleGeneration(t, f, "1")
	return f
}
func assertLifecycleGeneration(t *testing.T, f lifecycleFixture, want string) {
	t.Helper()
	var got string
	if err := f.pool.QueryRow(t.Context(), `SELECT credential_generation::text FROM iscp_relay.device_authority WHERE scope_id='test-relay' AND domain_id='test-domain' AND device_id=$1`, f.client.Identity.DeviceID).Scan(&got); err != nil || got != want {
		t.Fatalf("generation %q, want %q: %v", got, want, err)
	}
	var unversioned int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM (SELECT credential_generation FROM iscp_relay.access_tokens WHERE device_id=$1 UNION ALL SELECT credential_generation FROM iscp_relay.refresh_tokens WHERE device_id=$1) t WHERE credential_generation IS NULL`, f.client.Identity.DeviceID).Scan(&unversioned); err != nil || unversioned != 0 {
		t.Fatal("unversioned token", unversioned, err)
	}
}
func lifecycleIntent(f lifecycleFixture) control.Intent {
	p := f.preparation
	return control.Intent{Type: "iscp.operation.intent.v2", Version: 2, Namespace: control.RelayNamespace, OperationID: "actual-disclosure-operation", Kind: "relay.refresh", SubjectBinding: control.Subject{DomainID: f.client.Identity.DomainID, DeviceID: f.client.Identity.DeviceID, BindingID: p.Binding.ClientID}, Target: control.Target{ServiceID: "test-relay", ResourceID: p.Binding.ClientID}, TaskAuthorization: control.Standing{Kind: "standing", AuthorizationRevision: "1", Scopes: []string{node.Permission}}, Payload: control.Payload{RequestedScopes: []string{node.Permission}}, Preconditions: control.Preconditions{ResourceVersion: "1", CredentialGeneration: "1", AuthorizationRevision: "1"}}
}
func TestLifecycleActualRevokeWaitsForControlDisclosure(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := t.Context()
	request := controlRequest(t, f.client, lifecycleIntent(f), "recover", nil)
	out, err := f.backend.Execute(ctx, request, f.client.Identity, "")
	if err != nil || out.Result == nil {
		t.Fatal("execute", err)
	}
	assertLifecycleGeneration(t, f, "2")
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	disclosure := make(chan error, 1)
	go func() {
		disclosure <- f.backend.Disclose(ctx, request, f.client.Identity, func() error { close(entered); <-release; return nil })
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("disclosure did not enter")
	}
	revoke := make(chan error, 1)
	go func() { revoke <- f.adapter.Revoke(ctx, "actual-revocation-operation", f.client.Identity.DeviceID, 2) }()
	select {
	case err := <-revoke:
		t.Fatal("actual Revoke bypassed disclosure guard", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	if err = <-disclosure; err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-revoke:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("actual Revoke did not complete")
	}
	var state, revision string
	if err = f.pool.QueryRow(ctx, `SELECT state,authorization_revision::text FROM iscp_relay.device_authority WHERE device_id=$1`, f.client.Identity.DeviceID).Scan(&state, &revision); err != nil || state != "revoked" || revision != "2" {
		t.Fatal("revocation authority not durable", state, revision, err)
	}
	emitted := false
	err = f.backend.Disclose(ctx, request, f.client.Identity, func() error { emitted = true; return nil })
	if err == nil || emitted {
		t.Fatal("post-revoke disclosure", err, emitted)
	}
	if err = f.adapter.Revoke(ctx, "actual-revocation-operation", f.client.Identity.DeviceID, 2); err != nil {
		t.Fatal("revocation reconciliation", err)
	}
	if _, err = f.adapter.Status(ctx, f.preparation.OperationID, f.preparation.BindingDigest); err == nil {
		t.Fatal("registration receipt disclosed after revoke")
	}
}
func TestLifecycleRefreshGenerationAndInactiveOldHTTP(t *testing.T) {
	f := newLifecycleFixture(t)
	build, key := refreshBuilder(t, f.client, f.tokens.Refresh.Token, "activated-refresh-operation")
	raw, err := f.adapter.refresh(build())
	if err != nil {
		t.Fatal(err)
	}
	assertLifecycleGeneration(t, f, "2")
	var receipt node.RegistrationReceipt
	if json.Unmarshal(raw, &receipt) != nil {
		t.Fatal("invalid refresh receipt")
	}
	next, err := node.OpenRegistrationReceipt(receipt, key, f.client.Identity)
	if err != nil {
		t.Fatal(err)
	}
	var gen string
	if err = f.pool.QueryRow(t.Context(), `SELECT credential_generation::text FROM iscp_relay.refresh_tokens WHERE refresh_hash=$1`, c.SHA256([]byte(next.Refresh.Token))).Scan(&gen); err != nil || gen != "2" {
		t.Fatal(gen, err)
	}
	again, err := f.adapter.refresh(build())
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("original refresh replay changed", err)
	}
	assertLifecycleGeneration(t, f, "2")
	// Even if an old token's revoked marker is lost, its generation cannot be
	// adopted as the current credential generation.
	if _, err = f.pool.Exec(t.Context(), `UPDATE iscp_relay.refresh_tokens SET revoked_at=NULL WHERE refresh_hash=$1`, c.SHA256([]byte(f.tokens.Refresh.Token))); err != nil {
		t.Fatal(err)
	}
	stale, _ := refreshBuilder(t, f.client, f.tokens.Refresh.Token, "stale-refresh-operation")
	if _, err = f.adapter.refresh(stale()); err == nil {
		t.Fatal("stale token generation accepted")
	}
	for _, run := range []func() (json.RawMessage, error){func() (json.RawMessage, error) { return f.adapter.Refresh(build()) }, func() (json.RawMessage, error) {
		return f.adapter.ServiceRecover(httptest.NewRequest(http.MethodPost, "/", nil))
	}} {
		_, err = run()
		typed, ok := err.(Error)
		if !ok || typed.Reason != "protocol_incompatible" || typed.Status != http.StatusGone {
			t.Fatal("old credential HTTP active", err)
		}
	}
	recorder := httptest.NewRecorder()
	f.adapter.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/registrations/recover", nil))
	if recorder.Code != http.StatusGone {
		t.Fatal("old private recovery active", recorder.Code)
	}
}
func TestLifecycleOldAdapterCannotAdoptWriterEpoch(t *testing.T) {
	f := newLifecycleFixture(t)
	// Model an old already-running instance; never read the activated epoch into it.
	old := &Adapter{db: f.pool, cfg: f.adapter.cfg, authority: f.adapter.authority, Now: time.Now}
	if err := old.Revoke(t.Context(), "old-writer-revoke-operation", f.client.Identity.DeviceID, 2); err == nil {
		t.Fatal("unconfigured old writer adopted epoch")
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE iscp_relay.writer_scopes SET writer_epoch=2 WHERE scope_id='test-relay'`); err != nil {
		t.Fatal(err)
	}
	if err := f.adapter.Revoke(t.Context(), "stale-writer-revoke-operation", f.client.Identity.DeviceID, 2); err == nil {
		t.Fatal("stale configured writer adopted new epoch")
	}
	var state string
	if err := f.pool.QueryRow(context.Background(), `SELECT state FROM iscp_relay.device_authority WHERE device_id=$1`, f.client.Identity.DeviceID).Scan(&state); err != nil || state != "active" {
		t.Fatal(state, err)
	}
}

func TestLifecycleRecoveryScopeAndServiceGeneration(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := t.Context()
	grant := f.preparation.Grant
	grant.Signature = trust.Grant{}.Signature
	grant.RevocationEpoch = 2
	var err error
	grant, err = trust.SignGrant(c.NewProvider(), f.signer, grant)
	if err != nil {
		t.Fatal(err)
	}
	r := node.RegistrationRecovery{OperationID: "authority-recovery-operation", Identity: f.client.Identity, Grant: grant, Revision: 2, ReceiptWrapPublicKey: f.preparation.ReceiptWrapPublicKey}
	r.Proof = proof(t, f.client, r.OperationID+"\x00"+r.ReceiptWrapPublicKey)
	r.BindingDigest = node.Digest(r)
	receipt, err := f.adapter.Recover(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	assertLifecycleGeneration(t, f, "2")
	var revision, version string
	if err = f.pool.QueryRow(ctx, `SELECT authorization_revision::text,state_version::text FROM iscp_relay.device_authority WHERE device_id=$1`, f.client.Identity.DeviceID).Scan(&revision, &version); err != nil || revision != "2" || version != "3" {
		t.Fatal("scope transition not atomic", revision, version, err)
	}
	replay, err := f.adapter.Recover(ctx, r)
	if err != nil || node.Digest(receipt) != node.Digest(replay) {
		t.Fatal("recovery replay changed", err)
	}
	assertLifecycleGeneration(t, f, "2")
	if _, err = f.backend.Execute(ctx, controlRequest(t, f.client, lifecycleIntent(f), "recover", nil), f.client.Identity, ""); err == nil {
		t.Fatal("v2 admitted original scope after actual recovery changed revision")
	}
	service := ServiceRecovery{OperationID: "active-service-recovery-operation", Identity: f.actor.Identity, ReceiptWrapPublicKey: f.preparation.ReceiptWrapPublicKey}
	service.Proof = proof(t, f.actor, strings.Join([]string{"sparkclaw/iscp-node/service-recovery/v1", service.OperationID, service.ReceiptWrapPublicKey}, "\x00"))
	raw, _ := json.Marshal(service)
	first, err := f.adapter.serviceRecover(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.adapter.serviceRecover(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("service recovery replay", err)
	}
	var generation string
	if err = f.pool.QueryRow(ctx, `SELECT credential_generation::text FROM iscp_relay.device_authority WHERE device_id=$1`, f.actor.Identity.DeviceID).Scan(&generation); err != nil || generation != "2" {
		t.Fatal("service generation", generation, err)
	}
	var invalidTokens int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM iscp_relay.access_tokens WHERE device_id=$1 AND credential_generation IS DISTINCT FROM 2`, f.actor.Identity.DeviceID).Scan(&invalidTokens); err != nil || invalidTokens != 0 {
		t.Fatal("service token generation", invalidTokens, err)
	}
}
