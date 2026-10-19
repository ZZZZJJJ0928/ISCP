package iscprelayadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	bridge "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	nodeclient "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeclient"
	nodectl "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodecontrol"
	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

// Business authority is the only fake in this chain. Both credential services,
// their encrypted stores, signatures, HTTPS clients, router and ACKs are real.
type parentHTTPManagement struct{ binding node.Binding }

func (m parentHTTPManagement) Identity(context.Context) (node.Binding, error) { return m.binding, nil }
func (m parentHTTPManagement) Client(_ context.Context, id string) (bool, error) {
	return id == m.binding.ClientID, nil
}
func (parentHTTPManagement) CreateClient(context.Context, string, string) (string, error) {
	return "", errors.New("recovery must not create a business client")
}
func (parentHTTPManagement) RevokeManagedClient(context.Context, string) error {
	return errors.New("unexpected management mutation")
}

func TestControlParentHTTPSPostgresLostResultReopensOriginalAndInstalls(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := t.Context()
	// Model an independently advanced Relay authorization revision. Issuer
	// authority remains revision 1 and starts at credential generation 9.
	relayGrant := f.preparation.Grant
	relayGrant.RevocationEpoch = 7
	relayGrant, err := trust.SignGrant(c.NewProvider(), f.signer, relayGrant)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.adapter.lockLifecycle(ctx, tx, f.client.Identity.DeviceID, "", true, false); err != nil {
		tx.Rollback(ctx)
		t.Fatal(err)
	}
	grantRaw, _ := json.Marshal(relayGrant)
	if _, err = tx.Exec(ctx, `UPDATE iscp_relay.node_grants SET revision=7,grant_raw=$2 WHERE device_id=$1;`, f.client.Identity.DeviceID, grantRaw); err == nil {
		_, err = tx.Exec(ctx, `UPDATE iscp_relay.device_authority SET authorization_revision=7,state_version=state_version+1 WHERE device_id=$1`, f.client.Identity.DeviceID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE iscp_relay.access_tokens SET expires_at=now()-interval '1 hour' WHERE device_id=$1`, f.client.Identity.DeviceID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE iscp_relay.refresh_tokens SET expires_at=now()-interval '1 hour' WHERE device_id=$1`, f.client.Identity.DeviceID)
	}
	if err != nil {
		tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	service, err := NewControlService(ctx, []ScopedNode{{Adapter: f.adapter}}, f.backend.signer, "1")
	if err != nil {
		t.Fatal(err)
	}
	local := service.Handler()
	var router atomic.Pointer[control.Router]
	var loseParentResult atomic.Bool
	loseParentResult.Store(true)
	public := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == control.AuthorityPath {
			local.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v2/control/") {
			t.Errorf("recovery used data-plane endpoint %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == control.OperationPath+"recover" {
			raw, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(raw))
			var q control.Request
			if json.Unmarshal(raw, &q) == nil && q.Key.Namespace == control.CredentialNamespace && loseParentResult.CompareAndSwap(true, false) {
				captured := httptest.NewRecorder()
				router.Load().ServeHTTP(captured, r)
				if captured.Code != http.StatusOK {
					t.Errorf("parent did not commit before injected lost response: %d %s", captured.Code, captured.Body.String())
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
		}
		router.Load().ServeHTTP(w, r)
	}))
	defer public.Close()
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: public.Certificate().Raw}))
	relayClient, err := nodectl.NewHTTPControlRelay(public.URL, certificate, "test-relay", f.actor, f.backend.signer.Identity)
	if err != nil {
		t.Fatal(err)
	}
	// ConnString retains the pool's original DSN even after database(t) selects
	// its isolated database through ConnConfig.Database. Build the target URL
	// explicitly so issuer state shares that test database, never the admin DB.
	storeURL, err := url.Parse(os.Getenv("SC_RELAY_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	storeURL.Path = "/" + f.pool.Config().ConnConfig.Database
	store, err := node.NewPostgresStore(ctx, storeURL.String(), c.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.ActivateControlWriter(ctx, "1", control.RandomID()); err != nil {
		t.Fatal(err)
	}
	if err = store.ConfigureControlWriter(ctx, "1"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	credential, err := node.SignCredential(node.Credential{Origin: public.URL, TLSCertificatePEM: certificate, DomainID: "test-domain", RelayID: "test-relay", RelaySignerIdentity: f.backend.signer.Identity, IssuerIdentity: f.signer.Identity, InvitationSignerIdentity: f.invite.Identity, IssuerRoute: "parent-test-route", ResponderIdentity: f.adapter.cfg.Responder, DeploymentID: f.preparation.Binding.DeploymentID, OwnerID: f.preparation.Binding.OwnerID, ClientID: f.preparation.Binding.ClientID, InvitationID: "original-parent-invitation", IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-45 * time.Minute), Scopes: []string{"settings.read"}, BootstrapSecret: control.RandomID()}, f.invite)
	if err != nil {
		t.Fatal(err)
	}
	state := &node.State{Credential: credential, State: "active", Revision: 1, Device: &f.client.Identity, Operations: map[string]*node.Operation{}, Control: &node.ControlState{HistoryID: control.RandomID(), HistoryComplete: true, Generation: "9", Records: map[string]*control.Record{}, Parents: map[string]*node.ControlParent{}}}
	if err = store.Create(ctx, credential.InvitationID, state); err != nil {
		t.Fatal(err)
	}
	issuer, err := node.New(node.Config{EnableControlV2: true, ControlRelay: relayClient, Template: credential, Issuer: f.signer, InvitationSigner: f.invite, GrantTTL: 10 * time.Minute}, store, parentHTTPManagement{f.preparation.Binding}, f.adapter)
	if err != nil {
		t.Fatal(err)
	}
	private := httptest.NewTLSServer(issuer.ControlHandler())
	defer private.Close()
	proxy, err := nodectl.NewHTTPSControlTarget(private.URL, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: private.Certificate().Raw})))
	if err != nil {
		t.Fatal(err)
	}
	routed, err := control.NewRouter(map[string]http.Handler{"test-relay": local, f.signer.Identity.DeviceID: proxy})
	if err != nil {
		t.Fatal(err)
	}
	router.Store(routed)
	directory := t.TempDir()
	if err = os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := nodeclient.StoredConfig{ControlV2: true, Origin: public.URL, TLSCertificatePEM: certificate, IssuerRoute: credential.IssuerRoute, InvitationID: credential.InvitationID, IssuerIdentity: f.signer.Identity, RelaySignerIdentity: f.backend.signer.Identity, ResponderIdentity: f.adapter.cfg.Responder, Binding: f.preparation.Binding, Revision: 1, Scopes: credential.Scopes, RelayID: "test-relay"}
	client, err := nodeclient.NewStored(cfg, f.client, directory, f.preparation.Grant)
	if err != nil {
		t.Fatal(err)
	}
	bundle := bridge.EnrollmentBundle{Type: bridge.EnrollmentBundleType, Mode: bridge.BundleModeWorkbenchNodeManaged, DomainID: f.client.Identity.DomainID, DeviceID: f.client.Identity.DeviceID, RelayID: "test-relay", RelayBaseURL: public.URL, RelayWebSocketURL: "wss" + strings.TrimPrefix(public.URL, "https") + "/v2/relay/duplex", RelaySignerIdentity: &f.backend.signer.Identity, InvitationSignerIdentity: &f.invite.Identity, TLSCertificatePEM: certificate, IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), Access: f.tokens.Access, Refresh: f.tokens.Refresh}
	bundle.Access.ExpiresAt, bundle.Refresh.ExpiresAt = bundle.ExpiresAt, bundle.ExpiresAt
	binding := bridge.CredentialBinding{DomainID: bundle.DomainID, DeviceID: bundle.DeviceID, ResourceBindingID: cfg.Binding.ClientID, TargetServiceID: bundle.RelayID, IssuerPublicKey: cfg.IssuerIdentity.PublicKey.Public, RelayPublicKey: cfg.RelaySignerIdentity.PublicKey.Public, TLSCertificateSHA256: c.Base64URL(c.SHA256([]byte(certificate)))}
	if _, err = client.RecoverCredentialLease(ctx, binding, "", bundle); err == nil {
		t.Fatal("injected parent response loss was hidden")
	}
	committed, err := store.Read(ctx, credential.InvitationID)
	if err != nil || len(committed.Control.Records) != 1 {
		t.Fatal("parent did not retain original", err)
	}
	var original *control.Record
	for _, record := range committed.Control.Records {
		original = record
	}
	if original.Result == nil || original.Generation != "10" || original.Result.Payload.Body.RelayResult == nil || original.Disposition != nil {
		t.Fatal("parent result or deferred install ACK missing")
	}
	child := original.Result.Payload.Body.RelayResult
	if child.Payload.Key.DeviceID != f.actor.Identity.DeviceID || child.Payload.CredentialGeneration != "2" || child.Payload.Body.RelayCredentials.AuthorizationRevision != "7" || child.Verify(f.backend.signer.Identity) != nil {
		t.Fatal("real delegated child mixed actor, signer or target counters")
	}
	childRecord, err := f.adapter.controlBackend.read(ctx, nil, child.Payload.Key)
	if err != nil || childRecord == nil || childRecord.Disposition == nil || childRecord.Disposition.Ack.Disposition != "delegated" || childRecord.Disposition.Ack.ParentResultDigest == nil || *childRecord.Disposition.Ack.ParentResultDigest != original.Result.ResultDigest {
		t.Fatal("child was not durably delegated to immutable parent", err)
	}
	client, err = nodeclient.NewStored(cfg, f.client, directory, f.preparation.Grant)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "enrollment.json")
	transport, err := bridge.NewRelayCredentialClient(bridge.ProfileProduction, path, bundle, f.client, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	grantPath := filepath.Join(directory, "grant.json")
	if err = transport.ConfigureCredentialProviderWithInstallation(binding, func(ctx context.Context, b bridge.CredentialBinding, generation bridge.CredentialGeneration) (bridge.CredentialLease, error) {
		lease, err := client.RecoverCredentialLease(ctx, b, generation, bundle)
		if err != nil {
			return lease, err
		}
		grant, err := client.PersistControlGrant(ctx, lease, func(grant trust.Grant) error {
			raw, err := json.Marshal(grant)
			if err != nil {
				return err
			}
			return node.WritePrivateAtomic(grantPath, raw)
		})
		if err == nil {
			err = client.AcceptGrant(grant)
		}
		return lease, err
	}, client.CredentialLeaseInstalled); err != nil {
		t.Fatal(err)
	}
	defer transport.CredentialProvider().Close()
	lease, err := transport.CredentialProvider().EnsureAccess(ctx, binding)
	if err != nil || lease.CredentialGeneration != "2" || lease.AuthorizationRevision != "7" {
		t.Fatal("reopened original recovery/install failed", lease.CredentialGeneration, lease.AuthorizationRevision, err)
	}
	for _, saved := range []string{grantPath, path + ".credentials.v2"} {
		if _, err := os.Stat(saved); err != nil {
			t.Fatal("ACK preceded durable local application", err)
		}
	}
	final, err := store.Read(ctx, credential.InvitationID)
	if err != nil || len(final.Control.Records) != 1 || final.Control.Generation != "10" {
		t.Fatal("retry issued a successor instead of original", err)
	}
	ack := final.Control.Records[original.Key.StorageKey()].Disposition
	if ack == nil || ack.Ack.Disposition != "installed" || ack.Ack.ResultDigest != original.Result.ResultDigest {
		t.Fatal("parent install ACK did not bind original result")
	}
	assertLifecycleGeneration(t, f, "2")
}
