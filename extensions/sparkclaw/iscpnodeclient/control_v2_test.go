package iscpnodeclient

import (
	"context"
	"errors"
	bridge "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testControlRelay struct {
	mu            sync.Mutex
	signer, actor identity.Device
	records       map[string]*control.Record
}

func (r *testControlRelay) Actor() identity.DeviceIdentity { return r.actor.Identity }
func (r *testControlRelay) Authority(_ context.Context, subject control.Subject, target control.Target) (node.ControlAuthority, error) {
	return node.ControlAuthority{Subject: subject, Target: target, Generation: "36", AuthorizationRevision: "1", ResourceVersion: "1", Scopes: []string{node.Permission}}, nil
}
func (r *testControlRelay) Attempt(_ context.Context, q control.Request, _ string) (control.Outcome, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record := r.records[q.Key.StorageKey()]
	now := time.Now().UTC().Truncate(time.Second)
	if q.Action == "ack" {
		d, e := record.Acknowledge(*q.Ack, "37", true, now, r.signer)
		return control.Outcome{Disposition: &d}, e
	}
	if record == nil {
		tokens := &control.RelayCredentials{TargetServiceID: q.Intent.Target.ServiceID, BindingID: q.Intent.SubjectBinding.BindingID, CredentialGeneration: "37", AuthorizationRevision: "1", Access: control.Credential{DomainID: q.Intent.SubjectBinding.DomainID, DeviceID: q.Intent.SubjectBinding.DeviceID, Token: "https-child-access", ExpiresAt: now.Add(10 * time.Minute)}, Refresh: control.Credential{DomainID: q.Intent.SubjectBinding.DomainID, DeviceID: q.Intent.SubjectBinding.DeviceID, Token: "https-child-refresh", ExpiresAt: now.Add(time.Hour)}}
		result, e := control.NewResult(control.ResultPayload{Key: q.Key, SemanticDigest: q.SemanticDigest, ResultVersion: "1", State: "succeeded", CompletedAt: now, CredentialGeneration: "37", Body: control.ResultBody{RelayCredentials: tokens}}, r.signer)
		if e != nil {
			return control.Outcome{}, e
		}
		record = &control.Record{Key: q.Key, Intent: *q.Intent, SemanticDigest: q.SemanticDigest, State: "succeeded", Version: "1", Generation: "37", Result: &result, CreatedAt: now}
		r.records[q.Key.StorageKey()] = record
	}
	return control.Outcome{Result: record.Result}, nil
}

type dropControlRoundTripper struct {
	http.RoundTripper
	drop atomic.Bool
	path string
}

func (d *dropControlRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	res, e := d.RoundTripper.RoundTrip(r)
	if e == nil && strings.HasSuffix(r.URL.Path, d.path) && d.drop.CompareAndSwap(true, false) {
		res.Body.Close()
		return nil, errors.New("synthetic lost response after server commit")
	}
	return res, e
}
func TestControlHTTPSRecoveryNestedPinsIndependentGenerationsAndInstallACK(t *testing.T) {
	cl, _, _, _, _ := setupClientStoreMode(t, time.Minute, node.NewMemoryStore(), "control-create-operation", true)
	enrolled, err := cl.Enroll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = cl.AcceptGrant(enrolled.Grant); err != nil {
		t.Fatal(err)
	}
	bundle := enrolled.Enrollment
	bundle.IssuedAt = time.Now().Add(-2 * time.Hour)
	bundle.Access.ExpiresAt = time.Now().Add(-time.Minute)
	bundle.Refresh.ExpiresAt = time.Now().Add(-time.Minute)
	bundle.ExpiresAt = bundle.Refresh.ExpiresAt
	binding := bridge.CredentialBinding{DomainID: cl.device.Identity.DomainID, DeviceID: cl.device.Identity.DeviceID, ResourceBindingID: cl.cfg.Binding.ClientID, TargetServiceID: cl.cfg.RelayID, IssuerPublicKey: cl.cfg.IssuerIdentity.PublicKey.Public, RelayPublicKey: cl.cfg.RelaySignerIdentity.PublicKey.Public, TLSCertificateSHA256: c.Base64URL(c.SHA256([]byte(cl.cfg.TLSCertificatePEM)))}
	dropped := &dropControlRoundTripper{RoundTripper: cl.http.Transport, path: "/recover"}
	dropped.drop.Store(true)
	cl.http.Transport = dropped
	if _, err = cl.RecoverCredentialLease(t.Context(), binding, "", bundle); err == nil {
		t.Fatal("expected lost result")
	}
	journal, err := (clientControlStore{cl}).Load(t.Context())
	if err != nil || journal.Pending == nil {
		t.Fatal("lost stable intent", err)
	}
	original := journal.Pending.Key
	again, err := NewStored(cl.StoredConfig(), cl.device, cl.directory, enrolled.Grant)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := again.RecoverCredentialLease(t.Context(), binding, "", bundle)
	if err != nil {
		t.Fatal(err)
	}
	if lease.CredentialGeneration != "37" || lease.AuthorizationRevision != "1" {
		t.Fatalf("mixed issuer and Relay counters: %#v", lease)
	}
	journal, err = (clientControlStore{again}).Load(t.Context())
	if err != nil || journal.Pending.Key != original || journal.Pending.Result.Payload.CredentialGeneration != "2" {
		t.Fatal("operation changed after restart", err)
	}
	valid := *journal.Pending.Result
	forged := valid
	child := *valid.Payload.Body.RelayResult
	child.Signature.Value = c.Base64URL(make([]byte, 64))
	forged.Payload.Body.RelayResult = &child
	if again.verifyControlResult(journal.Pending.Intent, forged) == nil {
		t.Fatal("accepted issuer envelope without original Relay signature")
	}
	grant, err := again.PendingControlGrant(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = again.AcceptGrant(*grant.Grant); err != nil {
		t.Fatal(err)
	}
	enrollmentPath := filepath.Join(cl.directory, "relay.enrollment")
	relay, err := bridge.NewRelayCredentialClient(bridge.ProfileProduction, enrollmentPath, bundle, cl.device, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	droppedACK := &dropControlRoundTripper{RoundTripper: again.http.Transport, path: "/ack"}
	droppedACK.drop.Store(true)
	again.http.Transport = droppedACK
	if err = relay.ConfigureCredentialProviderWithInstallation(binding, func(ctx context.Context, b bridge.CredentialBinding, g bridge.CredentialGeneration) (bridge.CredentialLease, error) {
		return again.RecoverCredentialLease(ctx, b, g, bundle)
	}, again.CredentialLeaseInstalled); err != nil {
		t.Fatal(err)
	}
	if _, err = relay.CredentialProvider().EnsureAccess(t.Context(), binding); err == nil {
		t.Fatal("lost ACK was not retained")
	}
	if _, err = os.Stat(enrollmentPath + ".credentials.v2"); err != nil {
		t.Fatal("ACK sent before durable provider install", err)
	}
	if _, err = relay.CredentialProvider().EnsureAccess(t.Context(), binding); err != nil {
		t.Fatal("cached installed lease did not resume ACK", err)
	}
	journal, err = (clientControlStore{again}).Load(t.Context())
	if err != nil || journal.Pending != nil || journal.Generation != "2" {
		t.Fatal("ACK not finalized", err)
	}
	relay.CredentialProvider().Close()
}
