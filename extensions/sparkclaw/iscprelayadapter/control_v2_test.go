package iscprelayadapter

import (
	"bytes"
	"context"
	"errors"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"testing"
	"time"

	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func controlRequest(t *testing.T, actor identity.Device, intent control.Intent, action string, ack *control.Ack) control.Request {
	t.Helper()
	digest, e := control.Digest("ISCP-OPERATION-INTENT-V2\x00", intent)
	if e != nil {
		t.Fatal(e)
	}
	r := control.Request{Type: "iscp.operation.request.v2", Protocol: control.Protocol, AttemptID: "test-" + control.RandomID(), Action: action, Key: control.Key{DomainID: actor.Identity.DomainID, DeviceID: actor.Identity.DeviceID, Namespace: intent.Namespace, OperationID: intent.OperationID}, SemanticDigest: digest}
	if action == "ack" {
		r.Ack = ack
	} else {
		d, _, _ := control.NewDelivery()
		r.Delivery = &d
		if action != "lookup" {
			r.Intent = &intent
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	ch := control.Challenge{Type: "iscp.control.challenge.v2", Protocol: control.Protocol, Audience: "test-relay", ChallengeID: control.RandomID(), Challenge: control.RandomID(), Purpose: action, ServerTime: now, ExpiresAt: now.Add(10 * time.Second)}
	if e = control.Authenticate(&r, ch, actor, "", now); e != nil {
		t.Fatal(e)
	}
	return r
}
func TestControlSnapshotRefreshRaceSupersededChildAndLostACKRestart(t *testing.T) {
	pool := database(t)
	ctx := context.Background()
	invite, signer, responder, actor, relaySigner, client := device(t, "invitation"), device(t, "grant-signer"), device(t, "responder"), device(t, "issuer-service"), device(t, "relay-signer"), device(t, "control-desktop")
	cfg := Config{DomainID: "test-domain", RelayID: "test-relay", InvitationSigner: invite.Identity, GrantSigner: signer.Identity, Responder: responder.Identity, ServicePeers: []identity.DeviceIdentity{actor.Identity}, ControlIssuerActor: &actor.Identity}
	a, e := New(ctx, pool, cfg)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := prep(t, a, invite, signer, client, "control-register-operation")
	if e = a.Prepare(ctx, p); e != nil {
		t.Fatal(e)
	}
	if _, e = a.Commit(ctx, node.RegistrationCommit{OperationID: p.OperationID, BindingDigest: p.BindingDigest, IdentityProof: proof(t, client, p.TicketV3.TicketID), TicketV3: p.TicketV3}); e != nil {
		t.Fatal(e)
	}
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.claim(ctx, tx, actor.Identity, false); e == nil {
		e = a.createDevice(ctx, tx, actor.Identity)
	}
	if e != nil {
		tx.Rollback(ctx)
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	// Explicit synthetic genesis provenance; never inferred from an empty ledger.
	_, e = pool.Exec(ctx, `INSERT INTO iscp_relay.writer_scopes(scope_id,writer_role,writes_enabled) VALUES('test-relay',current_user,true); INSERT INTO iscp_relay.domain_authority(scope_id,domain_id,history_id,history_state,history_evidence_sha256,activated_at) VALUES('test-relay','test-domain',repeat('A',43),'continuous',repeat('B',43),now()); INSERT INTO iscp_relay.device_authority VALUES('test-relay','test-domain','control-desktop',1,1,1,'active'),('test-relay','test-domain','issuer-service',1,1,1,'active'); INSERT INTO iscp_relay.connection_owners(scope_id,domain_id,device_id) VALUES('test-relay','test-domain','control-desktop'),('test-relay','test-domain','issuer-service')`)
	if e != nil {
		t.Fatal(e)
	}
	backend, e := a.EnableControlV2(ctx, relaySigner, "1")
	if e != nil {
		t.Fatal(e)
	}
	subject := control.Subject{DomainID: client.Identity.DomainID, DeviceID: client.Identity.DeviceID, BindingID: p.Binding.ClientID}
	target := control.Target{ServiceID: "test-relay", ResourceID: p.Binding.ClientID}
	snapshot, e := backend.Authority(ctx, actor.Identity, subject, target)
	if e != nil || snapshot.Generation != "1" {
		t.Fatalf("snapshot %v %v", snapshot, e)
	}
	base := control.Intent{Type: "iscp.operation.intent.v2", Version: 2, Namespace: control.RelayNamespace, OperationID: "direct-refresh-operation", Kind: "relay.refresh", SubjectBinding: subject, Target: target, TaskAuthorization: control.Standing{Kind: "standing", AuthorizationRevision: "1", Scopes: []string{node.Permission}}, Payload: control.Payload{RequestedScopes: []string{node.Permission}}, Preconditions: control.Preconditions{ResourceVersion: "1", CredentialGeneration: snapshot.Generation, AuthorizationRevision: "1"}}
	direct, e := backend.Execute(ctx, controlRequest(t, client, base, "recover", nil), client.Identity, "")
	if e != nil || direct.Result == nil || direct.Result.Payload.CredentialGeneration != "2" {
		t.Fatalf("refresh failed %v", e)
	}
	parentKey := control.Key{DomainID: client.Identity.DomainID, DeviceID: client.Identity.DeviceID, Namespace: control.CredentialNamespace, OperationID: "parent-operation"}
	parentDigest := control.RandomID()
	child := base
	child.Kind = "relay.recover"
	child.OperationID, _ = control.ChildOperationID(parentKey, parentDigest, "test-relay", "0", nil)
	child.Parent = &control.Parent{Key: parentKey, SemanticDigest: parentDigest, Step: "relay.credentials.recover", ChildIndex: "0"}
	request := controlRequest(t, actor, child, "recover", nil)
	failed, e := backend.Execute(ctx, request, actor.Identity, "")
	if e != nil || failed.Result == nil || failed.Result.Payload.State != "failed" || failed.Result.Payload.Body.Code != "generation_conflict" || failed.Result.Payload.Body.RelayCredentials != nil {
		t.Fatalf("CAS race did not durably fail: %#v %v", failed, e)
	}
	ack := control.Ack{ResultDigest: failed.Result.ResultDigest, Disposition: "acknowledged_superseded", CredentialGeneration: "1", RecordedAt: time.Now().UTC().Truncate(time.Second)}
	ackRequest := controlRequest(t, actor, child, "ack", &ack)
	closed, e := backend.Execute(ctx, ackRequest, actor.Identity, "")
	if e != nil || closed.Disposition == nil {
		t.Fatalf("superseded close %v", e)
	}
	restarted, e := a.EnableControlV2(ctx, relaySigner, "1")
	if e != nil {
		t.Fatal(e)
	}
	retried, e := restarted.Execute(ctx, ackRequest, actor.Identity, "")
	if e != nil || retried.Disposition == nil || retried.Disposition.DispositionDigest != closed.Disposition.DispositionDigest {
		t.Fatal("lost ACK/restart changed disposition", e)
	}
	predecessor := closed.Disposition.DispositionDigest
	successor := child
	successor.OperationID, _ = control.ChildOperationID(parentKey, parentDigest, "test-relay", "1", &predecessor)
	successor.Parent = &control.Parent{Key: parentKey, SemanticDigest: parentDigest, Step: "relay.credentials.recover", ChildIndex: "1"}
	successor.Preconditions.CredentialGeneration = "2"
	successor.Predecessor = &control.Predecessor{Key: request.Key, ResultDigest: failed.Result.ResultDigest, DispositionDigest: predecessor}
	succeeded, e := restarted.Execute(ctx, controlRequest(t, actor, successor, "recover", nil), actor.Identity, "")
	if e != nil || succeeded.Result == nil || succeeded.Result.Payload.CredentialGeneration != "3" {
		t.Fatal("linked successor failed", e)
	}
	// A correctly authenticated issuer still cannot invent IDs or skip a
	// retained predecessor index, even with the current CAS generation.
	for _, mutate := range []func(*control.Intent){
		func(v *control.Intent) { v.OperationID = "arbitrary-child-operation" },
		func(v *control.Intent) { p := *v.Parent; p.ChildIndex = "0"; v.Parent = &p },
		func(v *control.Intent) {
			p := *v.Parent
			p.ChildIndex = "3"
			v.Parent = &p
			v.OperationID, _ = control.ChildOperationID(p.Key, p.SemanticDigest, v.Target.ServiceID, p.ChildIndex, &v.Predecessor.DispositionDigest)
		},
	} {
		forged := successor
		mutate(&forged)
		if _, err := restarted.Execute(ctx, controlRequestUnchecked(t, actor, forged), actor.Identity, ""); err == nil {
			t.Fatal("accepted forged child chain")
		}
	}
	token := succeeded.Result.Payload.Body.RelayCredentials.Access.Token
	var stored string
	var ciphertext []byte
	e = pool.QueryRow(ctx, "SELECT credential_generation::text FROM iscp_relay.access_tokens WHERE device_id=$1 AND revoked_at IS NULL", client.Identity.DeviceID).Scan(&stored)
	if e != nil || stored != "3" {
		t.Fatalf("token generation %s %v", stored, e)
	}
	e = pool.QueryRow(ctx, "SELECT ciphertext FROM iscp_relay.control_operations WHERE operation_id=$1", successor.OperationID).Scan(&ciphertext)
	if e != nil || bytes.Contains(ciphertext, []byte(token)) {
		t.Fatal("credential result not encrypted")
	}
	disclosure := controlRequest(t, actor, successor, "lookup", nil)
	started, release := make(chan struct{}), make(chan struct{})
	disclosed := make(chan error, 1)
	go func() {
		disclosed <- restarted.Disclose(ctx, disclosure, actor.Identity, func() error { close(started); <-release; return nil })
	}()
	<-started
	revoked := make(chan error, 1)
	go func() {
		tx, err := pool.Begin(ctx)
		if err != nil {
			revoked <- err
			return
		}
		defer tx.Rollback(ctx)
		_, err = authority.Lock(ctx, tx, authority.Request{ScopeID: "test-relay", DomainID: "test-domain", ExpectedWriterEpoch: "1", Devices: []authority.DeviceLock{{ID: client.Identity.DeviceID, Exclusive: true}}, AllowInactiveDevices: true})
		if err == nil {
			_, err = tx.Exec(ctx, "UPDATE iscp_relay.device_authority SET state='revoked',authorization_revision=2,state_version=state_version+1 WHERE scope_id='test-relay' AND domain_id='test-domain' AND device_id=$1", client.Identity.DeviceID)
		}
		if err == nil {
			err = tx.Commit(ctx)
		}
		revoked <- err
	}()
	select {
	case err := <-revoked:
		t.Fatalf("revocation passed in-progress disclosure: %v", err)
	case <-time.After(40 * time.Millisecond):
	}
	close(release)
	if err := <-disclosed; err != nil {
		t.Fatal(err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	emitted := false
	err := restarted.Disclose(ctx, disclosure, actor.Identity, func() error { emitted = true; return nil })
	var failure *control.Failure
	if emitted || !errors.As(err, &failure) || failure.Code != "authorization_revoked" {
		t.Fatalf("post-revoke result disclosed: %v %v", emitted, err)
	}
	// Restore only the synthetic test authority under the same ordered lock so
	// subsequent exact-result assertions can inspect the original record.
	tx, e = pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = authority.Lock(ctx, tx, authority.Request{ScopeID: "test-relay", DomainID: "test-domain", ExpectedWriterEpoch: "1", Devices: []authority.DeviceLock{{ID: client.Identity.DeviceID, Exclusive: true}}, AllowInactiveDevices: true})
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.Exec(ctx, "UPDATE iscp_relay.device_authority SET state='active',authorization_revision=1,state_version=state_version+1 WHERE scope_id='test-relay' AND domain_id='test-domain' AND device_id=$1", client.Identity.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	// A raw operation replay remains exactly the failed result, not another issue.
	replay, e := restarted.Execute(ctx, request, actor.Identity, "")
	if e != nil || replay.Result.ResultDigest != failed.Result.ResultDigest {
		t.Fatal("original child was replaced", e)
	}
	var count int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM iscp_relay.control_operations").Scan(&count); e != nil || count != 3 {
		t.Fatalf("expected durable three records, got %d %v", count, e)
	}
}

func controlRequestUnchecked(t *testing.T, actor identity.Device, intent control.Intent) control.Request {
	t.Helper()
	digest, err := control.Digest("ISCP-OPERATION-INTENT-V2\x00", intent)
	if err != nil {
		t.Fatal(err)
	}
	r := control.Request{Type: "iscp.operation.request.v2", Protocol: control.Protocol, AttemptID: "test-" + control.RandomID(), Action: "recover", Key: control.Key{DomainID: actor.Identity.DomainID, DeviceID: actor.Identity.DeviceID, Namespace: intent.Namespace, OperationID: intent.OperationID}, SemanticDigest: digest, Intent: &intent}
	d, _, _ := control.NewDelivery()
	r.Delivery = &d
	// Reuse a valid proof-shaped authentication; Execute is after the HTTP proof
	// boundary and must independently enforce the semantic parent-child checks.
	base := intent
	base.Parent = nil
	base.Predecessor = nil
	base.SubjectBinding.DeviceID = actor.Identity.DeviceID
	valid := controlRequest(t, actor, base, "recover", nil)
	r.Authentication = valid.Authentication
	return r
}
