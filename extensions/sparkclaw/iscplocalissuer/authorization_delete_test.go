package iscplocalissuer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
)

func TestSelfDeletionReceiptRecoversAfterIssuerAndDeviceRestart(t *testing.T) {
	f := newRenewalFixture(t, 30*time.Minute, false)
	f.permanent(t)
	server := httptest.NewServer(f.i.Handler())
	defer server.Close()
	newClient := func() *iscpbridge.GrantLifecycleClient {
		client, err := iscpbridge.NewGrantLifecycleClient(server.URL, filepath.Join(t.TempDir(), "pending.json"), f.subject, f.i.device.Identity, "local-relay", f.grant, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		client.RequireStandingAuthorization()
		return client
	}
	client := newClient()
	ctx := context.Background()
	if _, err := client.AuthorizationDeletionReceipt(ctx, "delete-1", 1); err == nil {
		t.Fatal("invented a receipt")
	}
	first, err := client.DeleteAuthorization(ctx, "delete-1", 1)
	if err != nil || first.State != iscpauth.Revoked || first.AuthorizationRevision != 2 {
		t.Fatal(first, err)
	}
	if err := client.CheckAuthorization(ctx); !errors.Is(err, iscpbridge.ErrAuthorizationRevoked) {
		t.Fatal(err)
	}
	// The issuer reloads the durable tombstone on every request. A newly
	// constructed client can query it despite a revoked Grant.
	if _, err := f.load(t).readRenewalState(); err != nil {
		t.Fatal(err)
	}
	recovered, err := newClient().AuthorizationDeletionReceipt(ctx, "delete-1", 1)
	if err != nil || recovered != first {
		t.Fatal(recovered, err)
	}
	retried, err := newClient().DeleteAuthorization(ctx, "delete-1", 1)
	if err != nil || retried != first {
		t.Fatal(retried, err)
	}
	if _, err := newClient().DeleteAuthorization(ctx, "delete-other", 1); err == nil {
		t.Fatal("different operation consumed original receipt")
	}
	if _, err := newClient().AuthorizationDeletionReceipt(ctx, "delete-1", 2); err == nil {
		t.Fatal("different revision consumed original receipt")
	}
}

func TestDeletionProofCannotBeSubstitutedFromStatusOrOtherActions(t *testing.T) {
	f := newRenewalFixture(t, 30*time.Minute, false)
	f.permanent(t)
	for _, challenge := range []string{"key", iscpauth.DeletionChallenge(iscpauth.DeleteReceiptPath, "key", "operation", 1), iscpauth.DeletionChallenge(iscpauth.DeletePath, "key", "other", 1), iscpauth.DeletionChallenge(iscpauth.DeletePath, "key", "operation", 2)} {
		var proof RenewalRequest
		_ = json.Unmarshal(f.body(t, f.subject, challenge, "nonce"), &proof)
		raw, _ := json.Marshal(deletionRequest{RenewalRequest: proof, OperationID: "operation", ExpectedRevision: 1})
		requireReason(t, grantRequest(f.i, iscpauth.DeletePath, "key", raw), 401, "device_proof_invalid")
	}
	// A Gateway holds the audience key; possession alone cannot delete the
	// initiating device's standing consent.
	var proof RenewalRequest
	_ = json.Unmarshal(f.body(t, f.audience, iscpauth.DeletionChallenge(iscpauth.DeletePath, "key", "operation", 1), "nonce"), &proof)
	raw, _ := json.Marshal(deletionRequest{RenewalRequest: proof, OperationID: "operation", ExpectedRevision: 1})
	requireReason(t, grantRequest(f.i, iscpauth.DeletePath, "key", raw), 401, "device_proof_invalid")
	state, err := f.i.readRenewalState()
	if err != nil || state.Authorization.Revoked {
		t.Fatal("invalid proof changed authority", err)
	}
}
