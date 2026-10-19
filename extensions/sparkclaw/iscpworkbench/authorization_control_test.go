package iscpworkbench

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestControlReceiptSurvivesRevocationAndExpiredRelayEnrollment(t *testing.T) {
	issuer, cfg, _, grant := lifecycleFixture(t)
	if err := issuer.AuthorizePermanentRenewal(cfg.GrantFile); err != nil {
		t.Fatal(err)
	}
	control, err := NewAuthorizationControl(cfg)
	if err != nil {
		t.Fatal(err)
	}
	id := newUUID()
	receipt, err := control.DeleteAuthorization(context.Background(), id, grant.RevocationEpoch)
	if err != nil || receipt.State != "revoked" {
		t.Fatalf("delete %+v %v", receipt, err)
	}
	var enrollment map[string]any
	raw, _ := os.ReadFile(cfg.EnrollmentFile)
	if json.Unmarshal(raw, &enrollment) != nil {
		t.Fatal("bad fixture")
	}
	enrollment["expires_at"] = time.Now().Add(-time.Hour).Format(time.RFC3339Nano)
	raw, _ = json.Marshal(enrollment)
	if err = os.WriteFile(cfg.EnrollmentFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = NewEndpoint(cfg, nil, nil); err == nil {
		t.Fatal("normal endpoint accepted expired Relay enrollment")
	}
	restored, err := NewAuthorizationControl(cfg)
	if err != nil {
		t.Fatal(err)
	}
	again, err := restored.AuthorizationDeletionReceipt(context.Background(), id, grant.RevocationEpoch)
	if err != nil || again != receipt {
		t.Fatalf("control receipt lost %+v %v", again, err)
	}
	if _, err = restored.Call(context.Background(), Request{Operation: OperationIdentity}); err == nil {
		t.Fatal("control plane exposed business transport")
	}
}
