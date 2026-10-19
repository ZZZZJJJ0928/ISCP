package iscpnodeissuer

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOperatorMigrationRetainsOnlyApprovedExistingClientBinding(t *testing.T) {
	f := setup(t, NewMemoryStore())
	ctx := context.Background()
	f.issuer.cfg.MigrationClients = map[string]string{"original-client": "operator-migration-operation"}
	f.management.active["original-client"] = true
	before := f.management.creates
	v, e := f.issuer.CreateMigrationInvitation(ctx, "Original SparkX", 15*time.Minute, []string{"settings.read"}, "operator-migration-operation", "original-client")
	if e != nil {
		t.Fatal(e)
	}
	cred, e := ParseCredential(v, time.Now(), false)
	if e != nil || cred.ClientID != "original-client" || cred.OwnerID != f.management.binding.OwnerID || cred.DeploymentID != f.management.binding.DeploymentID {
		t.Fatal("original scope changed")
	}
	if f.management.creates != before {
		t.Fatal("migration created a replacement Client")
	}
	again, e := f.issuer.CreateMigrationInvitation(ctx, "Original SparkX", 15*time.Minute, []string{"settings.read"}, "operator-migration-operation", "original-client")
	if e != nil || again != v {
		t.Fatal("migration retry did not retain exact credential")
	}
	for _, input := range [][2]string{{"wrong-operation", "original-client"}, {"operator-migration-operation", "another-client"}} {
		if _, e = f.issuer.CreateMigrationInvitation(ctx, "Original SparkX", 15*time.Minute, []string{"settings.read"}, input[0], input[1]); !errors.Is(e, ErrDenied) {
			t.Fatal("unapproved migration accepted")
		}
	}
	// The same operation cannot be converted back into ordinary fresh issuance.
	if _, e = f.issuer.CreateInvitation(ctx, "Original SparkX", 15*time.Minute, []string{"settings.read"}, "operator-migration-operation"); !errors.Is(e, ErrConflict) {
		t.Fatal("Client binding substitution accepted")
	}
	f.management.active["original-client"] = false
	if _, e = f.issuer.CreateMigrationInvitation(ctx, "Original SparkX", 15*time.Minute, []string{"settings.read"}, "operator-migration-operation", "original-client"); !errors.Is(e, ErrDenied) {
		t.Fatal("revoked original Client revived")
	}
	if f.management.creates != before {
		t.Fatal("revoked migration manufactured a new Client")
	}
}
