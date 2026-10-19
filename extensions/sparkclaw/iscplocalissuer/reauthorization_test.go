package iscplocalissuer

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

func TestExplicitReauthorizationChangesEpochWithoutRevivingOldDevices(t *testing.T) {
	f := newRenewalFixture(t, 30*time.Minute, false)
	f.permanent(t)
	server := httptest.NewServer(f.i.Handler())
	defer server.Close()
	client := func(grant trust.Grant) *iscpbridge.GrantLifecycleClient {
		c, err := iscpbridge.NewGrantLifecycleClient(server.URL, filepath.Join(t.TempDir(), "pending.json"), f.subject, f.i.device.Identity, "local-relay", grant, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c.RequireStandingAuthorization()
		return c
	}
	ctx := context.Background()
	deleted, err := client(f.grant).DeleteAuthorization(ctx, "manual-deletion", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.i.ReauthorizePermanentScopes("new-consent", 1, []string{"settings.read"}); err == nil {
		t.Fatal("stale operator revision accepted")
	}
	grant, err := f.i.ReauthorizePermanentScopes("new-consent", 2, []string{"settings.read"})
	if err != nil || grant.RevocationEpoch != 3 {
		t.Fatal(grant.RevocationEpoch, err)
	}
	replay, err := f.load(t).ReauthorizePermanentScopes("new-consent", 2, []string{"settings.read"})
	if err != nil || replay.Signature != grant.Signature {
		t.Fatal("operator lost-response replay changed Grant", err)
	}
	if _, err := f.i.ReauthorizePermanentScopes("new-consent", 2, []string{"settings.admin"}); err == nil {
		t.Fatal("operator replay widened scope")
	}
	old := client(f.grant)
	if err := old.CheckAuthorization(ctx); err == nil {
		t.Fatal("old Grant regained access")
	}
	if _, err := old.Current(ctx); err == nil {
		t.Fatal("renewal silently adopted new consent")
	}
	receipt, err := old.AuthorizationDeletionReceipt(ctx, "manual-deletion", 1)
	if err != nil || receipt != deleted {
		t.Fatal("reauthorization erased deletion proof", err)
	}
	current := client(grant)
	policy, err := current.AuthorizationPolicy(ctx)
	if err != nil || !policy.Allows("settings.read") || policy.Allows("settings.admin") || policy.Lifetime != iscpauth.UntilRevoked {
		t.Fatal(policy, err)
	}
	if _, err := current.AuthorizationDeletionReceipt(ctx, "manual-deletion", 1); err == nil {
		t.Fatal("historical receipt revoked a new generation")
	}
	if err := current.CheckAuthorization(ctx); err != nil {
		t.Fatal("old receipt poisoned current consent", err)
	}
}
