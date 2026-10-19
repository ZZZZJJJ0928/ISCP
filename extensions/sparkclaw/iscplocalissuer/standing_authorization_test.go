package iscplocalissuer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
)

func (f *renewalFixture) permanent(t *testing.T) string {
	t.Helper()
	path := filepath.Join(f.dir, "permanent-grant.json")
	raw, _ := json.Marshal(f.grant)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.i.AuthorizePermanentRenewal(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPermanentAuthorizationSurvivesYearsAndRevocationSurvivesRestart(t *testing.T) {
	f := newRenewalFixture(t, 30*time.Minute, true)
	path := f.permanent(t)
	f.clock.Add(int64(2 * 365 * 24 * time.Hour))
	i := f.load(t)
	w := grantRequest(i, AutoRenewPath, "renew-after-years", f.body(t, f.subject, "renew-after-years", "fresh-nonce"))
	grant := responseGrant(t, w, 201)
	if grant.ExpiresAt.Sub(grant.NotBefore) != 30*time.Minute {
		t.Fatal("standing consent changed Grant TTL")
	}
	state, err := i.readRenewalState()
	if err != nil || state.SchemaVersion != 2 || !state.Authorization.ExpiresAt.IsZero() || state.Authorization.Lifetime != iscpauth.UntilRevoked {
		t.Fatalf("permanent policy: %v", err)
	}
	if err := i.RevokeRenewal(); err != nil {
		t.Fatal(err)
	}
	i = f.load(t)
	if err := i.RevokeRenewal(); err != nil {
		t.Fatal(err)
	}
	state, _ = i.readRenewalState()
	if state.Authorization.Revision != 2 {
		t.Fatal("repeated deletion changed revision")
	}
	requireReason(t, grantRequest(i, CurrentGrantPath, "after-revoke", f.body(t, f.subject, "after-revoke", "other")), 403, "renewal_authorization_revoked")
	// Even a signed success replay cannot bypass current revocation.
	requireReason(t, grantRequest(i, AutoRenewPath, "renew-after-years", f.body(t, f.subject, "renew-after-years", "fresh-nonce")), 403, "renewal_authorization_revoked")
	if err := i.AuthorizePermanentRenewal(path); err == nil {
		t.Fatal("migration resurrected deleted consent")
	}
	if err := i.AuthorizeRenewal(path, 24); err == nil {
		t.Fatal("legacy setup replaced permanent tombstone")
	}
}

func TestPermanentRenewalReceiptsAreBoundedWithoutReissuingOldRequest(t *testing.T) {
	f := newRenewalFixture(t, 30*time.Minute, false)
	f.permanent(t)
	f.clock.Add(int64(25 * time.Minute))
	raw := f.body(t, f.subject, "renew-receipt", "receipt-nonce")
	first := responseGrant(t, grantRequest(f.i, AutoRenewPath, "renew-receipt", raw), 201)
	f.clock.Add(int64(6 * 24 * time.Hour))
	cached := responseGrant(t, grantRequest(f.load(t), AutoRenewPath, "renew-receipt", raw), 201)
	if cached.Signature != first.Signature {
		t.Fatal("original receipt changed")
	}
	f.clock.Add(int64(2 * 24 * time.Hour))
	if w := grantRequest(f.load(t), AutoRenewPath, "renew-receipt", raw); w.Code == 201 {
		t.Fatal("expired receipt issued another Grant from stale proof")
	}
	fresh := responseGrant(t, grantRequest(f.load(t), AutoRenewPath, "fresh-renewal", f.body(t, f.subject, "fresh-renewal", "fresh-nonce")), 201)
	if fresh.GrantID == first.GrantID {
		t.Fatal("fresh proof could not renew permanent consent")
	}
	state, _ := f.i.readRenewalState()
	if len(state.Idempotency) != 1 {
		t.Fatal("old receipt was not pruned")
	}
}

func TestStandingStatusClientRejectsReplayForgeryAndUnsignedRevocation(t *testing.T) {
	f := newRenewalFixture(t, 30*time.Minute, false)
	f.permanent(t)
	var mu sync.Mutex
	mode := "live"
	var captured []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != iscpauth.StatusPath {
			f.i.Handler().ServeHTTP(w, r)
			return
		}
		if mode == "http403" {
			w.WriteHeader(403)
			return
		}
		if mode == "replay" {
			_, _ = w.Write(captured)
			return
		}
		result := httptest.NewRecorder()
		f.i.Handler().ServeHTTP(result, r)
		raw := result.Body.Bytes()
		if mode == "forged" {
			var signed descriptor.SignedDescriptor
			_ = json.Unmarshal(raw, &signed)
			signed.Signature.Value = "forged"
			raw, _ = json.Marshal(signed)
		} else {
			captured = append([]byte(nil), raw...)
		}
		w.WriteHeader(result.Code)
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	client, err := iscpbridge.NewGrantLifecycleClient(server.URL, filepath.Join(f.dir, "pending.json"), f.subject, f.i.device.Identity, "local-relay", f.grant, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.RequireStandingAuthorization()
	ctx := context.Background()
	if _, err := client.Current(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.CheckAuthorization(ctx); err != nil {
		t.Fatal(err)
	}
	// A renewal eligibility 429 must not pause authorization/revocation checks.
	if _, err := client.Renew(ctx, f.grant); err == nil {
		t.Fatal("expected early renewal backoff")
	}
	if err := client.CheckAuthorization(ctx); err != nil {
		t.Fatalf("renewal backoff blocked status: %v", err)
	}

	for _, attack := range []string{"replay", "forged", "http403"} {
		mu.Lock()
		mode = attack
		mu.Unlock()
		if err := client.CheckAuthorization(ctx); err == nil || errors.Is(err, iscpbridge.ErrAuthorizationRevoked) {
			t.Fatalf("%s accepted or permanently revoked: %v", attack, err)
		}
	}
	mu.Lock()
	mode = "live"
	mu.Unlock()
	if err := client.CheckAuthorization(ctx); err != nil {
		t.Fatalf("transient error locked consent: %v", err)
	}
	if err := f.load(t).RevokeRenewal(); err != nil {
		t.Fatal(err)
	}
	if err := client.CheckAuthorization(ctx); !errors.Is(err, iscpbridge.ErrAuthorizationRevoked) {
		t.Fatalf("signed revocation not recognized: %v", err)
	}
	mu.Lock()
	mode = "replay"
	mu.Unlock()
	if _, err := client.Current(ctx); !errors.Is(err, iscpbridge.ErrAuthorizationRevoked) {
		t.Fatal("deleted authorization resumed")
	}
	// Fresh process also requires a fresh proof-bound signed status.
	restarted, err := iscpbridge.NewGrantLifecycleClient(server.URL, filepath.Join(f.dir, "other-pending.json"), f.audience, f.i.device.Identity, "local-relay", f.grant, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	restarted.RequireStandingAuthorization()
	if err := restarted.CheckAuthorization(ctx); err == nil {
		t.Fatal("different device accepted replay")
	}
	mu.Lock()
	mode = "live"
	mu.Unlock()
	if err := restarted.CheckAuthorization(ctx); !errors.Is(err, iscpbridge.ErrAuthorizationRevoked) {
		t.Fatalf("restart failed to observe deletion: %v", err)
	}
}

func TestPermanentMigrationPreservesShortenedGrantTTL(t *testing.T) {
	f := newRenewalFixture(t, 30*time.Minute, true)
	f.clock.Add(int64(24*time.Hour - time.Minute))
	f.grant = responseGrant(t, grantRequest(f.i, AutoRenewPath, "short-grant", f.body(t, f.subject, "short-grant", "nonce")), 201)
	if f.grant.ExpiresAt.Sub(f.grant.NotBefore) != time.Minute {
		t.Fatal("fixture did not shorten bounded Grant")
	}
	f.permanent(t)
	f.clock.Add(int64(2 * time.Minute))
	next := responseGrant(t, grantRequest(f.load(t), AutoRenewPath, "permanent-short", f.body(t, f.subject, "permanent-short", "new-nonce")), 201)
	if next.ExpiresAt.Sub(next.NotBefore) != time.Minute {
		t.Fatal("migration expanded the signed TTL continuity bound")
	}
}

func TestExplicitScopesPersistAndRenewalCannotWiden(t *testing.T) {
	f := newRenewalFixture(t, 30*time.Minute, false)
	path := filepath.Join(f.dir, "scoped-grant.json")
	raw, _ := json.Marshal(f.grant)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.i.AuthorizePermanentScopes(path, []string{"settings.read", "notifications.read"}); err != nil {
		t.Fatal(err)
	}
	if err := f.i.AuthorizePermanentScopes(path, []string{"settings.admin"}); err == nil {
		t.Fatal("in-place scope widening accepted")
	}
	i := f.load(t)
	server := httptest.NewServer(i.Handler())
	defer server.Close()
	client, err := iscpbridge.NewGrantLifecycleClient(server.URL, filepath.Join(f.dir, "scoped-pending.json"), f.subject, i.device.Identity, "local-relay", f.grant, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.RequireStandingAuthorization()
	policy, err := client.AuthorizationPolicy(context.Background())
	if err != nil || !policy.Allows("settings.read") || policy.Allows("settings.admin") {
		t.Fatal(policy, err)
	}
	policy.Scopes[0] = "settings.admin"
	again, err := client.AuthorizationPolicy(context.Background())
	if err != nil || again.Allows("settings.admin") {
		t.Fatal("caller mutated signed scopes")
	}
	f.clock.Add(int64(25 * time.Minute))
	responseGrant(t, grantRequest(i, AutoRenewPath, "scoped-renew", f.body(t, f.subject, "scoped-renew", "scoped-nonce")), 201)
	state, err := f.load(t).readRenewalState()
	if err != nil || !state.policy(f.now()).Allows("notifications.read") || state.policy(f.now()).Allows("settings.admin") {
		t.Fatal(state, err)
	}
}
