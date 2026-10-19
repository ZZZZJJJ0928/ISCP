package iscpbridge

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

func signedLifecycleGrantAt(t *testing.T, h *grantLifecycleHarness, id string, notBefore, expires time.Time, epoch uint64) trust.Grant {
	t.Helper()
	grant := cloneLifecycleGrant(h.previous)
	grant.GrantID, grant.NotBefore, grant.ExpiresAt, grant.RevocationEpoch = id, notBefore, expires, epoch
	grant, err := trust.SignGrant(h.provider, h.issuer, grant)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

// These signed short-TTL snapshots model the server's clock advancing while
// the client is offline. The test does not sleep or weaken runtime freshness.
func prepareExpiredUnknownRenewal(t *testing.T, h *grantLifecycleHarness, path string) (trust.Grant, trust.Grant) {
	t.Helper()
	now := time.Now().UTC()
	previous := signedLifecycleGrantAt(t, h, "original-short-grant", now.Add(-4*time.Minute), now.Add(-3*time.Minute), 4)
	cached := signedLifecycleGrantAt(t, h, "cached-expired-success", now.Add(-2*time.Minute), now.Add(-time.Minute), 4)
	h.mu.Lock()
	h.previous, h.current, h.renewed = previous, previous, cached
	h.responseStatus = 503
	h.mu.Unlock()
	client := h.client(t, path, h.subject, previous, time.Second)
	if _, err := client.Renew(context.Background(), previous); err == nil || !client.HasPendingRenewal() {
		t.Fatal("unknown renewal was not persisted")
	}
	h.mu.Lock()
	h.responseStatus = 0
	h.mu.Unlock()
	return previous, cached
}

func TestGrantLifecycleExpiredCachedSuccessRetiresAndRecoversAfterRestart(t *testing.T) {
	h := newGrantLifecycleHarness(t)
	path := filepath.Join(t.TempDir(), "pending.json")
	previous, _ := prepareExpiredUnknownRenewal(t, h, path)
	restarted := h.client(t, path, h.subject, previous, time.Second)
	result, err := restarted.Renew(context.Background(), previous)
	if !errors.Is(err, ErrGrantRenewalResultExpired) || result.GrantID != "" {
		t.Fatalf("expired result entered authorization or was not retired: %v", err)
	}
	if restarted.HasPendingRenewal() || restarted.previous.GrantID != previous.GrantID {
		t.Fatal("retirement changed the baseline or kept the settled request")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("settled expired request was not durably retired")
	}
	h.mu.Lock()
	if len(h.keys) != 2 || h.keys[0] != h.keys[1] || !bytes.Equal(h.bodies[0], h.bodies[1]) {
		t.Fatal("expired cached response was not reached using exact replay")
	}
	oldKey := h.keys[1]
	now := time.Now().UTC()
	h.renewed = signedLifecycleGrantAt(t, h, "fresh-recovery", now, now.Add(time.Minute), 4)
	h.mu.Unlock()
	// A second process after retirement starts a new durable logical request.
	recovered := h.client(t, path, h.subject, previous, time.Second)
	result, err = recovered.Renew(context.Background(), previous)
	if err != nil || result.GrantID != "fresh-recovery" || !time.Now().UTC().Before(result.ExpiresAt) {
		t.Fatalf("fresh renewal did not recover: %v", err)
	}
	h.mu.Lock()
	if h.keys[2] == oldKey || bytes.Equal(h.bodies[1], h.bodies[2]) {
		t.Fatal("new recovery reused the retired request")
	}
	h.mu.Unlock()
	if !recovered.HasPendingRenewal() {
		t.Fatal("fresh success was retired before caller saved it")
	}
	if err := recovered.CommitRenewal(); err != nil {
		t.Fatal(err)
	}
}

func TestGrantLifecycleExpiredCachedSuccessPreservesNewerRollbackFence(t *testing.T) {
	h := newGrantLifecycleHarness(t)
	path := filepath.Join(t.TempDir(), "pending.json")
	_, _ = prepareExpiredUnknownRenewal(t, h, path)
	now := time.Now().UTC()
	latest := signedLifecycleGrantAt(t, h, "newer-persisted-grant", now.Add(-time.Second), now.Add(59*time.Second), 5)
	restarted := h.client(t, path, h.subject, latest, time.Second)
	result, err := restarted.Renew(context.Background(), latest)
	if !errors.Is(err, ErrGrantRenewalResultExpired) || result.GrantID != "" {
		t.Fatalf("older settled renewal blocked recovery: %v", err)
	}
	if restarted.HasPendingRenewal() || restarted.previous.GrantID != latest.GrantID || restarted.previous.RevocationEpoch != 5 {
		t.Fatal("settled historical result rolled back the caller's authorization")
	}
}

func TestGrantLifecycleInvalidExpiredCachedResultKeepsExactPending(t *testing.T) {
	mutations := map[string]func(*trust.Grant){
		"tampered signature": func(g *trust.Grant) { g.Signature.Value = "tampered" },
		"widened scope":      func(g *trust.Grant) { g.Permissions = append(g.Permissions, "filesystem") },
		"wrong subject":      func(g *trust.Grant) { g.SubjectDeviceID = "other-device" },
		"wrong confirmation": func(g *trust.Grant) { g.ConfirmationThumbprint = "other-key" },
		"epoch rollback":     func(g *trust.Grant) { g.RevocationEpoch = 3 },
		"TTL widened":        func(g *trust.Grant) { g.ExpiresAt = g.ExpiresAt.Add(time.Nanosecond) },
		"no extension": func(g *trust.Grant) {
			g.NotBefore = g.NotBefore.Add(-2 * time.Minute)
			g.ExpiresAt = g.ExpiresAt.Add(-2 * time.Minute)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			h := newGrantLifecycleHarness(t)
			path := filepath.Join(t.TempDir(), "pending.json")
			previous, cached := prepareExpiredUnknownRenewal(t, h, path)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&cached)
			if name != "tampered signature" {
				cached, err = trust.SignGrant(h.provider, h.issuer, cached)
				if err != nil {
					t.Fatal(err)
				}
			}
			h.mu.Lock()
			h.renewed = cached
			h.mu.Unlock()
			restarted := h.client(t, path, h.subject, previous, time.Second)
			result, err := restarted.Renew(context.Background(), previous)
			if err == nil || errors.Is(err, ErrGrantRenewalResultExpired) || result.GrantID != "" || !restarted.HasPendingRenewal() {
				t.Fatalf("unverified outcome was accepted or retired: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("unverified expired result changed the durable unknown request")
			}
		})
	}
}
