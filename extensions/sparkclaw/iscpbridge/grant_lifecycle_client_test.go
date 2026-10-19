package iscpbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

type grantLifecycleHarness struct {
	provider                   iscpcrypto.Provider
	subject, audience, issuer  identity.Device
	previous, renewed, current trust.Grant
	server                     *httptest.Server
	mu                         sync.Mutex
	capChange                  func(*descriptor.TrustRootDescriptor)
	forgeCapability            bool
	responseStatus             int
	responseDelay              time.Duration
	keys                       []string
	bodies                     [][]byte
	cache                      map[string][]byte
	capCalls, postCalls        atomic.Int32
}

func newGrantLifecycleHarness(t *testing.T) *grantLifecycleHarness {
	t.Helper()
	now := time.Now().UTC()
	p := iscpcrypto.NewProvider()
	h := &grantLifecycleHarness{provider: p, cache: map[string][]byte{}}
	var err error
	h.subject, err = identity.NewDevice(p, "lifecycle-domain", "desktop", now)
	if err != nil {
		t.Fatal(err)
	}
	h.audience, err = identity.NewDevice(p, "lifecycle-domain", "gateway", now)
	if err != nil {
		t.Fatal(err)
	}
	h.issuer, err = identity.NewDevice(p, "lifecycle-domain", "issuer", now)
	if err != nil {
		t.Fatal(err)
	}
	thumb, _ := identity.Thumbprint(h.subject.Identity)
	h.previous, err = trust.SignGrant(p, h.issuer, trust.Grant{GrantID: "old-grant", SubjectDeviceID: "desktop", Audience: "gateway", ConfirmationThumbprint: thumb,
		Permissions: []string{"sparkclaw.workbench.v1"}, RelayConstraints: []string{"relay-test"}, NotBefore: now.Add(-50 * time.Minute), ExpiresAt: now.Add(10 * time.Minute), RevocationEpoch: 4})
	if err != nil {
		t.Fatal(err)
	}
	h.renewed = cloneLifecycleGrant(h.previous)
	h.renewed.GrantID = "renewed-grant"
	h.renewed.NotBefore = now.Add(-time.Second)
	h.renewed.ExpiresAt = now.Add(59 * time.Minute)
	h.renewed, err = trust.SignGrant(p, h.issuer, h.renewed)
	if err != nil {
		t.Fatal(err)
	}
	h.current = h.previous
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if r.Method == http.MethodGet && r.URL.Path == "/v1/renewal-capability" {
			h.capCalls.Add(1)
			now := time.Now().UTC()
			cap := descriptor.TrustRootDescriptor{Type: "iscp.trust_root.descriptor.v2", TrustRootID: h.issuer.Identity.DeviceID, DomainID: h.issuer.Identity.DomainID,
				IssuedAt: now, ExpiresAt: now.Add(4 * time.Minute), Keys: []descriptor.PublicKey{{KTY: "Ed25519", Use: "descriptor-signature", KID: h.issuer.Identity.PublicKey.KID, Public: h.issuer.Identity.PublicKey.Public, State: "active"}},
				Metadata: map[string]string{"purpose": GrantRenewalCapabilityPurpose, "grant_renewal": "true", "issuer_device_id": "issuer", "relay_id": "relay-test", "subject_device_id": "desktop",
					"audience_device_id": "gateway", "permission": "sparkclaw.workbench.v1", "authorization_expires_at": now.Add(24 * time.Hour).Format(time.RFC3339Nano)}}
			if h.capChange != nil {
				h.capChange(&cap)
			}
			signed, err := descriptor.Sign(p, h.issuer, cap.Type, cap, now)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			if h.forgeCapability {
				signed.Signature.Value = iscpcrypto.Base64URL(make([]byte, 64))
			}
			_ = json.NewEncoder(w).Encode(signed)
			return
		}
		if r.Method != http.MethodPost || (r.URL.Path != "/v1/grants/current" && r.URL.Path != "/v2/relay/devices/auto-renew-grant") {
			t.Errorf("unexpected lifecycle endpoint %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			return
		}
		h.postCalls.Add(1)
		raw, _ := io.ReadAll(io.LimitReader(r.Body, grantLifecycleMaxBody+1))
		key := r.Header.Get("Idempotency-Key")
		h.keys = append(h.keys, key)
		h.bodies = append(h.bodies, append([]byte(nil), raw...))
		var request grantLifecycleRequest
		if json.Unmarshal(raw, &request) != nil || key == "" {
			t.Error("invalid lifecycle request")
			w.WriteHeader(400)
			return
		}
		// Unknown-outcome replays are checked before proof freshness. The exact
		// original signed bytes commit to the cached logical operation.
		if original, ok := h.cache[key]; ok {
			if !bytes.Equal(original, raw) {
				t.Error("unknown renewal body changed")
				w.WriteHeader(409)
				return
			}
		} else {
			if identity.VerifyProof(p, request.Identity, request.Proof, "relay-test", key, time.Now().UTC(), time.Minute) != nil {
				t.Error("invalid proof binding")
				w.WriteHeader(401)
				return
			}
			if r.URL.Path == "/v2/relay/devices/auto-renew-grant" {
				h.cache[key] = append([]byte(nil), raw...)
			}
		}
		if h.responseDelay > 0 {
			time.Sleep(h.responseDelay)
		}
		if h.responseStatus != 0 {
			if h.responseStatus == 429 {
				w.Header().Set("Retry-After", "2")
			}
			w.WriteHeader(h.responseStatus)
			_, _ = io.WriteString(w, `{"error":"secret-response-payload-must-not-leak"}`)
			return
		}
		grant := h.current
		if r.URL.Path == "/v2/relay/devices/auto-renew-grant" {
			grant = h.renewed
			h.current = h.renewed
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"device_id": request.Identity.DeviceID, "domain_id": request.Identity.DomainID}, "grant": grant})
	}))
	t.Cleanup(h.server.Close)
	return h
}

func (h *grantLifecycleHarness) client(t *testing.T, path string, device identity.Device, previous trust.Grant, timeout time.Duration) *GrantLifecycleClient {
	t.Helper()
	c, err := NewGrantLifecycleClient(h.server.URL, path, device, h.issuer.Identity, "relay-test", previous, timeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.http.CloseIdleConnections)
	return c
}

func TestGrantLifecycleUnknownOutcomeExactReplayAfterRestart(t *testing.T) {
	h := newGrantLifecycleHarness(t)
	path := filepath.Join(t.TempDir(), "pending.json")
	c := h.client(t, path, h.subject, h.previous, time.Second)
	h.mu.Lock()
	h.responseStatus = 503
	h.mu.Unlock()
	if _, err := c.Renew(context.Background(), h.previous); err == nil || strings.Contains(err.Error(), "secret-response") {
		t.Fatalf("expected bounded unknown outcome error: %v", err)
	}
	if !c.HasPendingRenewal() {
		t.Fatal("unknown outcome lost its logical request")
	}
	if err := c.CommitRenewal(); err == nil {
		t.Fatal("unconfirmed renewal was committed")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("pending permissions: %v %v", info, err)
	}
	h.mu.Lock()
	h.responseStatus = 0
	h.mu.Unlock()
	restarted := h.client(t, path, h.subject, h.previous, time.Second)
	result, err := restarted.Renew(context.Background(), h.previous)
	if err != nil || result.GrantID != h.renewed.GrantID {
		t.Fatalf("restart renewal: %v", err)
	}
	if !restarted.HasPendingRenewal() {
		t.Fatal("success cleared pending before caller persisted Grant")
	}
	h.mu.Lock()
	if len(h.keys) != 2 || h.keys[0] != h.keys[1] || !bytes.Equal(h.bodies[0], h.bodies[1]) {
		t.Fatal("logical request was not replayed byte for byte")
	}
	h.mu.Unlock()
	// Simulate caller save succeeding, then a crash before CommitRenewal.
	saved := h.client(t, path, h.subject, result, time.Second)
	replay, err := saved.Renew(context.Background(), result)
	if err != nil || replay.GrantID != result.GrantID {
		t.Fatalf("save-before-commit crash recovery: %v", err)
	}
	if err := saved.CommitRenewal(); err != nil {
		t.Fatal(err)
	}
	if saved.HasPendingRenewal() {
		t.Fatal("commit retained pending")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("committed pending still on disk")
	}
}

func TestGrantLifecycleTimeoutRetainsRequest(t *testing.T) {
	h := newGrantLifecycleHarness(t)
	path := filepath.Join(t.TempDir(), "pending.json")
	c := h.client(t, path, h.subject, h.previous, 40*time.Millisecond)
	h.mu.Lock()
	h.responseDelay = 100 * time.Millisecond
	h.mu.Unlock()
	if _, err := c.Renew(context.Background(), h.previous); err == nil {
		t.Fatal("expected request timeout")
	}
	if !c.HasPendingRenewal() {
		t.Fatal("timeout discarded renewal")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("timeout request was not durable")
	}
}

func TestGrantLifecycleKnownRejectionAndPersistentPacing(t *testing.T) {
	for _, status := range []int{403, 408, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			h := newGrantLifecycleHarness(t)
			path := filepath.Join(t.TempDir(), "pending.json")
			c := h.client(t, path, h.subject, h.previous, time.Second)
			h.mu.Lock()
			h.responseStatus = status
			h.mu.Unlock()
			_, err := c.Renew(context.Background(), h.previous)
			var httpErr *GrantLifecycleHTTPError
			if !errors.As(err, &httpErr) || httpErr.StatusCode != status {
				t.Fatalf("status error %v", err)
			}
			if c.HasPendingRenewal() != (status != 403) {
				t.Fatal("incorrect outcome retirement")
			}
			if status == 429 {
				if httpErr.RetryAfter() != 2*time.Second {
					t.Fatal("missing pacing")
				}
				restarted := h.client(t, path, h.subject, h.previous, time.Second)
				before := h.capCalls.Load() + h.postCalls.Load()
				if _, err := restarted.Renew(context.Background(), h.previous); !errors.As(err, &httpErr) || httpErr.RetryAfter() <= 0 {
					t.Fatal("restart lost pacing")
				}
				if after := h.capCalls.Load() + h.postCalls.Load(); after != before {
					t.Fatal("pacing sent another HTTP request")
				}
			}
		})
	}
	if delay := boundedLifecycleRetryAfter("999999999", time.Now()); delay != grantLifecycleMaxRetryAfter {
		t.Fatalf("unbounded Retry-After %v", delay)
	}
}

func TestGrantLifecycleCurrentPossessionAndRollbackFence(t *testing.T) {
	h := newGrantLifecycleHarness(t)
	c := h.client(t, filepath.Join(t.TempDir(), "pending.json"), h.audience, h.previous, time.Second)
	current, err := c.Current(context.Background())
	if err != nil || current.GrantID != h.previous.GrantID {
		t.Fatalf("same current Grant: %v", err)
	}
	h.mu.Lock()
	h.current = h.renewed
	h.mu.Unlock()
	current, err = c.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AcceptGrant(current); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.current = h.previous
	h.mu.Unlock()
	if _, err := c.Current(context.Background()); err == nil {
		t.Fatal("current Grant rolled back after caller saved renewal")
	}
	if _, err := c.Renew(context.Background(), h.previous); err == nil {
		t.Fatal("audience could renew subject's Grant")
	}
}

func TestGrantLifecycleExpiredSignedSeedCanRenew(t *testing.T) {
	h := newGrantLifecycleHarness(t)
	previous := cloneLifecycleGrant(h.previous)
	previous.NotBefore = time.Now().UTC().Add(-61 * time.Minute)
	previous.ExpiresAt = previous.NotBefore.Add(time.Hour)
	previous, err := trust.SignGrant(h.provider, h.issuer, previous)
	if err != nil {
		t.Fatal(err)
	}
	c := h.client(t, filepath.Join(t.TempDir(), "pending.json"), h.subject, previous, time.Second)
	if _, err := c.Renew(context.Background(), previous); err != nil {
		t.Fatalf("expired signed snapshot should recover: %v", err)
	}
}

func TestVerifyGrantRenewalRejectsAuthorizationChanges(t *testing.T) {
	h := newGrantLifecycleHarness(t)
	tests := map[string]func(*trust.Grant){
		"permission widened": func(g *trust.Grant) { g.Permissions = append(g.Permissions, "filesystem") },
		"permission reduced": func(g *trust.Grant) { g.Permissions = nil },
		"relay widened":      func(g *trust.Grant) { g.RelayConstraints = nil },
		"relay changed":      func(g *trust.Grant) { g.RelayConstraints = []string{"other-relay"} },
		"subject changed":    func(g *trust.Grant) { g.SubjectDeviceID = "other" },
		"audience changed":   func(g *trust.Grant) { g.Audience = "other" },
		"key changed":        func(g *trust.Grant) { g.ConfirmationThumbprint = "other" },
		"epoch rollback":     func(g *trust.Grant) { g.RevocationEpoch = 3 },
		"TTL enlarged":       func(g *trust.Grant) { g.ExpiresAt = g.NotBefore.Add(2 * time.Hour) },
		"TTL enlarged 1ns":   func(g *trust.Grant) { g.ExpiresAt = g.NotBefore.Add(time.Hour + time.Nanosecond) },
		"expiry unchanged":   func(g *trust.Grant) { g.ExpiresAt = h.previous.ExpiresAt },
		"expired result":     func(g *trust.Grant) { g.ExpiresAt = time.Now().UTC().Add(-time.Second) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			grant := cloneLifecycleGrant(h.renewed)
			mutate(&grant)
			grant, err := trust.SignGrant(h.provider, h.issuer, grant)
			if err != nil {
				t.Fatal(err)
			}
			if VerifyGrantRenewal(h.provider, grant, h.previous, h.issuer.Identity, "relay-test", time.Now().UTC()) == nil {
				t.Fatal("authorization change accepted")
			}
		})
	}
	for _, change := range []string{"issuer", "KID", "algorithm", "signature"} {
		t.Run(change, func(t *testing.T) {
			grant := cloneLifecycleGrant(h.renewed)
			switch change {
			case "issuer":
				grant.Issuer = "other"
			case "KID":
				grant.Signature.KID = "other"
			case "algorithm":
				grant.Signature.Alg = "other"
			case "signature":
				grant.Signature.Value = iscpcrypto.Base64URL(make([]byte, 64))
			}
			if VerifyGrantRenewal(h.provider, grant, h.previous, h.issuer.Identity, "relay-test", time.Now().UTC()) == nil {
				t.Fatal("bad signer accepted")
			}
		})
	}
	if VerifyGrantRenewal(h.provider, h.renewed, h.previous, h.audience.Identity, "relay-test", time.Now().UTC()) == nil {
		t.Fatal("wrong issuer public key accepted")
	}
	if window := GrantRenewalWindow(h.previous); window != 12*time.Minute {
		t.Fatalf("TTL/5 window %v", window)
	}
	long := h.previous
	long.ExpiresAt = long.NotBefore.Add(7 * 24 * time.Hour)
	if GrantRenewalWindow(long) != 24*time.Hour {
		t.Fatal("24h window cap missing")
	}
	sameExpiry := cloneLifecycleGrant(h.previous)
	sameExpiry.GrantID = "different-grant"
	sameExpiry, err := trust.SignGrant(h.provider, h.issuer, sameExpiry)
	if err != nil {
		t.Fatal(err)
	}
	if verifyGrantContinuity(h.provider, sameExpiry, h.previous, h.issuer.Identity, "relay-test", time.Now().UTC(), false) == nil {
		t.Fatal("different current Grant without lifetime extension accepted")
	}
}

func TestGrantLifecycleRejectsForgedExpiredOrMismatchedCapability(t *testing.T) {
	tests := map[string]func(*descriptor.TrustRootDescriptor){
		"expired":    func(d *descriptor.TrustRootDescriptor) { d.ExpiresAt = time.Now().UTC().Add(-time.Second) },
		"too long":   func(d *descriptor.TrustRootDescriptor) { d.ExpiresAt = d.IssuedAt.Add(6 * time.Minute) },
		"disabled":   func(d *descriptor.TrustRootDescriptor) { d.Metadata["grant_renewal"] = "false" },
		"purpose":    func(d *descriptor.TrustRootDescriptor) { d.Metadata["purpose"] = "other" },
		"relay":      func(d *descriptor.TrustRootDescriptor) { d.Metadata["relay_id"] = "other" },
		"subject":    func(d *descriptor.TrustRootDescriptor) { d.Metadata["subject_device_id"] = "other" },
		"audience":   func(d *descriptor.TrustRootDescriptor) { d.Metadata["audience_device_id"] = "other" },
		"permission": func(d *descriptor.TrustRootDescriptor) { d.Metadata["permission"] = "filesystem" },
		"issuer":     func(d *descriptor.TrustRootDescriptor) { d.TrustRootID = "other" },
		"pinned key": func(d *descriptor.TrustRootDescriptor) { d.Keys[0].Public = iscpcrypto.Base64URL(make([]byte, 32)) },
		"authorization expired": func(d *descriptor.TrustRootDescriptor) {
			d.Metadata["authorization_expires_at"] = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			h := newGrantLifecycleHarness(t)
			c := h.client(t, filepath.Join(t.TempDir(), "pending.json"), h.subject, h.previous, time.Second)
			h.mu.Lock()
			h.capChange = change
			h.mu.Unlock()
			if _, err := c.Renew(context.Background(), h.previous); err == nil {
				t.Fatal("bad capability accepted")
			}
			if _, err := c.Current(context.Background()); err == nil {
				t.Fatal("current ignored bad capability")
			}
			if h.postCalls.Load() != 0 || c.HasPendingRenewal() {
				t.Fatal("bad capability triggered possession operation")
			}
		})
	}
	t.Run("forgery", func(t *testing.T) {
		h := newGrantLifecycleHarness(t)
		c := h.client(t, filepath.Join(t.TempDir(), "pending.json"), h.subject, h.previous, time.Second)
		h.mu.Lock()
		h.forgeCapability = true
		h.mu.Unlock()
		if _, err := c.Renew(context.Background(), h.previous); err == nil || h.postCalls.Load() != 0 {
			t.Fatal("forged capability reached renewal")
		}
	})
}

func TestGrantLifecycleLocalURLAndPrivatePending(t *testing.T) {
	for _, url := range []string{"http://127.0.0.1:8080", "http://[::1]:8080", "http://localhost", "http://iscp-local-issuer:8080", "https://issuer.example"} {
		if err := ValidateGrantLifecycleURL(url); err != nil {
			t.Fatalf("valid URL %s: %v", url, err)
		}
	}
	for _, url := range []string{"http://192.168.1.1", "http://iscp-local-issuer.evil", "http://evil.example", "http://user:secret@127.0.0.1", "https://issuer.example/api", "http://127.0.0.1?token=secret", "http://127.0.0.1#secret", "file:///tmp/issuer", "http://127.0.0.1:99999"} {
		if ValidateGrantLifecycleURL(url) == nil {
			t.Fatalf("unsafe URL accepted: %s", url)
		}
	}
	h := newGrantLifecycleHarness(t)
	path := filepath.Join(t.TempDir(), "pending.json")
	if err := os.WriteFile(path, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGrantLifecycleClient(h.server.URL, path, h.subject, h.issuer.Identity, "relay-test", h.previous, time.Second); err == nil {
		t.Fatal("publicly readable pending accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGrantLifecycleClient(h.server.URL, path, h.subject, h.issuer.Identity, "relay-test", h.previous, time.Second); err == nil {
		t.Fatal("symlink pending accepted")
	}
}

func TestGrantLifecycleRedirectAndAuthorizationLimit(t *testing.T) {
	h := newGrantLifecycleHarness(t)
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); w.WriteHeader(200) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	c, err := NewGrantLifecycleClient(source.URL, filepath.Join(t.TempDir(), "pending.json"), h.subject, h.issuer.Identity, "relay-test", h.previous, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.http.CloseIdleConnections()
	if _, err := c.Current(context.Background()); err == nil || redirected.Load() != 0 {
		t.Fatal("issuer redirect was followed")
	}
	c = h.client(t, filepath.Join(t.TempDir(), "pending.json"), h.subject, h.previous, time.Second)
	h.mu.Lock()
	h.capChange = func(cap *descriptor.TrustRootDescriptor) {
		cap.Metadata["authorization_expires_at"] = time.Now().UTC().Add(20 * time.Minute).Format(time.RFC3339Nano)
	}
	h.mu.Unlock()
	if _, err := c.Renew(context.Background(), h.previous); err == nil {
		t.Fatal("Grant exceeded authorization expiry")
	}
	if !c.HasPendingRenewal() {
		t.Fatal("invalid successful response lost its dedupe request")
	}
	if err := c.CommitRenewal(); err == nil {
		t.Fatal("unverified response was committed")
	}
}
