package iscplocalissuer

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

type renewalFixture struct {
	i                 *Issuer
	dir               string
	subject, audience identity.Device
	clock             atomic.Int64
	grant             trust.Grant
}

func newRenewalFixture(t *testing.T, ttl time.Duration, authorize bool) *renewalFixture {
	t.Helper()
	f := &renewalFixture{dir: filepath.Join(t.TempDir(), "issuer")}
	f.clock.Store(time.Now().UTC().Truncate(time.Second).UnixNano())
	provider := iscpcrypto.NewProvider()
	var err error
	f.subject, err = identity.NewDevice(provider, "renewal-domain", "desktop", f.now())
	if err != nil {
		t.Fatal(err)
	}
	f.audience, err = identity.NewDevice(provider, "renewal-domain", "gateway", f.now())
	if err != nil {
		t.Fatal(err)
	}
	for name, dev := range map[string]identity.Device{"subject": f.subject, "audience": f.audience} {
		raw, _ := json.Marshal(dev.Identity)
		if err = os.WriteFile(filepath.Join(filepath.Dir(f.dir), name+".json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = Initialize(f.dir, filepath.Join(filepath.Dir(f.dir), "subject.json"), filepath.Join(filepath.Dir(f.dir), "audience.json"), "local-relay"); err != nil {
		t.Fatal(err)
	}
	f.i = f.load(t)
	f.grant, err = f.i.Sign(ttl)
	if err != nil {
		t.Fatal(err)
	}
	if authorize {
		f.authorize(t, f.i, f.grant)
	}
	return f
}
func (f *renewalFixture) now() time.Time { return time.Unix(0, f.clock.Load()).UTC() }
func (f *renewalFixture) load(t *testing.T) *Issuer {
	t.Helper()
	i, err := Load(filepath.Join(f.dir, "issuer.json"))
	if err != nil {
		t.Fatal(err)
	}
	i.Now = f.now
	return i
}
func (f *renewalFixture) authorize(t *testing.T, i *Issuer, grant trust.Grant) {
	t.Helper()
	raw, _ := json.Marshal(grant)
	path := filepath.Join(f.dir, "authorization-grant.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := i.AuthorizeRenewal(path, 24); err != nil {
		t.Fatal(err)
	}
}
func (f *renewalFixture) body(t *testing.T, dev identity.Device, key, nonce string) []byte {
	t.Helper()
	proof, err := dev.CreateProof(iscpcrypto.NewProvider(), "local-relay", key, nonce, f.now())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(RenewalRequest{Identity: dev.Identity, IdentityProof: proof})
	return raw
}
func grantRequest(i *Issuer, path, key string, raw []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	i.Handler().ServeHTTP(w, r)
	return w
}
func requireReason(t *testing.T, w *httptest.ResponseRecorder, status int, reason string) {
	t.Helper()
	var result struct{ Type, Reason string }
	if w.Code != status || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Type != "iscp.error.v2" || result.Reason != reason {
		t.Fatalf("status/reason: got %d %s; want %d %s", w.Code, w.Body.String(), status, reason)
	}
}
func responseGrant(t *testing.T, w *httptest.ResponseRecorder, status int) trust.Grant {
	t.Helper()
	var value GrantResponse
	if w.Code != status || decode(w.Body.Bytes(), &value) != nil || value.Data.Status != "active" || value.Data.GrantID != value.Grant.GrantID {
		t.Fatalf("invalid grant response status %d", w.Code)
	}
	return value.Grant
}

func TestRenewalCapabilityIsSignedBoundedAndRequiresAuthorization(t *testing.T) {
	f := newRenewalFixture(t, 30*time.Minute, false)
	get := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		f.i.Handler().ServeHTTP(w, httptest.NewRequest("GET", RenewalCapabilityPath, nil))
		return w
	}
	requireReason(t, get(), 404, "renewal_authorization_not_found")
	f.authorize(t, f.i, f.grant)
	w := get()
	var signed descriptor.SignedDescriptor
	if w.Code != 200 || decode(w.Body.Bytes(), &signed) != nil {
		t.Fatal("missing signed capability")
	}
	if err := descriptor.Verify(iscpcrypto.NewProvider(), signed, f.i.device.Identity, config.DefaultGate(config.ProfileProduction), f.now()); err != nil {
		t.Fatal(err)
	}
	var body descriptor.TrustRootDescriptor
	if decode(signed.Descriptor, &body) != nil || signed.DescriptorType != trustRootDescriptorType || body.Type != trustRootDescriptorType || body.TrustRootID != f.i.device.Identity.DeviceID || body.DomainID != f.subject.Identity.DomainID || body.ExpiresAt.Sub(f.now()) != 5*time.Minute || body.Metadata["grant_renewal"] != "true" || body.Metadata["relay_id"] != "local-relay" || body.Metadata["permission"] != Permission || len(body.Keys) != 1 || body.Keys[0].Use != "descriptor-signature" {
		t.Fatal("capability scope/lifetime changed")
	}
	f.clock.Add(int64(24*time.Hour - time.Minute))
	w = get()
	_ = decode(w.Body.Bytes(), &signed)
	_ = decode(signed.Descriptor, &body)
	if body.ExpiresAt.Sub(f.now()) != time.Minute {
		t.Fatal("capability outlives authorization")
	}
	f.clock.Add(int64(time.Minute))
	requireReason(t, get(), 410, "renewal_authorization_expired")
}

func TestAutoRenewalKeepsScopeAndRecoversExactUnknownOutcomeAfterRestart(t *testing.T) {
	f := newRenewalFixture(t, 30*time.Minute, true)
	early := grantRequest(f.i, AutoRenewPath, "early", f.body(t, f.subject, "early", "early-nonce"))
	requireReason(t, early, 429, "renewal_not_yet_eligible")
	if early.Header().Get("Retry-After") != "1440" {
		t.Fatal("wrong eligibility retry interval")
	}
	f.clock.Add(int64(24 * time.Minute))
	raw := f.body(t, f.subject, "attempt", "renew-nonce")
	w := grantRequest(f.i, AutoRenewPath, "attempt", raw)
	grant := responseGrant(t, w, 201)
	if grant.GrantID == f.grant.GrantID || grant.ExpiresAt.Sub(grant.NotBefore) != 30*time.Minute {
		t.Fatal("grant was not renewed at original TTL")
	}
	if _, err := f.i.validateGrant(grant); err != nil {
		t.Fatal(err)
	}
	originalResponse := append([]byte(nil), w.Body.Bytes()...)
	f.clock.Add(int64(6 * time.Minute)) // Original PoP is now stale.
	restarted := f.load(t)
	retry := grantRequest(restarted, AutoRenewPath, "attempt", raw)
	if retry.Code != 201 || !bytes.Equal(retry.Body.Bytes(), originalResponse) {
		t.Fatal("unknown outcome changed after issuer restart/proof expiry")
	}
	requireReason(t, grantRequest(restarted, AutoRenewPath, "attempt", append(raw, ' ')), 409, "renewal_identity_conflict")
	for index, dev := range []identity.Device{f.subject, f.audience} {
		key := "current-" + strconv.Itoa(index)
		current := responseGrant(t, grantRequest(restarted, CurrentGrantPath, key, f.body(t, dev, key, key)), 200)
		if current.GrantID != grant.GrantID {
			t.Fatal("peers see different current grants")
		}
	}
	journal, err := os.ReadFile(filepath.Join(f.dir, "issuance.jsonl"))
	if err != nil || bytes.Count(journal, []byte("\n")) != 2 || bytes.Contains(journal, []byte(grant.Signature.Value)) || bytes.Contains(journal, []byte(f.i.token)) {
		t.Fatal("duplicate issuance or journal secret")
	}
	if err = restarted.RevokeRenewal(); err != nil {
		t.Fatal(err)
	}
	requireReason(t, grantRequest(f.i, AutoRenewPath, "attempt", raw), 403, "renewal_authorization_revoked")
	requireReason(t, grantRequest(f.i, CurrentGrantPath, "fresh", f.body(t, f.audience, "fresh", "fresh")), 403, "renewal_authorization_revoked")
}

func TestDeviceProofRejectsWrongIdentityKeyChallengeAndPersistentReplay(t *testing.T) {
	f := newRenewalFixture(t, time.Minute, true)
	good := f.body(t, f.subject, "one", "shared-nonce")
	responseGrant(t, grantRequest(f.i, CurrentGrantPath, "one", good), 200)
	restarted := f.load(t)
	requireReason(t, grantRequest(restarted, CurrentGrantPath, "two", f.body(t, f.subject, "two", "shared-nonce")), 409, "proof_replay_detected")
	responseGrant(t, grantRequest(restarted, CurrentGrantPath, "audience", f.body(t, f.audience, "audience", "shared-nonce")), 200)
	requireReason(t, grantRequest(restarted, AutoRenewPath, "aud-renew", f.body(t, f.audience, "aud-renew", "aud-renew")), 401, "device_proof_invalid")
	other, _ := identity.NewDevice(iscpcrypto.NewProvider(), f.subject.Identity.DomainID, "unknown", f.now())
	requireReason(t, grantRequest(restarted, CurrentGrantPath, "unknown", f.body(t, other, "unknown", "unknown")), 401, "device_proof_invalid")
	other.Identity.DeviceID = f.subject.Identity.DeviceID
	requireReason(t, grantRequest(restarted, CurrentGrantPath, "new-key", f.body(t, other, "new-key", "new-key")), 409, "renewal_identity_conflict")
	for _, mutation := range []func(*RenewalRequest){
		func(r *RenewalRequest) { r.IdentityProof.Audience = "other-relay" },
		func(r *RenewalRequest) { r.IdentityProof.Challenge = "other-key" },
		func(r *RenewalRequest) { r.IdentityProof.Signature.Value = strings.Repeat("a", 86) },
		func(r *RenewalRequest) { r.IdentityProof.Nonce = "" },
		func(r *RenewalRequest) { r.IdentityProof.Signature.Alg = "none" },
	} {
		var input RenewalRequest
		_ = decode(f.body(t, f.subject, "bad", "bad"), &input)
		mutation(&input)
		raw, _ := json.Marshal(input)
		requireReason(t, grantRequest(restarted, CurrentGrantPath, "bad", raw), 401, "device_proof_invalid")
	}
	requireReason(t, grantRequest(restarted, CurrentGrantPath, "", good), 400, "idempotency_key_required")
	requireReason(t, grantRequest(restarted, CurrentGrantPath, "oversize", bytes.Repeat([]byte("x"), 16385)), 400, "invalid_request")
	f.clock.Add(int64(6 * time.Minute))
	requireReason(t, grantRequest(restarted, CurrentGrantPath, "stale", good), 401, "device_proof_invalid")
}

func TestAuthorizationExpiryCannotBeBypassedByCachedSuccess(t *testing.T) {
	f := newRenewalFixture(t, time.Minute, true)
	raw := f.body(t, f.subject, "key", "nonce")
	responseGrant(t, grantRequest(f.i, CurrentGrantPath, "key", raw), 200)
	f.clock.Add(int64(24 * time.Hour))
	requireReason(t, grantRequest(f.load(t), CurrentGrantPath, "key", raw), 410, "renewal_authorization_expired")
}

func TestEarlyRenewalExactRetrySucceedsWithoutNonceReplay(t *testing.T) {
	f := newRenewalFixture(t, 10*time.Second, true)
	raw := f.body(t, f.subject, "early", "early-nonce")
	requireReason(t, grantRequest(f.i, AutoRenewPath, "early", raw), 429, "renewal_not_yet_eligible")
	f.clock.Add(int64(8 * time.Second))
	responseGrant(t, grantRequest(f.load(t), AutoRenewPath, "early", raw), 201)
}

func TestRenewalTailGrantEndsAtAbsoluteAuthorizationDeadline(t *testing.T) {
	f := newRenewalFixture(t, 30*time.Minute, true)
	deadline := f.now().Add(24 * time.Hour)
	f.clock.Add(int64(24*time.Hour - 10*time.Second))
	raw := f.body(t, f.subject, "tail", "tail")
	grant := responseGrant(t, grantRequest(f.i, AutoRenewPath, "tail", raw), 201)
	if grant.ExpiresAt.After(deadline) || grant.ExpiresAt.Sub(grant.NotBefore) != 10*time.Second {
		t.Fatal("tail grant outlives authorization or keeps full TTL")
	}
	if _, err := f.i.validateGrant(grant); err != nil {
		t.Fatal(err)
	}
	state, err := f.load(t).readRenewalState()
	if err != nil || state.TTLSeconds != 1800 {
		t.Fatal("tail grant changed the original TTL policy")
	}
	current := responseGrant(t, grantRequest(f.i, CurrentGrantPath, "read-tail", f.body(t, f.audience, "read-tail", "read-tail")), 200)
	if current.GrantID != grant.GrantID {
		t.Fatal("audience did not receive tail grant")
	}
	if signed, err := f.i.readCapability(); err != nil {
		t.Fatal(err)
	} else {
		var capability descriptor.TrustRootDescriptor
		_ = decode(signed.Descriptor, &capability)
		if capability.ExpiresAt.After(deadline) {
			t.Fatal("tail capability exceeds authorization")
		}
	}
	f.clock.Add(int64(7 * time.Second))
	early := grantRequest(f.i, AutoRenewPath, "another", f.body(t, f.subject, "another", "another"))
	requireReason(t, early, 429, "renewal_not_yet_eligible")
	if early.Header().Get("Retry-After") != "1" {
		t.Fatal("tail eligibility did not use shortened TTL")
	}
	f.clock.Add(int64(time.Second))
	finalAttempt := f.body(t, f.subject, "final", "final")
	blocked := grantRequest(f.i, AutoRenewPath, "final", finalAttempt)
	requireReason(t, blocked, 429, "renewal_not_yet_eligible")
	if blocked.Header().Get("Retry-After") != "2" {
		t.Fatal("nonextending grant must wait until absolute deadline")
	}
	f.clock.Add(int64(2 * time.Second))
	requireReason(t, grantRequest(f.i, AutoRenewPath, "final", finalAttempt), 410, "renewal_authorization_expired")
}

func TestCapabilityDiscoveryDoesNotCreatePersistentFiles(t *testing.T) {
	i, dir := fixture(t)
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	i.Handler().ServeHTTP(w, httptest.NewRequest("GET", RenewalCapabilityPath, nil))
	requireReason(t, w, 404, "renewal_authorization_not_found")
	after, err := os.ReadDir(dir)
	if err != nil || len(after) != len(before) {
		t.Fatal("GET changed issuer storage")
	}
}

func TestFreshnessVerificationUsesSignedTimeAndStoredSubjectKey(t *testing.T) {
	f := newRenewalFixture(t, time.Minute, true)
	past := f.body(t, f.subject, "old-proof", "old-proof")
	f.clock.Add(int64(6 * time.Minute))
	requireReason(t, grantRequest(f.i, CurrentGrantPath, "old-proof", past), 401, "device_proof_invalid")
	f.clock.Add(int64(6 * time.Minute))
	future := f.body(t, f.subject, "future-proof", "future-proof")
	f.clock.Add(-int64(6 * time.Minute))
	requireReason(t, grantRequest(f.i, CurrentGrantPath, "future-proof", future), 401, "device_proof_invalid")
	changed, _ := identity.NewDevice(iscpcrypto.NewProvider(), f.subject.Identity.DomainID, f.subject.Identity.DeviceID, f.now())
	raw, _ := json.Marshal(changed.Identity)
	if err := os.WriteFile(filepath.Join(filepath.Dir(f.dir), "subject.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(f.dir, "issuer.json")); err == nil {
		t.Fatal("stored subject key replacement accepted")
	}
}

func TestCurrentCacheExpiresWithoutDiscardingRenewalRecovery(t *testing.T) {
	f := newRenewalFixture(t, time.Minute, true)
	currentRaw := f.body(t, f.audience, "current", "current")
	responseGrant(t, grantRequest(f.i, CurrentGrantPath, "current", currentRaw), 200)
	f.clock.Add(int64(48 * time.Second))
	renewRaw := f.body(t, f.subject, "renew", "renew")
	renewed := grantRequest(f.i, AutoRenewPath, "renew", renewRaw)
	responseGrant(t, renewed, 201)
	f.clock.Add(int64(6 * time.Minute))
	restarted := f.load(t)
	requireReason(t, grantRequest(restarted, CurrentGrantPath, "current", currentRaw), 401, "device_proof_invalid")
	newCurrent := responseGrant(t, grantRequest(restarted, CurrentGrantPath, "fresh", f.body(t, f.audience, "fresh", "fresh")), 200)
	if newCurrent.GrantID == f.grant.GrantID {
		t.Fatal("fresh current read returned original grant")
	}
	recovered := grantRequest(restarted, AutoRenewPath, "renew", renewRaw)
	if recovered.Code != 201 || !bytes.Equal(recovered.Body.Bytes(), renewed.Body.Bytes()) {
		t.Fatal("current pruning discarded renewal response")
	}
	state, err := restarted.readRenewalState()
	if err != nil || len(state.Idempotency) != 2 {
		t.Fatal("expired current read cache retained")
	}
}

func TestRenewalConcurrentInstancesPersistOneSuccessfulIssuance(t *testing.T) {
	f := newRenewalFixture(t, 10*time.Second, true)
	f.clock.Add(int64(8 * time.Second))
	second := f.load(t)
	raw := f.body(t, f.subject, "attempt", "nonce")
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 16)
	for index := 0; index < 16; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			issuer := f.i
			if index%2 == 1 {
				issuer = second
			}
			results <- grantRequest(issuer, AutoRenewPath, "attempt", raw)
		}(index)
	}
	wg.Wait()
	close(results)
	var first []byte
	for w := range results {
		responseGrant(t, w, 201)
		if first == nil {
			first = w.Body.Bytes()
		} else if !bytes.Equal(first, w.Body.Bytes()) {
			t.Fatal("concurrent retry minted different grants")
		}
	}
	journal, _ := os.ReadFile(filepath.Join(f.dir, "issuance.jsonl"))
	if bytes.Count(journal, []byte("\n")) != 2 {
		t.Fatal("concurrent requests issued more than once")
	}
}

func TestRenewalStateAndExplicitAuthorizationFailClosed(t *testing.T) {
	f := newRenewalFixture(t, time.Minute, false)
	raw, _ := json.Marshal(f.grant)
	file := filepath.Join(f.dir, "grant.json")
	_ = os.WriteFile(file, raw, 0o600)
	for _, hours := range []int{0, 23, 8761} {
		if f.i.AuthorizeRenewal(file, hours) == nil {
			t.Fatal("invalid authorization lifetime accepted")
		}
	}
	for _, mutate := range []func(*trust.Grant){
		func(g *trust.Grant) { g.Audience = "another" }, func(g *trust.Grant) { g.RelayConstraints = nil },
		func(g *trust.Grant) { g.Permissions = append(g.Permissions, "arbitrary") }, func(g *trust.Grant) { g.ExpiresAt = g.NotBefore.Add(time.Hour) },
	} {
		bad := f.grant
		mutate(&bad)
		raw, _ := json.Marshal(bad)
		_ = os.WriteFile(file, raw, 0o600)
		if f.i.AuthorizeRenewal(file, 24) == nil {
			t.Fatal("changed authorization grant accepted")
		}
	}
	f.authorize(t, f.i, f.grant)
	if _, err := f.i.Sign(2 * time.Minute); err == nil {
		t.Fatal("management changed authorized TTL")
	}
	statePath := filepath.Join(f.dir, RenewalStateFile)
	if err := os.Rename(statePath, statePath+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(statePath+".saved", statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(f.dir, "issuer.json")); err == nil {
		t.Fatal("symlink renewal state accepted")
	}
	_ = os.Remove(statePath)
	fileHandle, err := os.OpenFile(statePath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = fileHandle.Truncate(maxRenewalStateBytes + 1)
	_ = fileHandle.Close()
	if _, err := Load(filepath.Join(f.dir, "issuer.json")); err == nil {
		t.Fatal("unbounded state accepted")
	}
}
