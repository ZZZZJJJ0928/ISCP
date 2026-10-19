package iscpcontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func fixture(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	b, e := os.ReadFile("../../../conformance/fixtures/operation-recovery.v2.json")
	if e != nil {
		t.Fatal(e)
	}
	var f map[string]json.RawMessage
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	return f
}
func TestFrozenProductionCodec(t *testing.T) {
	f := fixture(t)
	var intent Intent
	if e := Decode(f["intent"], "intent", &intent); e != nil {
		t.Fatal(e)
	}
	if e := intent.Validate(); e != nil {
		t.Fatal(e)
	}
	d, e := Digest("ISCP-OPERATION-INTENT-V2\x00", intent)
	var want string
	_ = json.Unmarshal(f["semantic_digest"], &want)
	if e != nil || d != want {
		t.Fatalf("semantic digest %s: %v", d, e)
	}
	var request Request
	if e = Decode(f["request"], "request_recover", &request); e != nil {
		t.Fatal(e)
	}
	if e = request.Validate(); e != nil {
		t.Fatal(e)
	}
	ctx, e := authContext(request, "POST", OperationPath+"recover", "issuer-test", "")
	if e != nil {
		t.Fatal(e)
	}
	b, _ := canonicalBytes(ctx)
	var expected string
	_ = json.Unmarshal(f["authentication_context_canonical"], &expected)
	if string(b) != expected {
		t.Fatalf("context differs: %s", b)
	}
	var keys map[string]string
	_ = json.Unmarshal(f["test_keys"], &keys)
	pub, _ := base64.RawURLEncoding.DecodeString(keys["device_public_key"])
	sig, _ := base64.RawURLEncoding.DecodeString(request.Authentication.Signature.Value)
	input := append([]byte("ISCP-V2-SIGNATURE\x00iscp.control.authentication.v2\x00"), b...)
	if !ed25519.Verify(pub, input, sig) {
		t.Fatal("cross-language proof failed")
	}
	var mutations []struct {
		Name string `json:"name"`
		Raw  string `json:"raw"`
		Hex  string `json:"raw_hex"`
	}
	_ = json.Unmarshal(f["negative_raw"], &mutations)
	for _, v := range mutations {
		if v.Raw != "" {
			var out any
			if Decode([]byte(v.Raw), "intent", &out) == nil {
				t.Errorf("accepted %s", v.Name)
			}
		}
	}
	var result Result
	if e = Decode(f["result"], "result", &result); e != nil {
		t.Fatal(e)
	}
	var disposition Disposition
	if e = Decode(f["disposition"], "disposition_receipt", &disposition); e != nil {
		t.Fatal(e)
	}
}

type testBackend struct {
	actor      identity.DeviceIdentity
	signer     identity.Device
	mu         sync.Mutex
	result     *Result
	executions int
	fail       error
}

func (b *testBackend) ResolveActor(_ context.Context, domain, device string) (identity.DeviceIdentity, error) {
	if domain != b.actor.DomainID || device != b.actor.DeviceID {
		return identity.DeviceIdentity{}, ErrAuthentication
	}
	return b.actor, nil
}
func (b *testBackend) Execute(_ context.Context, r Request, _ identity.DeviceIdentity, token string) (Outcome, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if token != "" {
		return Outcome{}, &Failure{Code: "authentication_failed"}
	}
	if b.fail != nil {
		return Outcome{}, b.fail
	}
	if b.result == nil {
		b.executions++
		v, e := NewResult(ResultPayload{Key: r.Key, SemanticDigest: r.SemanticDigest, ResultVersion: "1", State: "failed", CompletedAt: time.Now().UTC().Truncate(time.Second), CredentialGeneration: "9", Body: ResultBody{Code: "generation_conflict"}}, b.signer)
		if e != nil {
			return Outcome{}, e
		}
		b.result = &v
	}
	return Outcome{Result: b.result}, nil
}
func TestHTTPSFreshAttemptsRecoverSameResultWithoutSocket(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	device, _ := identity.NewDevice(c.NewProvider(), "domain-test", "device-test", now)
	signer, _ := identity.NewDevice(c.NewProvider(), "domain-test", "issuer-test", now)
	backend := &testBackend{actor: device.Identity, signer: signer}
	h := NewHandler("issuer-test", signer, backend)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client, e := NewClient(server.URL, "issuer-test", device, signer.Identity, server.Client())
	if e != nil {
		t.Fatal(e)
	}
	var intent Intent
	if e = Decode(fixture(t)["intent"], "intent", &intent); e != nil {
		t.Fatal(e)
	}
	digest, _ := Digest("ISCP-OPERATION-INTENT-V2\x00", intent)
	request := Request{Action: "recover", Key: Key{device.Identity.DomainID, device.Identity.DeviceID, intent.Namespace, intent.OperationID}, SemanticDigest: digest, Intent: &intent}
	first, e := client.Attempt(context.Background(), request, "")
	if e != nil {
		t.Fatal(e)
	}
	second, e := client.Attempt(context.Background(), request, "")
	if e != nil {
		t.Fatal(e)
	}
	if first.Result.ResultDigest != second.Result.ResultDigest || backend.executions != 1 {
		t.Fatal("stable operation was replaced")
	}
	if _, e = client.Attempt(context.Background(), request, "expired-token"); e == nil {
		t.Fatal("invalid token silently omitted")
	}
	backend.mu.Lock()
	rev := Counter("8")
	backend.fail = &Failure{Code: "authorization_revoked", Revision: &rev}
	backend.mu.Unlock()
	_, e = client.Attempt(context.Background(), request, "")
	var typed *Error
	if !errors.As(e, &typed) || typed.Code != "authorization_revoked" || typed.AuthorizationRevision == nil || *typed.AuthorizationRevision != "8" {
		t.Fatalf("signed revocation lost: %v", e)
	}
}
func TestAuthenticationBindsRealEndpointAndEveryAttempt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	device, _ := identity.NewDevice(c.NewProvider(), "domain-test", "device-test", now)
	var intent Intent
	_ = Decode(fixture(t)["intent"], "intent", &intent)
	digest, _ := Digest("ISCP-OPERATION-INTENT-V2\x00", intent)
	delivery, _, _ := NewDelivery()
	r := Request{Type: "iscp.operation.request.v2", Protocol: Protocol, Action: "recover", AttemptID: "attempt-1", Key: Key{device.Identity.DomainID, device.Identity.DeviceID, intent.Namespace, intent.OperationID}, SemanticDigest: digest, Intent: &intent, Delivery: &delivery}
	ch := Challenge{Type: "iscp.control.challenge.v2", Protocol: Protocol, Audience: "issuer-test", Purpose: "recover", ChallengeID: RandomID(), Challenge: RandomID(), ServerTime: now, ExpiresAt: now.Add(10 * time.Second)}
	if e := Authenticate(&r, ch, device, "", now); e != nil {
		t.Fatal(e)
	}
	if e := VerifyAuthentication(r, ch, device.Identity, "POST", OperationPath+"recover", "issuer-test", "", now); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Request){func(v *Request) { v.AttemptID = "attempt-2" }, func(v *Request) { v.Delivery = &Delivery{RandomID(), delivery.RecipientPublicKey} }, func(v *Request) { v.Action = "submit" }} {
		copy := clone(r)
		change(&copy)
		if VerifyAuthentication(copy, ch, device.Identity, "POST", OperationPath+"recover", "issuer-test", "", now) == nil {
			t.Fatal("modified request accepted")
		}
	}
	if VerifyAuthentication(r, ch, device.Identity, "POST", OperationPath+"submit", "issuer-test", "", now) == nil || VerifyAuthentication(r, ch, device.Identity, "POST", OperationPath+"recover", "other-issuer", "", now) == nil || VerifyAuthentication(r, ch, device.Identity, "POST", OperationPath+"recover", "issuer-test", "", now.Add(11*time.Second)) == nil {
		t.Fatal("endpoint/audience/expiry not bound")
	}
}

func TestHTTPChallengeIsOpaqueAndLimitsAreSymmetric(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	device, _ := identity.NewDevice(c.NewProvider(), "domain-test", "device-test", now)
	signer, _ := identity.NewDevice(c.NewProvider(), "domain-test", "issuer-test", now)
	backend := &testBackend{actor: device.Identity, signer: signer}
	h := NewHandler("issuer-test", signer, backend)
	for _, id := range []string{"device-test", "unknown-device"} {
		q := ChallengeRequest{Type: "iscp.control.challenge.request.v2", Protocol: Protocol, Audience: "issuer-test", DomainID: "domain-test", DeviceID: id, Purpose: "lookup"}
		raw, _ := json.Marshal(q)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", ChallengePath, bytes.NewReader(raw)))
		if rec.Code != 200 {
			t.Fatalf("challenge leaks actor existence %s %d", id, rec.Code)
		}
		var ch Challenge
		if Decode(rec.Body.Bytes(), "challenge", &ch) != nil {
			t.Fatal("invalid opaque challenge")
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", ChallengePath, bytes.NewReader(make([]byte, MaxBody+1))))
	if rec.Body.Len() > MaxBody || rec.Code != 400 {
		t.Fatalf("request bound %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.write(rec, strings.Repeat("x", MaxBody))
	if rec.Body.Len() > MaxBody || rec.Code != 503 {
		t.Fatalf("response bound %d", rec.Code)
	}
	for code, status := range map[string]int{"authentication_failed": 401, "scope_denied": 403, "generation_conflict": 409, "deadline_exceeded": 410, "authorization_unavailable": 503} {
		rec = httptest.NewRecorder()
		h.failure(rec, code, nil, nil)
		if rec.Code != status {
			t.Errorf("%s status %d", code, rec.Code)
		}
	}
}

func TestRealThumbprintKIDAllowsBase64urlPrefixes(t *testing.T) {
	found := map[byte]bool{}
	now := time.Now().UTC().Truncate(time.Second)
	for n := 0; n < 256 && len(found) < 2; n++ {
		seed := bytes.Repeat([]byte{byte(n)}, 32)
		ed := ed25519.NewKeyFromSeed(seed)
		pub := ed.Public().(ed25519.PublicKey)
		kid := c.Thumbprint("Ed25519", pub)
		if kid[0] != '-' && kid[0] != '_' || found[kid[0]] {
			continue
		}
		priv, e := c.Ed25519PrivateKeyFromBytes(ed)
		if e != nil {
			t.Fatal(e)
		}
		device := identity.Device{Identity: identity.DeviceIdentity{Type: identity.TypeDeviceIdentity, DomainID: "test", DeviceID: "issuer", PublicKey: identity.PublicKey{KTY: "Ed25519", Use: "identity-signature", KID: kid, Public: c.Base64URL(pub)}, CreatedAt: now}, Private: priv}
		errObject, e := NewError("invalid_request", "issuer", nil, nil, now, device)
		if e != nil {
			t.Fatalf("legitimate %c KID rejected: %v", kid[0], e)
		}
		if Verify(errObject.Type, errObject, errObject.Signature, device.Identity) != nil {
			t.Fatal("real signature invalid")
		}
		found[kid[0]] = true
		bad := *errObject
		bad.Signature.KID = "/invalid"
		if Validate(bad, "error") == nil {
			t.Fatal("nonidentifier KID accepted")
		}
	}
	if len(found) != 2 {
		t.Fatal("did not exercise both real KID prefixes")
	}
}

func TestChallengeRejectsUnrelatedSignedAuthorityTerminal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	device, _ := identity.NewDevice(c.NewProvider(), "domain-test", "device-test", now)
	signer, _ := identity.NewDevice(c.NewProvider(), "domain-test", "issuer-test", now)
	other := Request{AttemptID: "old-attempt", Key: Key{DomainID: "domain-test", DeviceID: "another-device", Namespace: CredentialNamespace, OperationID: "old-operation"}}
	rev := Counter("9")
	signed, e := NewError("authorization_revoked", "issuer-test", &other, &rev, now, signer)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_ = json.NewEncoder(w).Encode(signed)
	}))
	defer server.Close()
	client, e := NewClient(server.URL, "issuer-test", device, signer.Identity, server.Client())
	if e != nil {
		t.Fatal(e)
	}
	_, e = client.Attempt(context.Background(), Request{Action: "recover"}, "")
	if !errors.Is(e, ErrAuthentication) {
		t.Fatalf("old/other-subject terminal became current authority: %v", e)
	}
}
