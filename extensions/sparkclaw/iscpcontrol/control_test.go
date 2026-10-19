package iscpcontrol

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
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
