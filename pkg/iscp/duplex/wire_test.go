package duplex

import (
	"encoding/json"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"os"
	"testing"
	"time"
)

func TestFrozenFramesAndAuthenticationBytes(t *testing.T) {
	b, e := os.ReadFile("../../../conformance/fixtures/relay.duplex.v1.vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Frames    []json.RawMessage `json:"frames"`
		Challenge string            `json:"proof_challenge"`
	}
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	for _, raw := range v.Frames {
		f, e := Decode(raw)
		if e != nil {
			t.Fatal(e)
		}
		enc, e := Encode(f)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = Decode(enc); e != nil {
			t.Fatal(e)
		}
	}
	ch, _ := Decode(v.Frames[0])
	got, e := AuthChallenge(ch, "authenticate", "1", "0", "test-token", identity.DeviceIdentity{DomainID: "domain-test", DeviceID: "device-test"})
	if e != nil || got != v.Challenge {
		t.Fatal(got, e)
	}
}
func TestProductionDecoderRejectsLossyInput(t *testing.T) {
	for _, s := range []string{`{"x":"\ud800"}`, "{\"x\":\"\xff\"}", `{}x`, `{"v":1,"v":1}`, `{"v":1e0}`} {
		if _, e := Decode([]byte(s)); e == nil {
			t.Fatal("accepted", s)
		}
	}
}
func TestAcceptanceSignatureAndOriginalBinding(t *testing.T) {
	p := crypto.NewProvider()
	now := time.Now().UTC().Truncate(time.Second)
	signer, e := identity.NewDevice(p, "domain", "relay", now)
	if e != nil {
		t.Fatal(e)
	}
	sub := Submission{MessageID: "message", EnvelopeDigest: RandomID(), HistoryID: RandomID(), NotAfter: Timestamp(now.Add(time.Minute))}
	r := Receipt{ReceiptID: crypto.Base64URL(crypto.RandomBytes(16)), RelayID: "relay", DomainID: "domain", HistoryID: sub.HistoryID, MessageID: sub.MessageID, SenderDeviceID: "sender", RecipientDeviceID: "recipient", EnvelopeDigest: sub.EnvelopeDigest, NotAfter: sub.NotAfter, AcceptedAt: Timestamp(now), ExpiresAt: sub.NotAfter}
	r, e = SignReceipt(p, signer, r)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyReceipt(r, signer.Identity, sub, "relay", "domain", "sender", "recipient"); e != nil {
		t.Fatal(e)
	}
	bad := r
	bad.MessageID = "other"
	if VerifyReceipt(bad, signer.Identity, sub, "relay", "domain", "sender", "recipient") == nil {
		t.Fatal("wrong message")
	}
	bad = r
	bad.ExpiresAt = Timestamp(now.Add(2 * time.Minute))
	if VerifyReceipt(bad, signer.Identity, sub, "relay", "domain", "sender", "recipient") == nil {
		t.Fatal("tampered receipt")
	}
	other, _ := identity.NewDevice(p, "domain", "relay", now)
	if VerifyReceipt(r, other.Identity, sub, "relay", "domain", "sender", "recipient") == nil {
		t.Fatal("unpinned signer")
	}
}
