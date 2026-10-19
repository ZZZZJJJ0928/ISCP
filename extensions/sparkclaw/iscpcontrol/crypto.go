package iscpcontrol

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func canonicalBytes(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return canonical.Marshal(b)
}
func Digest(prefix string, v any) (string, error) {
	b, e := canonicalBytes(v)
	if e != nil {
		return "", e
	}
	return c.Base64URL(c.SHA256(append([]byte(prefix), b...))), nil
}
func RandomID() string { return c.Base64URL(c.RandomBytes(32)) }
func signature(typ string, v any, device identity.Device) (identity.Signature, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return identity.Signature{}, e
	}
	input, e := canonical.SignatureInput(typ, b)
	if e != nil {
		return identity.Signature{}, e
	}
	return identity.Signature{Alg: "Ed25519", KID: device.Identity.PublicKey.KID, Value: c.Base64URL(c.NewProvider().Sign(device.Private, input))}, nil
}
func Verify(typ string, v any, sig identity.Signature, id identity.DeviceIdentity) error {
	pub, e := base64.RawURLEncoding.Strict().DecodeString(id.PublicKey.Public)
	if e != nil || len(pub) != 32 || sig.Alg != "Ed25519" || sig.KID != id.PublicKey.KID || c.Thumbprint("Ed25519", pub) != id.PublicKey.KID {
		return ErrAuthentication
	}
	p, e := c.Ed25519PublicKeyFromBytes(pub)
	if e != nil {
		return ErrAuthentication
	}
	s, e := base64.RawURLEncoding.Strict().DecodeString(sig.Value)
	if e != nil || len(s) != 64 {
		return ErrAuthentication
	}
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	input, e := canonical.SignatureInput(typ, b)
	if e != nil || !c.NewProvider().Verify(p, input, s) {
		return ErrAuthentication
	}
	return nil
}
func authContext(r Request, method, path, audience, credential string) (AuthenticationContext, error) {
	b, e := json.Marshal(r)
	if e != nil {
		return AuthenticationContext{}, e
	}
	var obj map[string]any
	_ = json.Unmarshal(b, &obj)
	delete(obj, "authentication")
	d, e := Digest("ISCP-CONTROL-REQUEST-V2\x00", obj)
	if e != nil {
		return AuthenticationContext{}, e
	}
	var tokenHash *string
	if credential != "" {
		h := c.Base64URL(c.SHA256([]byte(credential)))
		tokenHash = &h
	}
	a := r.Authentication
	return AuthenticationContext{Type: "iscp.control.authentication.v2", Protocol: Protocol, Purpose: r.Action, Method: method, Path: path, Audience: audience, DomainID: r.Key.DomainID, DeviceID: r.Key.DeviceID, ChallengeID: a.ChallengeID, Challenge: a.Challenge, Nonce: a.Nonce, IssuedAt: a.IssuedAt, RequestDigest: d, CredentialSHA256: tokenHash}, nil
}
func Authenticate(r *Request, ch Challenge, device identity.Device, credential string, now time.Time) error {
	r.Authentication = Authentication{ChallengeID: ch.ChallengeID, Challenge: ch.Challenge, Nonce: c.Base64URL(c.RandomBytes(24)), IssuedAt: now.UTC().Truncate(time.Second)}
	a, e := authContext(*r, "POST", OperationPath+r.Action, ch.Audience, credential)
	if e != nil {
		return e
	}
	r.Authentication.Signature, e = signature(a.Type, a, device)
	if e != nil {
		return e
	}
	return r.Validate()
}
func VerifyAuthentication(r Request, ch Challenge, id identity.DeviceIdentity, method, path, audience, credential string, now time.Time) error {
	if e := r.Validate(); e != nil {
		return e
	}
	a := r.Authentication
	if r.Key.DomainID != id.DomainID || r.Key.DeviceID != id.DeviceID || ch.Protocol != Protocol || ch.Purpose != r.Action || ch.Audience != audience || a.ChallengeID != ch.ChallengeID || a.Challenge != ch.Challenge || !now.Before(ch.ExpiresAt) || ch.ExpiresAt.Sub(ch.ServerTime) != 10*time.Second || a.IssuedAt.Before(now.Add(-60*time.Second)) || a.IssuedAt.After(now.Add(30*time.Second)) || method != "POST" || path != OperationPath+r.Action {
		return ErrAuthentication
	}
	ctx, e := authContext(r, method, path, audience, credential)
	if e != nil {
		return e
	}
	return Verify(ctx.Type, ctx, a.Signature, id)
}
func NewResult(p ResultPayload, signer identity.Device) (Result, error) {
	p.Type = "iscp.operation.result.payload.v2"
	p.Protocol = Protocol
	d, e := Digest("ISCP-OPERATION-RESULT-V2\x00", p)
	if e != nil {
		return Result{}, e
	}
	r := Result{Type: "iscp.operation.result.v2", Payload: p, ResultDigest: d}
	r.Signature, e = signature(r.Type, r, signer)
	if e == nil {
		e = Validate(r, "result")
	}
	return r, e
}
func (r Result) Verify(id identity.DeviceIdentity) error {
	if e := Validate(r, "result"); e != nil {
		return e
	}
	d, e := Digest("ISCP-OPERATION-RESULT-V2\x00", r.Payload)
	if e != nil || d != r.ResultDigest {
		return ErrAuthentication
	}
	return Verify(r.Type, r, r.Signature, id)
}
func SignStatus(s Status, signer identity.Device) (Status, error) {
	s.Type = "iscp.operation.status.v2"
	s.Protocol = Protocol
	var e error
	s.Signature, e = signature(s.Type, s, signer)
	if e == nil {
		e = Validate(s, "status")
	}
	return s, e
}
func NewError(code, audience string, r *Request, revision *Counter, now time.Time, signer identity.Device) (*Error, error) {
	e := &Error{Type: "iscp.operation.error.v2", Protocol: Protocol, Audience: audience, Code: code, Retryable: code == "challenge_expired" || code == "authorization_unavailable" || code == "resource_exhausted", ServerTime: now.UTC().Truncate(time.Second), AuthorizationRevision: revision}
	if r != nil {
		e.AttemptID = &r.AttemptID
		e.Key = &r.Key
	}
	var err error
	e.Signature, err = signature(e.Type, e, signer)
	if err == nil {
		err = Validate(e, "error")
	}
	return e, err
}
func NewDisposition(key Key, digest string, ack Ack, now time.Time, signer identity.Device) (Disposition, error) {
	base := struct {
		Type           string `json:"type"`
		Protocol       string `json:"protocol"`
		Key            Key    `json:"key"`
		SemanticDigest string `json:"semantic_digest"`
		Ack            Ack    `json:"ack"`
	}{"iscp.operation.disposition.v2", Protocol, key, digest, ack}
	d, e := Digest("ISCP-OPERATION-DISPOSITION-V2\x00", base)
	if e != nil {
		return Disposition{}, e
	}
	out := Disposition{Type: base.Type, Protocol: Protocol, Key: key, SemanticDigest: digest, Ack: ack, DispositionDigest: d, AcceptedAt: now.UTC().Truncate(time.Second)}
	out.Signature, e = signature(out.Type, out, signer)
	if e == nil {
		e = Validate(out, "disposition_receipt")
	}
	return out, e
}
func (d Disposition) Verify(id identity.DeviceIdentity) error {
	if e := Validate(d, "disposition_receipt"); e != nil {
		return e
	}
	base := map[string]any{"type": d.Type, "protocol": d.Protocol, "key": d.Key, "semantic_digest": d.SemanticDigest, "ack": d.Ack}
	h, e := Digest("ISCP-OPERATION-DISPOSITION-V2\x00", base)
	if e != nil || h != d.DispositionDigest {
		return ErrAuthentication
	}
	return Verify(d.Type, d, d.Signature, id)
}
func ChildOperationID(parent Key, digest, target string, index Counter, predecessor *string) (string, error) {
	d, e := Digest("ISCP-CHILD-OPERATION-V2\x00", map[string]any{"parent_key": parent, "parent_semantic_digest": digest, "target_service_id": target, "step": "relay.credentials.recover", "child_index": index, "predecessor_disposition_digest": predecessor})
	return "child-" + d, e
}
func NewDelivery() (Delivery, []byte, error) {
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return Delivery{}, nil, e
	}
	return Delivery{RandomID(), c.Base64URL(key.PublicKey().Bytes())}, key.Bytes(), nil
}
func deliveryContext(w SealedResult) map[string]any {
	return map[string]any{"protocol": w.Protocol, "key": w.Key, "semantic_digest": w.SemanticDigest, "result_digest": w.ResultDigest, "delivery_id": w.DeliveryID, "recipient_public_key": w.RecipientPublicKey, "server_public_key": w.ServerPublicKey}
}
func deliveryKey(secret []byte, w SealedResult) ([]byte, []byte, error) {
	b, e := canonicalBytes(deliveryContext(w))
	if e != nil {
		return nil, nil, e
	}
	salt := sha256.Sum256(append([]byte("ISCP-CONTROL-RESULT-SALT-V2\x00"), b...))
	key, e := c.NewProvider().HKDF(secret, salt[:], append([]byte("ISCP-CONTROL-RESULT-KEY-V2\x00"), b...), 32)
	return key, append([]byte("ISCP-CONTROL-RESULT-AAD-V2\x00"), b...), e
}
func Seal(r Result, request Request) (SealedResult, error) {
	if request.Delivery == nil {
		return SealedResult{}, ErrInvalid
	}
	priv, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return SealedResult{}, e
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(request.Delivery.RecipientPublicKey)
	if e != nil {
		return SealedResult{}, ErrInvalid
	}
	pub, e := ecdh.X25519().NewPublicKey(b)
	if e != nil {
		return SealedResult{}, ErrInvalid
	}
	secret, e := priv.ECDH(pub)
	if e != nil {
		return SealedResult{}, ErrInvalid
	}
	w := SealedResult{Type: "iscp.operation.sealed-result.v2", Protocol: Protocol, AttemptID: request.AttemptID, Key: r.Payload.Key, SemanticDigest: r.Payload.SemanticDigest, ResultDigest: r.ResultDigest, DeliveryID: request.Delivery.DeliveryID, RecipientPublicKey: request.Delivery.RecipientPublicKey, ServerPublicKey: c.Base64URL(priv.PublicKey().Bytes()), Ciphersuite: c.CiphersuiteV2}
	key, aad, e := deliveryKey(secret, w)
	if e != nil {
		return w, e
	}
	plain, e := canonicalBytes(r)
	if e != nil {
		return w, e
	}
	nonce := c.RandomBytes(12)
	ct, e := c.NewProvider().Seal(key, nonce, plain, aad)
	w.Nonce = c.Base64URL(nonce)
	w.Ciphertext = c.Base64URL(ct)
	if e == nil {
		e = Validate(w, "sealed_result")
	}
	return w, e
}
func Open(w SealedResult, request Request, private []byte, signer identity.DeviceIdentity) (Result, error) {
	var out Result
	if e := Validate(w, "sealed_result"); e != nil {
		return out, e
	}
	if request.Delivery == nil || w.AttemptID != request.AttemptID || w.Key != request.Key || w.SemanticDigest != request.SemanticDigest || w.DeliveryID != request.Delivery.DeliveryID || w.RecipientPublicKey != request.Delivery.RecipientPublicKey {
		return out, ErrAuthentication
	}
	priv, e := ecdh.X25519().NewPrivateKey(private)
	if e != nil || c.Base64URL(priv.PublicKey().Bytes()) != w.RecipientPublicKey {
		return out, ErrAuthentication
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(w.ServerPublicKey)
	if e != nil {
		return out, ErrInvalid
	}
	pub, e := ecdh.X25519().NewPublicKey(b)
	if e != nil {
		return out, ErrInvalid
	}
	secret, e := priv.ECDH(pub)
	if e != nil {
		return out, ErrAuthentication
	}
	key, aad, e := deliveryKey(secret, w)
	if e != nil {
		return out, e
	}
	nonce, _ := base64.RawURLEncoding.Strict().DecodeString(w.Nonce)
	ct, _ := base64.RawURLEncoding.Strict().DecodeString(w.Ciphertext)
	plain, e := c.NewProvider().Open(key, nonce, ct, aad)
	if e != nil {
		return out, ErrAuthentication
	}
	if e = Decode(plain, "result", &out); e != nil {
		return out, e
	}
	if out.Payload.Key != w.Key || out.Payload.SemanticDigest != w.SemanticDigest || out.ResultDigest != w.ResultDigest {
		return out, fmt.Errorf("%w: result binding", ErrAuthentication)
	}
	return out, out.Verify(signer)
}
