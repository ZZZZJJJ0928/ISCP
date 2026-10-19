package iscpcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"time"
)

const AuthorityPath = "/internal/iscp/control/authority"

type Authority struct {
	Subject               Subject  `json:"subject"`
	Target                Target   `json:"target"`
	Generation            Counter  `json:"credential_generation"`
	AuthorizationRevision Counter  `json:"authorization_revision"`
	ResourceVersion       Counter  `json:"resource_version"`
	Scopes                []string `json:"scopes"`
}
type AuthorityRequest struct {
	Type      string                  `json:"type"`
	Method    string                  `json:"method"`
	Path      string                  `json:"path"`
	Audience  string                  `json:"audience"`
	Actor     identity.DeviceIdentity `json:"actor"`
	Subject   Subject                 `json:"subject"`
	Target    Target                  `json:"target"`
	Nonce     string                  `json:"nonce"`
	IssuedAt  time.Time               `json:"issued_at"`
	Signature identity.Signature      `json:"signature"`
}
type AuthorityResponse struct {
	Type          string             `json:"type"`
	RequestDigest string             `json:"request_digest"`
	Authority     Authority          `json:"authority"`
	CheckedAt     time.Time          `json:"checked_at"`
	Signature     identity.Signature `json:"signature"`
}

func NewAuthorityRequest(actor identity.Device, subject Subject, target Target) (AuthorityRequest, error) {
	q := AuthorityRequest{Type: "iscp.internal.control.authority.request.v1", Method: "POST", Path: AuthorityPath, Audience: target.ServiceID, Actor: actor.Identity, Subject: subject, Target: target, Nonce: RandomID(), IssuedAt: time.Now().UTC().Truncate(time.Second)}
	sig, err := signature(q.Type, q, actor)
	q.Signature = sig
	return q, err
}
func (q AuthorityRequest) Verify(actor identity.DeviceIdentity, now time.Time) error {
	if q.Type != "iscp.internal.control.authority.request.v1" || q.Method != "POST" || q.Path != AuthorityPath || q.Audience != q.Target.ServiceID || q.Actor.DomainID != q.Subject.DomainID || !equal(q.Actor, actor) || q.Nonce == "" || q.IssuedAt.Before(now.Add(-10*time.Second)) || q.IssuedAt.After(now.Add(3*time.Second)) {
		return ErrAuthentication
	}
	return Verify(q.Type, q, q.Signature, actor)
}
func NewAuthorityResponse(q AuthorityRequest, a Authority, signer identity.Device) (AuthorityResponse, error) {
	digest, err := Digest("", q)
	if err != nil {
		return AuthorityResponse{}, err
	}
	out := AuthorityResponse{Type: "iscp.internal.control.authority.response.v1", RequestDigest: digest, Authority: a, CheckedAt: time.Now().UTC().Truncate(time.Second)}
	sig, err := signature(out.Type, out, signer)
	out.Signature = sig
	return out, err
}
func (c *Client) Authority(ctx context.Context, subject Subject, target Target) (Authority, error) {
	q, err := NewAuthorityRequest(c.Device, subject, target)
	if err != nil {
		return Authority{}, err
	}
	raw, err := c.post(ctx, AuthorityPath, q, "")
	if err != nil {
		return Authority{}, err
	}
	var out AuthorityResponse
	digest, _ := Digest("", q)
	// Internal snapshot has a fixed typed shape and signed fresh request binding.
	if len(raw) > MaxBody || !json.Valid(raw) || !validUnicodeEscapes(raw) {
		return Authority{}, ErrInvalid
	}
	if _, err := canonical.ParseStrict(raw); err != nil {
		return Authority{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil {
		return Authority{}, ErrInvalid
	}
	if json.Unmarshal(raw, &out) != nil || out.Type != "iscp.internal.control.authority.response.v1" || out.RequestDigest != digest || out.Authority.Subject != subject || out.Authority.Target != target || Verify(out.Type, out, out.Signature, c.Signer) != nil {
		return Authority{}, ErrAuthentication
	}
	return out.Authority, nil
}
