package iscpnodeissuer

import (
	"context"
	"encoding/json"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"time"
)

// Lifecycle requests are proven by the already bound device. They need no
// consumed bootstrap secret and work after both short-lived credentials expire.
type LifecycleRequest struct {
	Version         int                     `json:"version"`
	OperationID     string                  `json:"operation_id"`
	InvitationID    string                  `json:"invitation_id"`
	Kind            string                  `json:"kind"`
	Identity        identity.DeviceIdentity `json:"identity"`
	Revision        uint64                  `json:"revision"`
	PreviousGrantID string                  `json:"previous_grant_id"`
	WrapPublicKey   string                  `json:"wrap_public_key"`
	Proof           identity.DeviceProof    `json:"proof"`
	RelayProof      *identity.DeviceProof   `json:"relay_proof,omitempty"`
}
type LifecycleResult struct {
	Version          int                       `json:"version"`
	OperationID      string                    `json:"operation_id"`
	InvitationID     string                    `json:"invitation_id"`
	Identity         identity.DeviceIdentity   `json:"identity"`
	Revision         uint64                    `json:"revision"`
	State            string                    `json:"state"`
	Scopes           []string                  `json:"scopes"`
	Grant            *trust.Grant              `json:"grant,omitempty"`
	RelayReceipt     *RegistrationReceipt      `json:"relay_receipt,omitempty"`
	RelayCredentials *RelayCredentials         `json:"relay_credentials,omitempty"`
	Deletion         *iscpauth.DeletionReceipt `json:"deletion,omitempty"`
	Signature        identity.Signature        `json:"signature"`
}
type LifecycleResponse struct {
	Version     int                 `json:"version"`
	OperationID string              `json:"operation_id"`
	Sealed      RegistrationReceipt `json:"sealed"`
}

func LifecycleChallenge(req LifecycleRequest) string {
	req.Proof = identity.DeviceProof{}
	return "sparkclaw/iscp-node/lifecycle/v1\x00" + Digest(req)
}
func NewLifecycleRequest(kind, op, invitation string, revision uint64, previous string, device identity.Device, issuerID string, now time.Time) (LifecycleRequest, []byte, error) {
	priv, pub, e := NewWrapKey()
	if e != nil {
		return LifecycleRequest{}, nil, e
	}
	r := LifecycleRequest{Version: 1, OperationID: op, InvitationID: invitation, Kind: kind, Identity: device.Identity, Revision: revision, PreviousGrantID: previous, WrapPublicKey: pub}
	p, e := device.CreateProof(c.NewProvider(), issuerID, LifecycleChallenge(r), c.Base64URL(c.RandomBytes(24)), now)
	r.Proof = p
	return r, priv, e
}

// Lifecycle sealing uses a separate domain from Relay receipt sealing and binds
// its entire request, device and response operation through the AAD.
func SealLifecycle(r LifecycleRequest, v LifecycleResult) (LifecycleResponse, error) {
	priv, eph, e := NewWrapKey()
	if e != nil {
		return LifecycleResponse{}, e
	}
	sec, e := shared(priv, r.WrapPublicKey)
	if e != nil {
		return LifecycleResponse{}, e
	}
	aad := []byte("sparkclaw/iscp-node/lifecycle-result/v1\x00" + Digest(r))
	p, _ := c.DecodeBase64URL(r.WrapPublicKey)
	ep, _ := c.DecodeBase64URL(eph)
	key, e := c.NewProvider().HKDF(sec, nil, append(append(append([]byte{}, aad...), p...), ep...), 32)
	if e != nil {
		return LifecycleResponse{}, e
	}
	raw, _ := json.Marshal(v)
	n := c.RandomBytes(12)
	ct, e := c.NewProvider().Seal(key, n, raw, aad)
	return LifecycleResponse{1, r.OperationID, RegistrationReceipt{SchemaVersion: 1, OperationID: r.OperationID, BindingDigest: Digest(r), DomainID: r.Identity.DomainID, DeviceID: r.Identity.DeviceID, State: "lifecycle", EphemeralPublic: eph, Nonce: c.Base64URL(n), Ciphertext: c.Base64URL(ct), IssuedAt: time.Now().UTC()}}, e
}
func OpenLifecycle(r LifecycleRequest, v LifecycleResponse, priv []byte) (LifecycleResult, error) {
	var out LifecycleResult
	if v.Version != 1 || v.OperationID != r.OperationID || v.Sealed.BindingDigest != Digest(r) || v.Sealed.DeviceID != r.Identity.DeviceID {
		return out, ErrDenied
	}
	sec, e := shared(priv, v.Sealed.EphemeralPublic)
	if e != nil {
		return out, e
	}
	aad := []byte("sparkclaw/iscp-node/lifecycle-result/v1\x00" + Digest(r))
	p, _ := c.DecodeBase64URL(r.WrapPublicKey)
	ep, _ := c.DecodeBase64URL(v.Sealed.EphemeralPublic)
	key, e := c.NewProvider().HKDF(sec, nil, append(append(append([]byte{}, aad...), p...), ep...), 32)
	if e != nil {
		return out, e
	}
	n, _ := c.DecodeBase64URL(v.Sealed.Nonce)
	ct, _ := c.DecodeBase64URL(v.Sealed.Ciphertext)
	raw, e := c.NewProvider().Open(key, n, ct, aad)
	if e != nil {
		return out, ErrDenied
	}
	if StrictDecode(raw, &out) != nil {
		return out, ErrInvalid
	}
	return out, nil
}
func (i *Issuer) lifecycle(ctx context.Context, x Exchange) (ExchangeResponse, error) {
	var req LifecycleRequest
	if StrictDecode(x.Frame, &req) != nil || req.OperationID != x.OperationID || req.InvitationID != x.InvitationID || req.Version != 1 {
		return ExchangeResponse{}, ErrInvalid
	}
	switch req.Kind {
	case "renew", "recover", "check", "delete", "delete-receipt":
	default:
		return ExchangeResponse{}, ErrInvalid
	}
	s, e := i.store.Read(ctx, x.InvitationID)
	if e != nil {
		return ExchangeResponse{}, e
	}
	if s.Device == nil || Digest(*s.Device) != Digest(req.Identity) {
		return ExchangeResponse{}, ErrDenied
	}
	if identity.VerifyProof(c.NewProvider(), *s.Device, req.Proof, i.cfg.Issuer.Identity.DeviceID, LifecycleChallenge(req), i.Now(), 5*time.Minute) != nil {
		// Only exact previously authenticated operations can replay a retained proof.
		op := s.Operations[x.OperationID]
		if op == nil || op.InputDigest != Digest(req) {
			return ExchangeResponse{}, ErrDenied
		}
	}
	if req.Kind == "delete" || req.Kind == "delete-receipt" {
		if req.Kind == "delete" {
			if e = i.Revoke(ctx, x.InvitationID, x.OperationID, req.Revision); e != nil {
				return ExchangeResponse{}, e
			}
		}
		s, e = i.store.Read(ctx, x.InvitationID)
		if e != nil {
			return ExchangeResponse{}, e
		}
		if s.State != "revoked" || s.RevocationOperation != x.OperationID || !s.RelayRevoked {
			return ExchangeResponse{}, ErrUnknownOutcome
		}
		res := LifecycleResult{Version: 1, OperationID: x.OperationID, InvitationID: x.InvitationID, Identity: *s.Device, Revision: s.Revision, State: "revoked", Scopes: s.Credential.Scopes, Deletion: &iscpauth.DeletionReceipt{OperationID: x.OperationID, ExpectedRevision: req.Revision, AuthorizationRevision: s.Revision, State: "revoked", DeletedAt: s.RevokedAt}}
		res.Signature, e = SignObject("sparkclaw.iscp.lifecycle-result.v1", res, i.cfg.Issuer)
		if e != nil {
			return ExchangeResponse{}, e
		}
		wrapped, e := SealLifecycle(req, res)
		if e != nil {
			return ExchangeResponse{}, e
		}
		return response(x, wrapped)
	}
	if s.State == "revoked" {
		res := LifecycleResult{Version: 1, OperationID: x.OperationID, InvitationID: x.InvitationID, Identity: *s.Device, Revision: s.Revision, State: "revoked", Scopes: s.Credential.Scopes}
		res.Signature, e = SignObject("sparkclaw.iscp.lifecycle-result.v1", res, i.cfg.Issuer)
		if e != nil {
			return ExchangeResponse{}, e
		}
		wrapped, e := SealLifecycle(req, res)
		if e != nil {
			return ExchangeResponse{}, e
		}
		return response(x, wrapped)
	}
	if e = i.authorized(ctx, s); e != nil {
		return ExchangeResponse{}, e
	}
	if req.Revision != s.Revision {
		return ExchangeResponse{}, ErrConflict
	}
	if req.Kind == "check" {
		res := LifecycleResult{Version: 1, OperationID: x.OperationID, InvitationID: x.InvitationID, Identity: *s.Device, Revision: s.Revision, State: "active", Scopes: s.Credential.Scopes}
		res.Signature, e = SignObject("sparkclaw.iscp.lifecycle-result.v1", res, i.cfg.Issuer)
		if e != nil {
			return ExchangeResponse{}, e
		}
		wrapped, e := SealLifecycle(req, res)
		if e != nil {
			return ExchangeResponse{}, e
		}
		return response(x, wrapped)
	}
	var result LifecycleResponse
	e = i.store.Update(ctx, x.InvitationID, func(st *State) error {
		if st.State != "active" || st.Revision != req.Revision {
			return ErrDenied
		}
		op := st.Operations[x.OperationID]
		if op != nil {
			if op.InputDigest != Digest(req) {
				return ErrConflict
			}
			if op.LifecycleResponse != nil {
				result = *op.LifecycleResponse
				return nil
			}
			return nil
		}
		for id, o := range st.Operations {
			if id != st.BoundOperation && o.State == "applied" && o.LifecycleResponse != nil && !o.AppliedAt.IsZero() && i.Now().Sub(o.AppliedAt) > 48*time.Hour {
				delete(st.Operations, id)
			}
		}
		if len(st.Operations) >= 512 {
			return ErrUnavailable
		}
		op = &Operation{CreatedAt: i.Now().UTC(), ID: x.OperationID, State: "lifecycle_pending", InputDigest: Digest(req), Renew: &req}
		if req.Kind == "renew" || req.Kind == "recover" {
			g, e := i.signGrant(st, *st.Device, i.Now().UTC())
			if e != nil {
				return e
			}
			op.Grant = &g
		}
		st.Operations[x.OperationID] = op
		return nil
	})
	if e != nil {
		return ExchangeResponse{}, e
	}
	if result.Version == 1 {
		return response(x, result)
	}
	s, e = i.store.Read(ctx, x.InvitationID)
	if e != nil {
		return ExchangeResponse{}, e
	}
	op := s.Operations[x.OperationID]
	res := LifecycleResult{Version: 1, OperationID: x.OperationID, InvitationID: x.InvitationID, Identity: *s.Device, Revision: s.Revision, State: "active", Scopes: s.Credential.Scopes, Grant: op.Grant}
	if req.Kind == "recover" {
		if req.RelayProof == nil {
			return ExchangeResponse{}, ErrDenied
		}
		recovery := RegistrationRecovery{OperationID: x.OperationID, Identity: *s.Device, Grant: *op.Grant, Proof: *req.RelayProof, ReceiptWrapPublicKey: req.WrapPublicKey, Revision: s.Revision}
		recovery.BindingDigest = Digest(recovery)
		receipt, e := i.relay.Recover(ctx, recovery)
		if e != nil {
			return ExchangeResponse{}, e
		} // The Relay receipt is sealed to SparkX; return it alongside issuer-signed Grant.
		op.Receipt = &receipt
		res.RelayReceipt = &receipt
	}
	res.Signature, e = SignObject("sparkclaw.iscp.lifecycle-result.v1", res, i.cfg.Issuer)
	if e != nil {
		return ExchangeResponse{}, e
	}
	result, e = SealLifecycle(req, res)
	if e != nil {
		return ExchangeResponse{}, e
	}
	b, _ := json.Marshal(result)
	e = i.store.Update(ctx, x.InvitationID, func(st *State) error {
		if st.State != "active" || st.Revision != req.Revision {
			return ErrDenied
		}
		o := st.Operations[x.OperationID]
		if o.LifecycleResponse == nil {
			o.LifecycleResponse = &result
			o.State = "lifecycle_ready"
			o.Receipt = op.Receipt
		}
		return nil
	})
	_ = b
	if e != nil {
		return ExchangeResponse{}, e
	}
	if e = i.publishRegistry(ctx); e != nil {
		return ExchangeResponse{}, e
	}
	stored, e := i.store.Read(ctx, x.InvitationID)
	if e != nil {
		return ExchangeResponse{}, e
	}
	return response(x, *stored.Operations[x.OperationID].LifecycleResponse)
}
