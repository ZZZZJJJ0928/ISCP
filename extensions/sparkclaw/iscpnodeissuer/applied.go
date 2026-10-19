package iscpnodeissuer

import (
	"context"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"time"
)

type AppliedRequest struct {
	Version     int                     `json:"version"`
	OperationID string                  `json:"operation_id"`
	GrantID     string                  `json:"grant_id"`
	Identity    identity.DeviceIdentity `json:"identity"`
	Proof       identity.DeviceProof    `json:"proof"`
}
type AppliedReceipt struct {
	Version     int                     `json:"version"`
	OperationID string                  `json:"operation_id"`
	GrantID     string                  `json:"grant_id"`
	Identity    identity.DeviceIdentity `json:"identity"`
	State       string                  `json:"state"`
	Signature   identity.Signature      `json:"signature"`
}

func AppliedChallenge(r AppliedRequest) string {
	r.Proof = identity.DeviceProof{}
	return "sparkclaw/iscp-node/applied/v1\x00" + Digest(r)
}
func (i *Issuer) applied(ctx context.Context, x Exchange) (ExchangeResponse, error) {
	var req AppliedRequest
	if StrictDecode(x.Frame, &req) != nil || req.Version != 1 || req.OperationID != x.OperationID {
		return ExchangeResponse{}, ErrInvalid
	}
	var out AppliedReceipt
	e := i.store.Update(ctx, x.InvitationID, func(s *State) error {
		if s.Device == nil || Digest(*s.Device) != Digest(req.Identity) || identity.VerifyProof(c.NewProvider(), *s.Device, req.Proof, i.cfg.Issuer.Identity.DeviceID, AppliedChallenge(req), i.Now(), 5*time.Minute) != nil {
			return ErrDenied
		}
		op := s.Operations[x.OperationID]
		if op == nil || op.Grant == nil || op.LifecycleResponse == nil || op.Grant.GrantID != req.GrantID {
			return ErrConflict
		}
		if op.State != "applied" {
			op.State = "applied"
			op.AppliedAt = i.Now().UTC()
		}
		out = AppliedReceipt{Version: 1, OperationID: req.OperationID, GrantID: req.GrantID, Identity: *s.Device, State: "applied"}
		sig, e := SignObject("sparkclaw.iscp.applied-receipt.v1", out, i.cfg.Issuer)
		if e != nil {
			return e
		}
		out.Signature = sig
		return nil
	})
	if e != nil {
		return ExchangeResponse{}, e
	}
	return response(x, out)
}
