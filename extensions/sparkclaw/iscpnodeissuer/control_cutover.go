package iscpnodeissuer

import (
	"context"
	"encoding/base64"
	"errors"
)

var ErrLegacyPending = errors.New("legacy operation remains unresolved; control history activation refused")

func ValidActivationEvidence(evidence string) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(evidence)
	return err == nil && len(raw) == 32
}

// ActivateControlHistory preserves all old evidence and the original binding.
// This explicit maintenance action creates a new protocol namespace only after
// old writer access is fenced and every old issuance has an applied receipt.
func (i *Issuer) ActivateControlHistory(ctx context.Context, invitationID, evidence string) error {
	if !i.cfg.EnableControlV2 || !ValidActivationEvidence(evidence) {
		return ErrInvalid
	}
	if store, ok := i.store.(*PostgresStore); ok && store.writerEpoch == "" {
		return ErrWriterFenced
	}
	return i.store.Update(ctx, invitationID, func(s *State) error {
		if s.State != "active" || s.Device == nil || !s.RevokedAt.IsZero() {
			return ErrDenied
		}
		if s.Control != nil {
			return ErrConflict
		}
		for id, operation := range s.Operations {
			if id == s.BoundOperation && operation.Result != nil {
				continue
			}
			if operation.Renew != nil && (operation.Renew.Kind == "renew" || operation.Renew.Kind == "recover") && operation.State != "applied" {
				return ErrLegacyPending
			}
			if operation.Renew == nil && operation.Result == nil {
				return ErrLegacyPending
			}
		}
		s.Control = newControlState()
		s.Control.ActivationEvidence = evidence
		return nil
	})
}
