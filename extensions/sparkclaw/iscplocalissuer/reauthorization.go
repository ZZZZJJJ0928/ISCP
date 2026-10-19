package iscplocalissuer

import (
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

type reauthorizationReceipt struct {
	OperationID      string      `json:"operation_id"`
	ExpectedRevision uint64      `json:"expected_revision"`
	ScopesDigest     string      `json:"scopes_digest"`
	Grant            trust.Grant `json:"grant"`
}

// ReauthorizePermanentScopes is an explicit local operator action, never a
// device endpoint or automatic renewal. Both peers must explicitly import the
// returned new-revision Grant; old sessions cannot silently regain authority.
func (i *Issuer) ReauthorizePermanentScopes(operationID string, expectedRevision uint64, scopes []string) (trust.Grant, error) {
	var result trust.Grant
	if !validIdempotencyKey(operationID) || expectedRevision == 0 || expectedRevision == ^uint64(0) {
		return result, errors.New("explicit reauthorization operation and revision required")
	}
	if err := iscpauth.ValidateScopes(scopes); err != nil {
		return result, err
	}
	scopes = slices.Clone(scopes)
	slices.Sort(scopes)
	raw, _ := json.Marshal(scopes)
	digest := hashBytes(raw)
	err := i.withRenewalState(func(state *renewalState) (bool, error) {
		if prior := state.Reauthorization; prior != nil && prior.OperationID == operationID {
			if prior.ExpectedRevision != expectedRevision || prior.ScopesDigest != digest {
				return false, errors.New("reauthorization operation conflict")
			}
			result = prior.Grant
			return false, nil
		}
		if state.SchemaVersion != 2 || state.Authorization == nil || state.Authorization.Revision != expectedRevision {
			return false, errors.New("authorization revision conflict")
		}
		if len(state.DeletionHistory) >= 4096 {
			return false, errors.New("authorization history capacity reached")
		}
		now := i.Now().UTC()
		grant, err := i.signGrantAt(time.Duration(state.TTLSeconds)*time.Second, now, expectedRevision+1)
		if err != nil {
			return false, err
		}
		if state.DeletionHistory == nil {
			state.DeletionHistory = map[string]iscpauth.DeletionReceipt{}
		}
		if old := state.Authorization.Deletion; old != nil {
			state.DeletionHistory[old.OperationID] = *old
		}
		state.Authorization = &renewalAuthorization{AuthorizedAt: now, Lifetime: iscpauth.UntilRevoked, Revision: expectedRevision + 1, Scopes: scopes}
		state.CurrentGrant = &grant
		state.Reauthorization = &reauthorizationReceipt{operationID, expectedRevision, digest, grant}
		result = grant
		return true, nil
	})
	return result, err
}
