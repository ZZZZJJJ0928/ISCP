package iscplocalissuer

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
)

type deletionRequest struct {
	RenewalRequest
	OperationID      string `json:"operation_id"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

func (i *Issuer) authorizationDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		writeProtocolError(w, failure(405, "method_not_allowed"))
		return
	}
	key := r.Header.Get("Idempotency-Key")
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
	var input deletionRequest
	if err != nil || !validIdempotencyKey(key) || decode(raw, &input) != nil || !validIdempotencyKey(input.OperationID) || input.ExpectedRevision == 0 || input.ExpectedRevision == ^uint64(0) {
		writeProtocolError(w, failure(400, "invalid_authorization_control_request"))
		return
	}
	var signed descriptor.SignedDescriptor
	err = i.withRenewalState(func(state *renewalState) (bool, error) {
		now := i.Now().UTC()
		challenge := iscpauth.DeletionChallenge(r.URL.Path, key, input.OperationID, input.ExpectedRevision)
		// Only the subject device can delete its own authorization. The
		// responder's status proof is deliberately insufficient.
		if err := i.verifyDeviceProof(iscpauth.DeletePath, challenge, input.RenewalRequest, now); err != nil {
			return false, err
		}
		a := state.Authorization
		if state.SchemaVersion != 2 || a == nil {
			return false, failure(404, "standing_authorization_not_found")
		}
		dirty := false
		receipt := a.Deletion
		if old, found := state.DeletionHistory[input.OperationID]; found {
			receipt = &old
		}
		if receipt == nil {
			if r.URL.Path == iscpauth.DeleteReceiptPath {
				return false, failure(404, "deletion_receipt_not_found")
			}
			if a.Revoked || a.Revision != input.ExpectedRevision {
				return false, failure(409, "authorization_revision_conflict")
			}
			a.Revoked = true
			a.Revision++
			a.Deletion = &iscpauth.DeletionReceipt{OperationID: input.OperationID, ExpectedRevision: input.ExpectedRevision, AuthorizationRevision: a.Revision, State: iscpauth.Revoked, DeletedAt: now}
			receipt = a.Deletion
			dirty = true
		}
		if receipt.OperationID != input.OperationID || receipt.ExpectedRevision != input.ExpectedRevision {
			return false, failure(409, "authorization_operation_conflict")
		}
		cap := i.capabilityBody(state, now)
		// A historical receipt describes only its original consent generation.
		// It cannot grant access or revoke a subsequently authorized generation.
		iscpauth.Policy{Version: 2, Lifetime: iscpauth.UntilRevoked, Revision: receipt.AuthorizationRevision, State: iscpauth.Revoked}.AddTo(cap.Metadata)
		cap.ExpiresAt = now.Add(time.Minute)
		cap.Metadata["request_id"], cap.Metadata["request_digest"], cap.Metadata["request_device_id"] = key, hashBytes(raw), input.Identity.DeviceID
		cap.Metadata["control_action"] = r.URL.Path
		receiptJSON, _ := json.Marshal(receipt)
		cap.Metadata["deletion_receipt"] = string(receiptJSON)
		var signErr error
		signed, signErr = descriptor.Sign(iscpcrypto.NewProvider(), i.device, trustRootDescriptorType, cap, now)
		return dirty, signErr
	})
	if err != nil {
		writeProtocolError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(signed)
}
