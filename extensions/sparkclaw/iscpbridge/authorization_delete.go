package iscpbridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
)

var deletionOperationPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func (c *GrantLifecycleClient) DeleteAuthorization(ctx context.Context, operationID string, expectedRevision uint64) (iscpauth.DeletionReceipt, error) {
	return c.authorizationDeletion(ctx, iscpauth.DeletePath, operationID, expectedRevision)
}

func (c *GrantLifecycleClient) AuthorizationDeletionReceipt(ctx context.Context, operationID string, expectedRevision uint64) (iscpauth.DeletionReceipt, error) {
	return c.authorizationDeletion(ctx, iscpauth.DeleteReceiptPath, operationID, expectedRevision)
}

func (c *GrantLifecycleClient) authorizationDeletion(ctx context.Context, path, operationID string, expectedRevision uint64) (iscpauth.DeletionReceipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var receipt iscpauth.DeletionReceipt
	if !deletionOperationPattern.MatchString(operationID) || expectedRevision == 0 || expectedRevision == ^uint64(0) || expectedRevision != c.previous.RevocationEpoch || c.device.Identity.DeviceID != c.previous.SubjectDeviceID {
		return receipt, errors.New("invalid self-authorization deletion request")
	}
	key := newWireID("auth")
	proof, err := c.device.CreateProof(c.provider, c.relayID, iscpauth.DeletionChallenge(path, key, operationID, expectedRevision), randomNonce(), time.Now().UTC())
	if err != nil {
		return receipt, errors.New("create authorization control proof")
	}
	input := struct {
		grantLifecycleRequest
		OperationID      string `json:"operation_id"`
		ExpectedRevision uint64 `json:"expected_revision"`
	}{grantLifecycleRequest{Identity: c.device.Identity, Proof: proof}, operationID, expectedRevision}
	body, err := json.Marshal(input)
	if err != nil {
		return receipt, err
	}
	raw, err := c.request(ctx, http.MethodPost, path, key, body)
	if err != nil {
		return receipt, err
	}
	cap, policy, err := c.verifyCapability(raw, c.previous)
	if err != nil {
		return receipt, err
	}
	digest := sha256.Sum256(body)
	if policy.Version != 2 || policy.State != iscpauth.Revoked || policy.Revision != expectedRevision+1 || cap.ExpiresAt.Sub(cap.IssuedAt) > time.Minute || cap.Metadata["request_id"] != key || cap.Metadata["request_digest"] != hex.EncodeToString(digest[:]) || cap.Metadata["request_device_id"] != c.device.Identity.DeviceID || cap.Metadata["control_action"] != path || strictUnmarshal([]byte(cap.Metadata["deletion_receipt"]), &receipt) != nil || receipt.OperationID != operationID || receipt.ExpectedRevision != expectedRevision || receipt.AuthorizationRevision != policy.Revision || receipt.State != iscpauth.Revoked || receipt.DeletedAt.IsZero() || receipt.DeletedAt.After(time.Now().Add(time.Second)) {
		return iscpauth.DeletionReceipt{}, errors.New("authorization deletion receipt binding mismatch")
	}
	c.revoked = true
	return receipt, nil
}
