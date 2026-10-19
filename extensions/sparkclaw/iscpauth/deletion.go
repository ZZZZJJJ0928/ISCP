package iscpauth

import (
	"strconv"
	"time"
)

const (
	DeletePath        = "/v1/authorization-delete"
	DeleteReceiptPath = "/v1/authorization-delete-receipt"
)

// DeletionReceipt is a control-plane tombstone, never a new Grant.
type DeletionReceipt struct {
	OperationID           string    `json:"operation_id"`
	ExpectedRevision      uint64    `json:"expected_revision"`
	AuthorizationRevision uint64    `json:"authorization_revision"`
	State                 string    `json:"state"`
	DeletedAt             time.Time `json:"deleted_at"`
}

// DeletionChallenge prevents a read-only proof or a proof for another action
// from being used to delete an authorization.
func DeletionChallenge(path, key, operationID string, revision uint64) string {
	return "sparkclaw.authorization.control.v1\n" + path + "\n" + key + "\n" + operationID + "\n" + strconv.FormatUint(revision, 10)
}
