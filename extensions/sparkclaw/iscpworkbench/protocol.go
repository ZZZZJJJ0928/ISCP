// Package iscpworkbench implements the bounded desktop workbench application
// profile over authenticated, end-to-end encrypted ISCP sessions.
package iscpworkbench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const (
	Profile          = "sparkclaw.workbench.transport.v1"
	ProfileV2        = "sparkclaw.workbench.transport.v2"
	Permission       = "sparkclaw.workbench.v1"
	RequestType      = "task.invoke"
	ResponseType     = "task.result"
	MaxRequestBytes  = 64 << 10
	MaxResponseBytes = 64 << 10
	MaxMessageBytes  = MaxRequestBytes
	MaxBodyBytes     = MaxMessageBytes - 2048
	MaxConcurrent    = 4
	RoleInitiator    = "initiator"
	RoleResponder    = "responder"
)

type Request struct {
	OperationID      string            `json:"operation_id,omitempty"`
	ExpectedRevision string            `json:"expected_revision,omitempty"`
	Params           map[string]string `json:"params,omitempty"`
	Object           *ObjectReference  `json:"body_object,omitempty"`
	Type             string            `json:"type"`
	Profile          string            `json:"profile"`
	ID               string            `json:"id"`
	Operation        string            `json:"operation"`
	InstallationID   string            `json:"installation_id,omitempty"`
	InputDigest      string            `json:"input_digest,omitempty"`
	Body             json.RawMessage   `json:"body,omitempty"`
	RequestID        string            `json:"request_id,omitempty"`
}

type Response struct {
	Code         ErrorCode        `json:"error_code,omitempty"`
	Retryable    bool             `json:"retryable,omitempty"`
	RetryAfterMS int              `json:"retry_after_ms,omitempty"`
	Object       *ObjectReference `json:"body_object,omitempty"`
	Type         string           `json:"type"`
	Profile      string           `json:"profile"`
	ID           string           `json:"id"`
	Status       int              `json:"status"`
	Body         json.RawMessage  `json:"body,omitempty"`
	Error        string           `json:"error,omitempty"`
}

type Handler func(context.Context, Request) Response

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (r Request) Validate() error {
	if r.Type != RequestType || (r.Profile != Profile && r.Profile != ProfileV2) || !uuidPattern.MatchString(r.ID) {
		return errors.New("invalid workbench request identity or profile")
	}
	spec, known := LookupOperation(r.Operation)
	if !known || (r.Profile == Profile && spec.Version != 1) {
		return errors.New("unsupported workbench operation")
	}
	if r.Profile == Profile && (r.OperationID != "" || r.ExpectedRevision != "" || len(r.Params) > 0 || r.Object != nil) {
		return errors.New("v2 fields are not allowed in v1")
	}
	if r.OperationID != "" && !uuidPattern.MatchString(r.OperationID) {
		return errors.New("operation ID must be a UUID")
	}
	if len(r.ExpectedRevision) > 128 || len(r.Params) > 16 {
		return errors.New("request parameters exceed limits")
	}
	for key, value := range r.Params {
		allowed := false
		for _, p := range spec.Params {
			if key == p {
				allowed = true
			}
		}
		limit := 1024
		// The original mail popup batches up to 100 presentation identities.
		// Only this typed JSON-array parameter needs more than a scalar bound.
		if r.Operation == OperationMailPresentationsGet && key == "target_ids" {
			limit = 32 << 10
		}
		if !allowed || len(value) > limit {
			return errors.New("unsupported request parameter")
		}
	}
	if r.Object != nil {
		if len(r.Body) > 0 {
			return errors.New("request supplies two bodies")
		}
		if err := r.Object.Validate(); err != nil {
			return err
		}
	}
	if len(r.Body) > MaxBodyBytes {
		return errors.New("workbench request body exceeds limit")
	}
	if len(r.InstallationID) > 200 || len(r.InputDigest) > 128 || len(r.RequestID) > 200 {
		return errors.New("workbench request field is too large")
	}
	if len(r.Body) > 0 && !json.Valid(r.Body) {
		return errors.New("invalid workbench request body")
	}
	if r.Operation == OperationSubmit || r.Operation == OperationLookup || r.Operation == OperationCancel || r.Operation == OperationAck {
		if !uuidPattern.MatchString(r.RequestID) {
			return errors.New("execution request ID must be a UUID")
		}
	}
	return nil
}

func (r Response) Validate() error {
	if r.Type != ResponseType || (r.Profile != Profile && r.Profile != ProfileV2) || !uuidPattern.MatchString(r.ID) || r.Status < 100 || r.Status > 599 {
		return errors.New("invalid workbench response")
	}
	if r.Profile == Profile && (r.Code != "" || r.Retryable || r.RetryAfterMS != 0 || r.Object != nil) {
		return errors.New("v2 fields are not allowed in v1")
	}
	if r.Object != nil {
		if len(r.Body) > 0 {
			return errors.New("response supplies two bodies")
		}
		if err := r.Object.Validate(); err != nil {
			return err
		}
	}
	if r.Code != "" && !validErrorCode(r.Code) {
		return errors.New("unknown workbench error code")
	}
	if r.RetryAfterMS < 0 || r.RetryAfterMS > 300000 {
		return errors.New("invalid retry delay")
	}
	if len(r.Error) > 1024 || (len(r.Body) > 0 && !json.Valid(r.Body)) {
		return errors.New("invalid workbench response body")
	}
	return nil
}

// encodeRequest deliberately embeds the original body bytes. encoding/json
// compacts RawMessage during Marshal, changing execution's durable input digest.
func encodeRequest(r Request) ([]byte, error) {
	body := r.Body
	r.Body = nil
	raw, err := json.Marshal(r)
	if err != nil || len(body) == 0 {
		return raw, err
	}
	if !json.Valid(body) {
		return nil, errors.New("invalid workbench body")
	}
	raw = append(raw[:len(raw)-1], []byte(`,"body":`)...)
	raw = append(raw, body...)
	return append(raw, '}'), nil
}

func strictDecode(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}
