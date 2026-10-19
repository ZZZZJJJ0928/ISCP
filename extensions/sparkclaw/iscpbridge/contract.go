package iscpbridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
)

const (
	ProtocolVersion    = "agent.capability.v1"
	BridgeVersion      = "sparkclaw.bridge.v1"
	maxContractPayload = 1 << 20

	TypeCapabilitiesDescribe = "agent.capabilities.describe.v1"
	TypeSessionList          = "agent.session.list.v1"
	TypeSessionCreate        = "agent.session.create.v1"
	TypeMessageSend          = "agent.message.send.v1"
	TypeMessageCancel        = "agent.message.cancel.v1"
	TypeNotificationDeliver  = "agent.notification.deliver.v1"
	TypeEvent                = "agent.event.v1"
	TypeEventResume          = "agent.event.resume.v1"
	TypeApprovalList         = "agent.approval.list.v1"
	TypeApprovalResolve      = "agent.approval.resolve.v1"
	TypeOperationStatus      = "agent.operation.status.v1"
	TypeResponse             = "agent.response.v1"
	// Read-only phone projections (WS-5 Phase C): activities feed and the
	// home-screen snapshot, implemented in internal/iscpbridge/projection.go.
	TypeActivityList = "agent.activity.list.v1"
	TypeSnapshotGet  = "agent.snapshot.get.v1"
)

const (
	CodeUnauthenticated        = "unauthenticated"
	CodePermissionDenied       = "permission_denied"
	CodeUnsupportedCapability  = "unsupported_capability"
	CodeInvalidRequest         = "invalid_request"
	CodeStaleState             = "stale_state"
	CodeApprovalRequired       = "approval_required"
	CodeNotFound               = "not_found"
	CodeConflict               = "conflict"
	CodeRateLimited            = "rate_limited"
	CodeTemporarilyUnavailable = "temporarily_unavailable"
	CodeInternal               = "internal"
)

var supportedRequestTypes = map[string]struct{}{
	TypeActivityList:         {},
	TypeSnapshotGet:          {},
	TypeCapabilitiesDescribe: {},
	TypeSessionList:          {},
	TypeSessionCreate:        {},
	TypeMessageSend:          {},
	TypeMessageCancel:        {},
	TypeNotificationDeliver:  {},
	TypeEventResume:          {},
	TypeApprovalList:         {},
	TypeApprovalResolve:      {},
	TypeOperationStatus:      {},
}

var mutationRequestTypes = map[string]struct{}{
	TypeSessionCreate:       {},
	TypeMessageSend:         {},
	TypeMessageCancel:       {},
	TypeNotificationDeliver: {},
	TypeApprovalResolve:     {},
}

type Request struct {
	ProtocolVersion string          `json:"protocol_version"`
	Type            string          `json:"type"`
	RequestID       string          `json:"request_id"`
	EndpointID      string          `json:"endpoint_id"`
	SessionID       string          `json:"session_id,omitempty"`
	IdempotencyKey  string          `json:"idempotency_key,omitempty"`
	IssuedAt        time.Time       `json:"issued_at"`
	ExpiresAt       time.Time       `json:"expires_at"`
	Payload         json.RawMessage `json:"payload,omitempty"`
}

type Response struct {
	ProtocolVersion string       `json:"protocol_version"`
	Type            string       `json:"type"`
	RequestID       string       `json:"request_id"`
	EndpointID      string       `json:"endpoint_id"`
	SessionID       string       `json:"session_id,omitempty"`
	Status          string       `json:"status"`
	Operation       *Operation   `json:"operation,omitempty"`
	Result          any          `json:"result,omitempty"`
	Error           *BridgeError `json:"error,omitempty"`
	IssuedAt        time.Time    `json:"issued_at"`
}

type Operation struct {
	ID        string       `json:"id"`
	RequestID string       `json:"request_id,omitempty"`
	SessionID string       `json:"session_id"`
	RunID     string       `json:"run_id,omitempty"`
	State     string       `json:"state"`
	Result    any          `json:"result,omitempty"`
	Error     *BridgeError `json:"error,omitempty"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

type Event struct {
	ProtocolVersion string    `json:"protocol_version"`
	Type            string    `json:"type"`
	EndpointID      string    `json:"endpoint_id"`
	SessionID       string    `json:"session_id"`
	OperationID     string    `json:"operation_id,omitempty"`
	Cursor          string    `json:"cursor"`
	EventType       string    `json:"event_type"`
	Payload         any       `json:"payload"`
	IssuedAt        time.Time `json:"issued_at"`
}

type BridgeError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func (e *BridgeError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

type Capability struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
}

type Manifest struct {
	ProductKind      string       `json:"product_kind"`
	RuntimeKind      string       `json:"runtime_kind"`
	ProtocolVersions []string     `json:"protocol_versions"`
	Capabilities     []Capability `json:"capabilities"`
}

func DefaultManifest() Manifest {
	return Manifest{
		ProductKind:      "sparkclaw",
		RuntimeKind:      "sparkclaw",
		ProtocolVersions: []string{ProtocolVersion, BridgeVersion},
		Capabilities: []Capability{
			{ID: "agent.sessions", Version: 1},
			{ID: "agent.conversation", Version: 1},
			{ID: "agent.streaming", Version: 1},
			{ID: "agent.activities", Version: 1},
			{ID: "agent.snapshot", Version: 1},
			{ID: "agent.approvals", Version: 1},
			{ID: "agent.notifications", Version: 1},
		},
	}
}

func (r Request) Validate(now time.Time) *BridgeError {
	if r.ProtocolVersion != ProtocolVersion {
		return bridgeError(CodeUnsupportedCapability, "unsupported protocol version", false)
	}
	if r.Type != strings.TrimSpace(r.Type) {
		return bridgeError(CodeInvalidRequest, "request type must not contain surrounding whitespace", false)
	}
	if _, ok := supportedRequestTypes[r.Type]; !ok {
		return bridgeError(CodeUnsupportedCapability, "unsupported request type", false)
	}
	if strings.TrimSpace(r.RequestID) == "" || strings.TrimSpace(r.EndpointID) == "" {
		return bridgeError(CodeInvalidRequest, "request_id and endpoint_id are required", false)
	}
	if len(r.RequestID) > 200 || len(r.EndpointID) > 200 || len(r.SessionID) > 200 || len(r.IdempotencyKey) > 300 {
		return bridgeError(CodeInvalidRequest, "request identifier is too long", false)
	}
	if len(r.Payload) > maxContractPayload {
		return bridgeError(CodeInvalidRequest, "request payload is too large", false)
	}
	if r.IssuedAt.IsZero() || r.ExpiresAt.IsZero() || !r.IssuedAt.Before(r.ExpiresAt) {
		return bridgeError(CodeInvalidRequest, "issued_at and expires_at are invalid", false)
	}
	if r.IssuedAt.After(now.Add(2 * time.Minute)) {
		return bridgeError(CodeInvalidRequest, "request issued_at is in the future", false)
	}
	if !now.Before(r.ExpiresAt) {
		return bridgeError(CodeStaleState, "request has expired", false)
	}
	if r.ExpiresAt.Sub(r.IssuedAt) > 10*time.Minute {
		return bridgeError(CodeInvalidRequest, "request validity window is too large", false)
	}
	if _, ok := mutationRequestTypes[r.Type]; ok && strings.TrimSpace(r.IdempotencyKey) == "" {
		return bridgeError(CodeInvalidRequest, "idempotency_key is required for mutations", false)
	}
	return nil
}

func DecodePayload(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid request payload: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid request payload: trailing JSON data")
	}
	return nil
}

func bridgeError(code, message string, retryable bool) *BridgeError {
	return &BridgeError{Code: code, Message: message, Retryable: retryable}
}

func newResponse(req Request, status string, result any, operation *Operation, err *BridgeError, now time.Time) Response {
	return Response{
		ProtocolVersion: ProtocolVersion,
		Type:            TypeResponse,
		RequestID:       req.RequestID,
		EndpointID:      req.EndpointID,
		SessionID:       req.SessionID,
		Status:          status,
		Operation:       operation,
		Result:          result,
		Error:           err,
		IssuedAt:        now.UTC(),
	}
}

func stableID(prefix string, parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return prefix + "_" + hex.EncodeToString(h.Sum(nil)[:16])
}

func requestFingerprint(req Request) string {
	payload := req.Payload
	if canonicalPayload, err := canonical.Marshal(payload); err == nil {
		payload = canonicalPayload
	}
	return stableID("fp", req.Type, req.SessionID, string(payload))
}

func validateNotificationDeepLink(raw string) error {
	if len(raw) == 0 || len(raw) > 2048 || raw != strings.TrimSpace(raw) {
		return errors.New("deep_link is required and must not exceed 2048 bytes")
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Hostname() == "" {
		return errors.New("deep_link must be an absolute URL")
	}
	if parsed.User != nil {
		return errors.New("deep_link must not contain credentials")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		host := strings.ToLower(parsed.Hostname())
		ip := net.ParseIP(host)
		if host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return errors.New("deep_link must use HTTPS, except for loopback development URLs")
}
