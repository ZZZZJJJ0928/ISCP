// Package iscpcontrol implements the accepted 0041 HTTPS control wire contract.
// It has no dependency on a live WebSocket or a business session.
package iscpcontrol

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

const Protocol = "iscp.operation.recovery.v2"
const ChallengePath = "/v2/control/challenge"
const OperationPath = "/v2/control/operations/"
const CredentialNamespace = "control.credentials.v2"
const RelayNamespace = "control.relay-credentials.v2"

var ErrInvalid = errors.New("invalid control message")
var ErrAuthentication = errors.New("control authentication failed")
var ErrUnknown = errors.New("control operation outcome unknown")

// Counters are independent target-local durable counters, not socket epochs.
type Counter string

func (v Counter) Uint64() (uint64, error) { return strconv.ParseUint(string(v), 10, 64) }
func Number(v uint64) Counter             { return Counter(strconv.FormatUint(v, 10)) }
func (v Counter) Next() (Counter, error) {
	n, e := v.Uint64()
	if e != nil || n == ^uint64(0) {
		return "", ErrInvalid
	}
	return Number(n + 1), nil
}

type Key struct {
	DomainID    string `json:"domain_id"`
	DeviceID    string `json:"device_id"`
	Namespace   string `json:"namespace"`
	OperationID string `json:"operation_id"`
}

func (k Key) StorageKey() string {
	return k.DomainID + "\x00" + k.DeviceID + "\x00" + k.Namespace + "\x00" + k.OperationID
}

type Subject struct {
	DomainID  string `json:"domain_id"`
	DeviceID  string `json:"device_id"`
	BindingID string `json:"binding_id"`
}
type Target struct {
	ServiceID  string `json:"service_id"`
	ResourceID string `json:"resource_id"`
}
type Standing struct {
	Kind                  string   `json:"kind"`
	AuthorizationRevision Counter  `json:"authorization_revision"`
	Scopes                []string `json:"scopes"`
}
type Payload struct {
	RequestedScopes []string `json:"requested_scopes"`
}
type Preconditions struct {
	ResourceVersion       Counter `json:"resource_version"`
	CredentialGeneration  Counter `json:"credential_generation"`
	AuthorizationRevision Counter `json:"authorization_revision"`
}
type Parent struct {
	Key            Key     `json:"key"`
	SemanticDigest string  `json:"semantic_digest"`
	Step           string  `json:"step"`
	ChildIndex     Counter `json:"child_index"`
}
type Predecessor struct {
	Key               Key    `json:"key"`
	ResultDigest      string `json:"result_digest"`
	DispositionDigest string `json:"disposition_digest"`
}
type Intent struct {
	Type              string        `json:"type"`
	Version           int           `json:"version"`
	Namespace         string        `json:"namespace"`
	OperationID       string        `json:"operation_id"`
	Kind              string        `json:"kind"`
	SubjectBinding    Subject       `json:"subject_binding"`
	Target            Target        `json:"target"`
	TaskAuthorization Standing      `json:"task_authorization"`
	Payload           Payload       `json:"payload"`
	BusinessDeadline  *time.Time    `json:"business_deadline"`
	Preconditions     Preconditions `json:"preconditions"`
	Parent            *Parent       `json:"parent,omitempty"`
	Predecessor       *Predecessor  `json:"predecessor,omitempty"`
}
type ChallengeRequest struct {
	Type     string `json:"type"`
	Protocol string `json:"protocol"`
	Audience string `json:"audience"`
	DomainID string `json:"domain_id"`
	DeviceID string `json:"device_id"`
	Purpose  string `json:"purpose"`
}
type Challenge struct {
	Type        string    `json:"type"`
	Protocol    string    `json:"protocol"`
	Audience    string    `json:"audience"`
	ChallengeID string    `json:"challenge_id"`
	Challenge   string    `json:"challenge"`
	Purpose     string    `json:"purpose"`
	ServerTime  time.Time `json:"server_time"`
	ExpiresAt   time.Time `json:"expires_at"`
}
type Authentication struct {
	ChallengeID string             `json:"challenge_id"`
	Challenge   string             `json:"challenge"`
	Nonce       string             `json:"nonce"`
	IssuedAt    time.Time          `json:"issued_at"`
	Signature   identity.Signature `json:"signature"`
}
type Delivery struct {
	DeliveryID         string `json:"delivery_id"`
	RecipientPublicKey string `json:"recipient_public_key"`
}
type Ack struct {
	ResultDigest         string    `json:"result_digest"`
	Disposition          string    `json:"disposition"`
	CredentialGeneration Counter   `json:"credential_generation"`
	RecordedAt           time.Time `json:"recorded_at"`
	ParentResultDigest   *string   `json:"parent_result_digest"`
}
type Request struct {
	Type           string         `json:"type"`
	Protocol       string         `json:"protocol"`
	AttemptID      string         `json:"attempt_id"`
	Action         string         `json:"action"`
	Key            Key            `json:"key"`
	SemanticDigest string         `json:"semantic_digest"`
	Intent         *Intent        `json:"intent,omitempty"`
	Delivery       *Delivery      `json:"delivery,omitempty"`
	Ack            *Ack           `json:"ack,omitempty"`
	Authentication Authentication `json:"authentication"`
}
type AuthenticationContext struct {
	Type             string    `json:"type"`
	Protocol         string    `json:"protocol"`
	Purpose          string    `json:"purpose"`
	Method           string    `json:"method"`
	Path             string    `json:"path"`
	Audience         string    `json:"audience"`
	DomainID         string    `json:"domain_id"`
	DeviceID         string    `json:"device_id"`
	ChallengeID      string    `json:"challenge_id"`
	Challenge        string    `json:"challenge"`
	Nonce            string    `json:"nonce"`
	IssuedAt         time.Time `json:"issued_at"`
	RequestDigest    string    `json:"request_digest"`
	CredentialSHA256 *string   `json:"credential_sha256"`
}
type Credential struct {
	DomainID  string    `json:"domain_id"`
	DeviceID  string    `json:"device_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}
type RelayCredentials struct {
	TargetServiceID       string     `json:"target_service_id"`
	BindingID             string     `json:"binding_id"`
	CredentialGeneration  Counter    `json:"credential_generation"`
	AuthorizationRevision Counter    `json:"authorization_revision"`
	Access                Credential `json:"access"`
	Refresh               Credential `json:"refresh"`
}
type ResultBody struct {
	Grant            *trust.Grant      `json:"grant,omitempty"`
	RelayResult      *Result           `json:"relay_result,omitempty"`
	RelayCredentials *RelayCredentials `json:"relay_credentials,omitempty"`
	Code             string            `json:"code,omitempty"`
}
type ResultPayload struct {
	Type                 string     `json:"type"`
	Protocol             string     `json:"protocol"`
	Key                  Key        `json:"key"`
	SemanticDigest       string     `json:"semantic_digest"`
	ResultVersion        Counter    `json:"result_version"`
	State                string     `json:"state"`
	CompletedAt          time.Time  `json:"completed_at"`
	CredentialGeneration Counter    `json:"credential_generation"`
	Body                 ResultBody `json:"body"`
}
type Result struct {
	Type         string             `json:"type"`
	Payload      ResultPayload      `json:"payload"`
	ResultDigest string             `json:"result_digest"`
	Signature    identity.Signature `json:"signature"`
}
type Status struct {
	Type                 string             `json:"type"`
	Protocol             string             `json:"protocol"`
	AttemptID            string             `json:"attempt_id"`
	Key                  Key                `json:"key"`
	SemanticDigest       string             `json:"semantic_digest"`
	State                string             `json:"state"`
	RecordVersion        Counter            `json:"record_version"`
	HistoryID            string             `json:"history_id"`
	HistoryComplete      bool               `json:"history_complete"`
	Code                 string             `json:"code"`
	ResultDigest         *string            `json:"result_digest"`
	CredentialGeneration Counter            `json:"credential_generation"`
	CheckedAt            time.Time          `json:"checked_at"`
	Signature            identity.Signature `json:"signature"`
}
type Error struct {
	Type                  string             `json:"type"`
	Protocol              string             `json:"protocol"`
	AttemptID             *string            `json:"attempt_id"`
	Audience              string             `json:"audience"`
	Code                  string             `json:"code"`
	Retryable             bool               `json:"retryable"`
	ServerTime            time.Time          `json:"server_time"`
	Key                   *Key               `json:"key"`
	AuthorizationRevision *Counter           `json:"authorization_revision"`
	Signature             identity.Signature `json:"signature"`
}

func (e *Error) Error() string { return "control: " + e.Code }

type Disposition struct {
	Type              string             `json:"type"`
	Protocol          string             `json:"protocol"`
	Key               Key                `json:"key"`
	SemanticDigest    string             `json:"semantic_digest"`
	Ack               Ack                `json:"ack"`
	DispositionDigest string             `json:"disposition_digest"`
	AcceptedAt        time.Time          `json:"accepted_at"`
	Signature         identity.Signature `json:"signature"`
}
type SealedResult struct {
	Type               string `json:"type"`
	Protocol           string `json:"protocol"`
	AttemptID          string `json:"attempt_id"`
	Key                Key    `json:"key"`
	SemanticDigest     string `json:"semantic_digest"`
	ResultDigest       string `json:"result_digest"`
	DeliveryID         string `json:"delivery_id"`
	RecipientPublicKey string `json:"recipient_public_key"`
	ServerPublicKey    string `json:"server_public_key"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
	Ciphersuite        string `json:"ciphersuite"`
}

// Outcome is locally typed; its HTTP representation is exactly one frozen object.
type Outcome struct {
	Result      *Result
	Status      *Status
	Disposition *Disposition
}

func clone[T any](v T) T { b, _ := json.Marshal(v); var out T; _ = json.Unmarshal(b, &out); return out }
