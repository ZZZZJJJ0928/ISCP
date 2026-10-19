package duplex

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

const Protocol = "iscp.relay.duplex.v1"
const Path = "/v2/relay/duplex"
const ReceiptType = "iscp.relay.acceptance.v1"
const MaxFrameBytes = 1114112
const MaxEnvelopeBytes = 1048576
const MaxControlBytes = 65536
const QueryRecoverySeconds = 604800

type Limits struct {
	MaxFrameBytes        int `json:"max_frame_bytes"`
	MaxEnvelopeBytes     int `json:"max_envelope_bytes"`
	MaxControlBytes      int `json:"max_control_bytes"`
	MaxTTLSeconds        int `json:"max_ttl_seconds"`
	QueryRecoverySeconds int `json:"query_recovery_seconds"`
}

func DefaultLimits() Limits {
	return Limits{MaxFrameBytes, MaxEnvelopeBytes, MaxControlBytes, 86400, QueryRecoverySeconds}
}

type Frame struct {
	V                  int                   `json:"v"`
	Kind               string                `json:"kind"`
	ConnectionID       string                `json:"connection_id"`
	OwnerGeneration    string                `json:"owner_generation,omitempty"`
	RequestID          string                `json:"request_id,omitempty"`
	RelayID            string                `json:"relay_id,omitempty"`
	DomainID           string                `json:"domain_id,omitempty"`
	DeviceID           string                `json:"device_id,omitempty"`
	ChallengeID        string                `json:"challenge_id,omitempty"`
	Challenge          string                `json:"challenge,omitempty"`
	ExpiresAt          string                `json:"expires_at,omitempty"`
	HistoryID          string                `json:"history_id,omitempty"`
	Limits             *Limits               `json:"limits,omitempty"`
	AccessToken        string                `json:"access_token,omitempty"`
	Proof              *identity.DeviceProof `json:"proof,omitempty"`
	AuthorityExpiresAt string                `json:"authority_expires_at,omitempty"`
	MessageID          string                `json:"message_id,omitempty"`
	EnvelopeDigest     string                `json:"envelope_digest,omitempty"`
	NotAfter           string                `json:"not_after,omitempty"`
	Envelope           json.RawMessage       `json:"envelope,omitempty"`
	Receipt            *Receipt              `json:"receipt,omitempty"`
	State              string                `json:"state,omitempty"`
	Reason             string                `json:"reason,omitempty"`
	Code               string                `json:"code,omitempty"`
}
type Receipt struct {
	Type              string             `json:"type"`
	ReceiptID         string             `json:"receipt_id"`
	RelayID           string             `json:"relay_id"`
	DomainID          string             `json:"domain_id"`
	HistoryID         string             `json:"history_id"`
	MessageID         string             `json:"message_id"`
	SenderDeviceID    string             `json:"sender_device_id"`
	RecipientDeviceID string             `json:"recipient_device_id"`
	EnvelopeDigest    string             `json:"envelope_digest"`
	NotAfter          string             `json:"not_after"`
	AcceptedAt        string             `json:"accepted_at"`
	ExpiresAt         string             `json:"expires_at"`
	Signature         identity.Signature `json:"signature"`
}
type Submission struct {
	MessageID, EnvelopeDigest, HistoryID, NotAfter, SessionID string
	Envelope                                                  json.RawMessage
}

// Unknown preserves reconciliation identity. Wrapping callers must use %w;
// canceling a waiter after a write starts cannot turn uncertainty into rejection.
type Unknown struct {
	Submission Submission
	Cause      error
}

func (e *Unknown) Error() string { return "Relay acceptance outcome unknown" }
func (e *Unknown) Unwrap() error { return e.Cause }

type Rejected struct {
	Code       string
	Submission Submission
}

func (e *Rejected) Error() string { return "Relay rejected this attempt: " + e.Code }

type NotSent struct{ Cause error }

func (e *NotSent) Error() string { return "Relay envelope was not sent" }
func (e *NotSent) Unwrap() error { return e.Cause }
func Decode(raw []byte) (Frame, error) {
	var f Frame
	if len(raw) > MaxFrameBytes {
		return f, errors.New("oversize")
	}
	if e := Validate(raw); e != nil {
		return f, e
	}
	e := json.Unmarshal(raw, &f)
	return f, e
}
func Encode(f Frame) ([]byte, error) {
	b, e := json.Marshal(f)
	if e != nil {
		return nil, e
	}
	if e = Validate(b); e != nil {
		return nil, e
	}
	return b, nil
}
func Digest(v any) (string, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	c, e := canonical.Marshal(b)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(c)
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}
func RandomID() string { return crypto.Base64URL(crypto.RandomBytes(32)) }
func Timestamp(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}
func Time(s string) time.Time { t, _ := time.Parse("2006-01-02T15:04:05Z", s); return t }
func Next(s string) (string, error) {
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil || n == ^uint64(0) {
		return "", errors.New("counter exhausted")
	}
	return strconv.FormatUint(n+1, 10), nil
}
func AuthChallenge(challenge Frame, purpose, requestID, generation, token string, id identity.DeviceIdentity) (string, error) {
	if challenge.Limits == nil {
		return "", errors.New("missing limits")
	}
	limitDigest, e := Digest(*challenge.Limits)
	if e != nil {
		return "", e
	}
	th := sha256.Sum256([]byte(token))
	ctx := map[string]any{"purpose": purpose, "protocol": Protocol, "method": "GET", "path": Path, "relay_id": challenge.RelayID, "domain_id": id.DomainID, "device_id": id.DeviceID, "connection_id": challenge.ConnectionID, "owner_generation": generation, "history_id": challenge.HistoryID, "challenge_id": challenge.ChallengeID, "challenge": challenge.Challenge, "request_id": requestID, "access_token_sha256": base64.RawURLEncoding.EncodeToString(th[:]), "limits_sha256": limitDigest}
	b, _ := json.Marshal(ctx)
	c, e := canonical.Marshal(b)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(append([]byte("ISCP-RELAY-DUPLEX-AUTH-V1\x00"), c...))
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}
func SignReceipt(p crypto.Provider, signer identity.Device, r Receipt) (Receipt, error) {
	r.Type = ReceiptType
	r.Signature = identity.Signature{}
	b, _ := json.Marshal(r)
	in, e := canonical.SignatureInput(ReceiptType, b)
	if e != nil {
		return r, e
	}
	r.Signature = identity.Signature{Alg: "Ed25519", KID: signer.Identity.PublicKey.KID, Value: crypto.Base64URL(p.Sign(signer.Private, in))}
	return r, nil
}
func VerifyReceipt(r Receipt, pin identity.DeviceIdentity, sub Submission, relay, domain, sender, recipient string) error {
	if r.Type != ReceiptType || r.RelayID != relay || r.DomainID != domain || r.HistoryID != sub.HistoryID || r.MessageID != sub.MessageID || r.SenderDeviceID != sender || r.RecipientDeviceID != recipient || r.EnvelopeDigest != sub.EnvelopeDigest || r.NotAfter != sub.NotAfter {
		return errors.New("acceptance receipt binding mismatch")
	}
	if r.Signature.Alg != "Ed25519" || r.Signature.KID != pin.PublicKey.KID {
		return errors.New("acceptance receipt signer mismatch")
	}
	pub, e := base64.RawURLEncoding.Strict().DecodeString(pin.PublicKey.Public)
	if e != nil {
		return e
	}
	if crypto.Thumbprint("Ed25519", pub) != pin.PublicKey.KID {
		return errors.New("invalid Relay signer pin")
	}
	key, e := crypto.Ed25519PublicKeyFromBytes(pub)
	if e != nil {
		return e
	}
	sig, e := base64.RawURLEncoding.Strict().DecodeString(r.Signature.Value)
	if e != nil {
		return e
	}
	b, _ := json.Marshal(r)
	in, e := canonical.SignatureInput(ReceiptType, b)
	if e != nil {
		return e
	}
	if !crypto.NewProvider().Verify(key, in, sig) {
		return errors.New("acceptance receipt signature invalid")
	}
	if Time(r.AcceptedAt).IsZero() || Time(r.ExpiresAt).After(Time(r.NotAfter)) || Time(r.ExpiresAt).Before(Time(r.AcceptedAt)) {
		return fmt.Errorf("invalid receipt times")
	}
	return nil
}
