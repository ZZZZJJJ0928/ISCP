// Package appstream defines the optional, application-neutral stream envelope.
// It is a local candidate extension, not an ISCP Core wire change or standard.
package appstream

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
	"unicode/utf8"
)

const (
	Version     = 1
	Type        = "iscp.application.stream.v1"
	ControlType = "iscp.application.stream.control.v1"
	MaxBytes    = 64 << 10
	MaxSequence = uint64(1<<53 - 1)
)

var uuid = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var ErrInvalid = errors.New("invalid application stream frame")

type Frame struct {
	Type           string          `json:"type"`
	SchemaVersion  int             `json:"schema_version"`
	SubscriptionID string          `json:"subscription_id"`
	StreamSeq      uint64          `json:"stream_seq"`
	Body           json.RawMessage `json:"body"`
}

type Control struct {
	Type           string          `json:"type"`
	SchemaVersion  int             `json:"schema_version"`
	SubscriptionID string          `json:"subscription_id"`
	Action         string          `json:"action"`
	LatestOpenAt   *time.Time      `json:"latest_open_at,omitempty"`
	Body           json.RawMessage `json:"body,omitempty"`
}

type Completion struct {
	SchemaVersion int    `json:"schema_version"`
	LastStreamSeq uint64 `json:"last_stream_seq"`
	Reason        string `json:"reason"`
}

func (f Frame) Validate() error {
	if f.Type != Type || f.SchemaVersion != Version || !uuid.MatchString(f.SubscriptionID) || f.StreamSeq == 0 || f.StreamSeq > MaxSequence || !object(f.Body) {
		return ErrInvalid
	}
	return nil
}
func Decode(raw []byte) (Frame, error) {
	var f Frame
	if len(raw) > MaxBytes || DecodeStrict(raw, &f) != nil || f.Validate() != nil || !exactFields(raw, "type", "schema_version", "subscription_id", "stream_seq", "body") {
		return f, ErrInvalid
	}
	return f, nil
}
func DecodeControl(raw []byte) (Control, error) {
	var c Control
	if len(raw) > MaxBytes || DecodeStrict(raw, &c) != nil || c.Type != ControlType || c.SchemaVersion != Version || !uuid.MatchString(c.SubscriptionID) {
		return c, ErrInvalid
	}
	switch c.Action {
	case "cancel":
		if c.LatestOpenAt == nil || c.LatestOpenAt.IsZero() || c.Body != nil || !exactFields(raw, "type", "schema_version", "subscription_id", "action", "latest_open_at") {
			return c, ErrInvalid
		}
	case "invalidate":
		if c.LatestOpenAt != nil || !object(c.Body) || !exactFields(raw, "type", "schema_version", "subscription_id", "action", "body") {
			return c, ErrInvalid
		}
	default:
		return c, ErrInvalid
	}
	return c, nil
}
func (c Completion) Validate() error {
	if c.SchemaVersion != Version || c.LastStreamSeq > MaxSequence {
		return ErrInvalid
	}
	switch c.Reason {
	case "terminal", "renew", "canceled", "reset", "auth_expired", "gap", "preview_unavailable":
		return nil
	}
	return ErrInvalid
}

func DecodeCompletion(raw []byte) (Completion, error) {
	var c Completion
	if len(raw) > MaxBytes || DecodeStrict(raw, &c) != nil || c.Validate() != nil || !exactFields(raw, "schema_version", "last_stream_seq", "reason") {
		return c, ErrInvalid
	}
	return c, nil
}

// Go's struct decoder accepts alternate capitalization and maps null to zero.
// The wire schema uses exact, non-null keys, including zero-valued sequences.
func exactFields(raw []byte, keys ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}
func object(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) > 1 && raw[0] == '{' && DecodeStrict(raw, new(map[string]json.RawMessage)) == nil
}

// DecodeStrict rejects ambiguous JSON before Go's decoder can replace malformed
// Unicode or collapse duplicate keys. Body-specific schemas remain the owner's.
func DecodeStrict(raw []byte, target any) error {
	if !utf8.Valid(raw) || !validEscapes(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := uniqueValue(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	return nil
}
func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 64 {
		return ErrInvalid
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	if v, ok := t.(json.Delim); ok {
		switch v {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return ErrInvalid
				}
				seen[s] = true
				if err = uniqueValue(d, depth+1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err = uniqueValue(d, depth+1); err != nil {
					return err
				}
			}
		default:
			return ErrInvalid
		}
		_, err = d.Token()
		return err
	}
	return nil
}
func hex4(b []byte) (uint16, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var v uint16
	for _, c := range b[:4] {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v += uint16(c - '0')
		case c >= 'a' && c <= 'f':
			v += uint16(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v += uint16(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return v, true
}
func validEscapes(b []byte) bool {
	in := false
	for i := 0; i < len(b); i++ {
		if b[i] == '"' {
			in = !in
			continue
		}
		if !in || b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		v, ok := hex4(b[i+1:])
		if !ok {
			return false
		}
		i += 4
		if v >= 0xdc00 && v <= 0xdfff {
			return false
		}
		if v >= 0xd800 && v <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return false
			}
			w, ok := hex4(b[i+3:])
			if !ok || w < 0xdc00 || w > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !in
}
