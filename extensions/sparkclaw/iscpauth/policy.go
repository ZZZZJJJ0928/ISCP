// Package iscpauth defines the local issuer's signed authorization metadata.
// It does not change ISCP Grant or Relay envelope formats.
package iscpauth

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"time"
)

const (
	UntilRevoked = "until_revoked"
	Bounded      = "bounded"
	Active       = "active"
	Revoked      = "revoked"
	Expired      = "expired"
	StatusPath   = "/v1/authorization-status"
)

// Policy is carried only inside an issuer-signed descriptor. The caller must
// authenticate its signature, peer scope and freshness before using it.
type Policy struct {
	Version   int
	Lifetime  string
	Revision  uint64
	State     string
	ExpiresAt time.Time
	Scopes    []string
}

func Parse(metadata map[string]string) (Policy, error) {
	p := Policy{Version: 1, Lifetime: Bounded, State: Active}
	version := metadata["authorization_version"]
	if version != "" {
		if version != "2" {
			return p, errors.New("unsupported authorization policy version")
		}
		p.Version = 2
		if raw, present := metadata["authorization_scopes"]; present {
			if len(raw) > 8192 || json.Unmarshal([]byte(raw), &p.Scopes) != nil || p.Scopes == nil || ValidateScopes(p.Scopes) != nil {
				return p, errors.New("invalid authorization scopes")
			}
		}
		p.Lifetime, p.State = metadata["authorization_lifetime"], metadata["authorization_state"]
		var err error
		p.Revision, err = strconv.ParseUint(metadata["authorization_revision"], 10, 64)
		if err != nil || p.Revision == 0 || strconv.FormatUint(p.Revision, 10) != metadata["authorization_revision"] {
			return p, errors.New("invalid authorization revision")
		}
		if p.State != Active && p.State != Revoked && p.State != Expired {
			return p, errors.New("invalid authorization state")
		}
		if p.Lifetime == UntilRevoked {
			if _, found := metadata["authorization_expires_at"]; found || p.State == Expired {
				return p, errors.New("permanent authorization cannot expire")
			}
			return p, nil
		}
		if p.Lifetime != Bounded {
			return p, errors.New("invalid authorization lifetime")
		}
	} else if metadata["authorization_lifetime"] != "" || metadata["authorization_state"] != "" || metadata["authorization_revision"] != "" || metadata["authorization_scopes"] != "" {
		return p, errors.New("authorization policy requires a version")
	}
	var err error
	p.ExpiresAt, err = time.Parse(time.RFC3339Nano, metadata["authorization_expires_at"])
	if err != nil || p.ExpiresAt.IsZero() {
		return p, errors.New("invalid authorization expiry")
	}
	return p, nil
}

func (p Policy) AddTo(metadata map[string]string) {
	if p.Version == 2 {
		metadata["authorization_version"] = "2"
		metadata["authorization_lifetime"] = p.Lifetime
		metadata["authorization_revision"] = strconv.FormatUint(p.Revision, 10)
		metadata["authorization_state"] = p.State
		if p.Scopes != nil {
			raw, _ := json.Marshal(p.Scopes)
			metadata["authorization_scopes"] = string(raw)
		}
	}
	if p.Lifetime == Bounded {
		metadata["authorization_expires_at"] = p.ExpiresAt.Format(time.RFC3339Nano)
	}
}

var scopePattern = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)

func ValidateScopes(scopes []string) error {
	if len(scopes) > 128 {
		return errors.New("too many authorization scopes")
	}
	if encoded, err := json.Marshal(scopes); err != nil || len(encoded) > 8192 {
		return errors.New("authorization scopes exceed descriptor limit")
	}
	seen := map[string]bool{}
	for _, scope := range scopes {
		if !scopePattern.MatchString(scope) || seen[scope] {
			return errors.New("invalid or duplicate authorization scope")
		}
		seen[scope] = true
	}
	return nil
}

// Usable reports an active v2 authorization. A trusted ISCP session keeps the
// same permissions as a normal connection, so this is its only runtime gate.
func (p Policy) Usable() bool {
	return p.State == Active && p.Version == 2
}

func (p Policy) Allows(scope string) bool {
	return p.State == Active && p.Version == 2 && slices.Contains(p.Scopes, scope)
}
