package iscpcontrol

import (
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"time"
)

// Record is persisted in the authority's encrypted transaction store. The
// immutable intent and result never contain a proof, wrap key or connection ID.
// A missing Record proves absence only with a continuous namespace history.
type Record struct {
	Key            Key          `json:"key"`
	Intent         Intent       `json:"intent"`
	SemanticDigest string       `json:"semantic_digest"`
	State          string       `json:"state"`
	Version        Counter      `json:"version"`
	Generation     Counter      `json:"credential_generation"`
	Result         *Result      `json:"result,omitempty"`
	Disposition    *Disposition `json:"disposition,omitempty"`
	CreatedAt      time.Time    `json:"created_at"`
}

func (r *Record) Status(request Request, history string, complete bool, now time.Time, signer identity.Device) (Status, error) {
	state, code := r.State, "none"
	var digest *string
	if request.SemanticDigest != r.SemanticDigest {
		state = "conflict"
		code = "operation_conflict"
	} else if r.Result != nil {
		digest = &r.Result.ResultDigest
		state = r.Result.Payload.State
	}
	return SignStatus(Status{AttemptID: request.AttemptID, Key: request.Key, SemanticDigest: request.SemanticDigest, State: state, RecordVersion: r.Version, HistoryID: history, HistoryComplete: complete, Code: code, ResultDigest: digest, CredentialGeneration: r.Generation, CheckedAt: now.UTC().Truncate(time.Second)}, signer)
}

// Acknowledge must run under the same authority+operation lock as installation
// generation checks. Delegated is valid only for the authenticated issuer actor.
func (r *Record) Acknowledge(ack Ack, current Counter, delegated bool, now time.Time, signer identity.Device) (Disposition, error) {
	if r.Result == nil || ack.ResultDigest != r.Result.ResultDigest || ack.CredentialGeneration != r.Generation {
		return Disposition{}, &Failure{Code: "generation_conflict"}
	}
	if r.Disposition != nil {
		if !equal(r.Disposition.Ack, ack) {
			return Disposition{}, &Failure{Code: "generation_conflict"}
		}
		return *r.Disposition, nil
	}
	if ack.RecordedAt.After(now.Add(30 * time.Second)) {
		return Disposition{}, ErrInvalid
	}
	expiry := r.Result.UsableUntil()
	switch ack.Disposition {
	case "installed":
		if delegated || r.Generation != current || expiry.IsZero() || !now.Before(expiry) || ack.ParentResultDigest != nil {
			return Disposition{}, &Failure{Code: "generation_conflict"}
		}
	case "acknowledged_expired":
		if expiry.IsZero() || now.Before(expiry) || ack.ParentResultDigest != nil {
			return Disposition{}, ErrInvalid
		}
	case "acknowledged_superseded":
		old, e := r.Generation.Uint64()
		next, f := current.Uint64()
		if e != nil || f != nil || old >= next || ack.ParentResultDigest != nil {
			return Disposition{}, ErrInvalid
		}
	case "delegated":
		if !delegated || ack.ParentResultDigest == nil {
			return Disposition{}, ErrAuthentication
		}
	case "applied":
		if !expiry.IsZero() || ack.ParentResultDigest != nil {
			return Disposition{}, ErrInvalid
		}
	default:
		return Disposition{}, ErrInvalid
	}
	d, e := NewDisposition(r.Key, r.SemanticDigest, ack, now, signer)
	if e != nil {
		return Disposition{}, e
	}
	r.Disposition = &d
	r.Version, e = r.Version.Next()
	return d, e
}
func (r Result) UsableUntil() time.Time {
	var expiry time.Time
	minimum := func(t time.Time) {
		if !t.IsZero() && (expiry.IsZero() || t.Before(expiry)) {
			expiry = t
		}
	}
	if g := r.Payload.Body.Grant; g != nil {
		minimum(g.ExpiresAt)
	}
	if creds := r.Payload.Body.RelayCredentials; creds != nil {
		minimum(creds.Access.ExpiresAt)
		minimum(creds.Refresh.ExpiresAt)
	}
	if child := r.Payload.Body.RelayResult; child != nil {
		minimum(child.UsableUntil())
	}
	return expiry
}
func CheckPredecessor(intent Intent, records map[string]*Record) error {
	if p := intent.Predecessor; p != nil {
		old := records[p.Key.StorageKey()]
		if old == nil || old.Result == nil || old.Disposition == nil || old.Result.ResultDigest != p.ResultDigest || old.Disposition.DispositionDigest != p.DispositionDigest || !(old.Disposition.Ack.Disposition == "acknowledged_expired" || old.Disposition.Ack.Disposition == "acknowledged_superseded") || old.Intent.SubjectBinding != intent.SubjectBinding || old.Intent.Target != intent.Target {
			return &Failure{Code: "generation_conflict"}
		}
	}
	return nil
}
