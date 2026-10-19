package iscpcontrol

import (
	"context"
	"errors"
	"reflect"
	"time"
)

// ClientJournal contains stable intent and verified evidence only. The caller
// encrypts it and implements cross-process compare-and-swap; network attempts
// are outside that critical section. Probe never admits an operation.
type ClientJournal struct {
	Version     uint64         `json:"version"`
	Generation  Counter        `json:"generation"`
	Probe       *Request       `json:"probe,omitempty"`
	Pending     *ClientPending `json:"pending,omitempty"`
	Predecessor *Predecessor   `json:"predecessor,omitempty"`
}
type ClientPending struct {
	Key         Key          `json:"key"`
	Intent      Intent       `json:"intent"`
	Digest      string       `json:"digest"`
	Result      *Result      `json:"result,omitempty"`
	Ack         *Ack         `json:"ack,omitempty"`
	Disposition *Disposition `json:"disposition,omitempty"`
}
type JournalStore interface {
	Load(context.Context) (ClientJournal, error)
	CompareAndSwap(context.Context, uint64, ClientJournal) error
}
type Coordinator struct {
	Client          *Client
	Store           JournalStore
	Namespace       string
	Subject         Subject
	Target          Target
	Revision        Counter
	ResourceVersion Counter
	Scopes          []string
	VerifyResult    func(Intent, Result) error
}

func (c *Coordinator) persist(ctx context.Context, old ClientJournal, next ClientJournal) error {
	next.Version = old.Version + 1
	return c.Store.CompareAndSwap(ctx, old.Version, next)
}
func (c *Coordinator) request(p *ClientPending, action string) Request {
	r := Request{Action: action, Key: p.Key, SemanticDigest: p.Digest}
	if action == "ack" {
		r.Ack = p.Ack
	} else if action != "lookup" {
		r.Intent = &p.Intent
	}
	return r
}

// Result performs only the accepted control family's find-or-admit operation.
// It never changes an unknown intent, and it closes an expired known issuance
// with its exact signed disposition before reserving a linked successor.
func (c *Coordinator) Result(ctx context.Context, kind string) (Result, error) {
	for step := 0; step < 8; step++ {
		state, err := c.Store.Load(ctx)
		if err != nil {
			return Result{}, err
		}
		if state.Generation == "" {
			if state.Probe == nil {
				probe := Request{Action: "lookup", Key: Key{DomainID: c.Subject.DomainID, DeviceID: c.Client.Device.Identity.DeviceID, Namespace: c.Namespace, OperationID: "probe-" + RandomID()}, SemanticDigest: RandomID()}
				next := state
				next.Probe = &probe
				if err = c.persist(ctx, state, next); err != nil {
					return Result{}, err
				}
				continue
			}
			out, err := c.Client.Attempt(ctx, *state.Probe, "")
			if err != nil {
				return Result{}, err
			}
			if out.Status == nil || out.Status.State != "absent" || !out.Status.HistoryComplete || out.Status.CredentialGeneration == "0" {
				return Result{}, ErrUnknown
			}
			next := state
			next.Generation = out.Status.CredentialGeneration
			next.Probe = nil
			if err = c.persist(ctx, state, next); err != nil {
				return Result{}, err
			}
			continue
		}
		if state.Pending == nil {
			intent := Intent{Type: "iscp.operation.intent.v2", Version: 2, Namespace: c.Namespace, OperationID: "operation-" + RandomID(), Kind: kind, SubjectBinding: c.Subject, Target: c.Target, TaskAuthorization: Standing{Kind: "standing", AuthorizationRevision: c.Revision, Scopes: append([]string(nil), c.Scopes...)}, Payload: Payload{RequestedScopes: append([]string(nil), c.Scopes...)}, Preconditions: Preconditions{ResourceVersion: c.ResourceVersion, CredentialGeneration: state.Generation, AuthorizationRevision: c.Revision}, Predecessor: state.Predecessor}
			if err = intent.Validate(); err != nil {
				return Result{}, err
			}
			digest, err := Digest("ISCP-OPERATION-INTENT-V2\x00", intent)
			if err != nil {
				return Result{}, err
			}
			next := state
			next.Pending = &ClientPending{Key: Key{DomainID: c.Subject.DomainID, DeviceID: c.Client.Device.Identity.DeviceID, Namespace: c.Namespace, OperationID: intent.OperationID}, Intent: intent, Digest: digest}
			if err = c.persist(ctx, state, next); err != nil {
				return Result{}, err
			}
			continue
		}
		p := state.Pending
		if p.Ack != nil {
			if err = c.finishAck(ctx, state); err != nil {
				return Result{}, err
			}
			continue
		}
		if p.Intent.Kind != kind {
			return Result{}, &Failure{Code: "generation_conflict"}
		}
		if p.Result == nil {
			out, err := c.Client.Attempt(ctx, c.request(p, "recover"), "")
			if err != nil {
				return Result{}, err
			}
			if out.Result == nil {
				return Result{}, ErrUnknown
			}
			if err = c.verify(p, *out.Result); err != nil {
				return Result{}, err
			}
			next := state
			copyPending := *p
			copyPending.Result = out.Result
			next.Pending = &copyPending
			if err = c.persist(ctx, state, next); err != nil {
				return Result{}, err
			}
			continue
		}
		if err = c.verify(p, *p.Result); err != nil {
			return Result{}, err
		}
		if p.Result.Payload.State != "succeeded" {
			if p.Result.Payload.Body.Code != "generation_conflict" {
				return Result{}, &Failure{Code: p.Result.Payload.Body.Code}
			}
			next := state
			copyPending := *p
			copyPending.Ack = &Ack{ResultDigest: p.Result.ResultDigest, Disposition: "acknowledged_superseded", CredentialGeneration: p.Result.Payload.CredentialGeneration, RecordedAt: time.Now().UTC().Truncate(time.Second)}
			next.Pending = &copyPending
			if err = c.persist(ctx, state, next); err != nil {
				return Result{}, err
			}
			continue
		}
		expiry := p.Result.UsableUntil()
		if expiry.IsZero() {
			return Result{}, ErrInvalid
		}
		if !time.Now().Before(expiry) {
			next := state
			copyPending := *p
			copyPending.Ack = &Ack{ResultDigest: p.Result.ResultDigest, Disposition: "acknowledged_expired", CredentialGeneration: p.Result.Payload.CredentialGeneration, RecordedAt: time.Now().UTC().Truncate(time.Second)}
			next.Pending = &copyPending
			if err = c.persist(ctx, state, next); err != nil {
				return Result{}, err
			}
			continue
		}
		return *p.Result, nil
	}
	return Result{}, ErrUnknown
}
func (c *Coordinator) verify(p *ClientPending, r Result) error {
	if r.Verify(c.Client.Signer) != nil || r.Payload.Key != p.Key || r.Payload.SemanticDigest != p.Digest {
		return ErrAuthentication
	}
	if c.VerifyResult != nil {
		return c.VerifyResult(p.Intent, r)
	}
	return nil
}

// Installed is called only after the consumer's durable generation CAS (and
// Grant persistence where applicable). ACK intent is retained before sending.
func (c *Coordinator) Installed(ctx context.Context, resultDigest string) error {
	state, err := c.Store.Load(ctx)
	if err != nil {
		return err
	}
	if state.Pending == nil {
		return nil
	}
	p := state.Pending
	if p.Result == nil || p.Result.ResultDigest != resultDigest {
		return ErrInvalid
	}
	if err = c.verify(p, *p.Result); err != nil {
		return err
	}
	if p.Ack == nil {
		if !time.Now().Before(p.Result.UsableUntil()) {
			return &Failure{Code: "deadline_exceeded"}
		}
		next := state
		copyPending := *p
		copyPending.Ack = &Ack{ResultDigest: resultDigest, Disposition: "installed", CredentialGeneration: p.Result.Payload.CredentialGeneration, RecordedAt: time.Now().UTC().Truncate(time.Second)}
		next.Pending = &copyPending
		if err = c.persist(ctx, state, next); err != nil {
			return err
		}
		state, err = c.Store.Load(ctx)
		if err != nil {
			return err
		}
	}
	return c.finishAck(ctx, state)
}
func (c *Coordinator) finishAck(ctx context.Context, state ClientJournal) error {
	p := state.Pending
	if p == nil || p.Ack == nil {
		return ErrInvalid
	}
	if p.Disposition == nil {
		out, err := c.Client.Attempt(ctx, c.request(p, "ack"), "")
		if err != nil {
			return err
		}
		if out.Disposition == nil || !reflect.DeepEqual(out.Disposition.Ack, *p.Ack) {
			return ErrAuthentication
		}
		next := state
		copyPending := *p
		copyPending.Disposition = out.Disposition
		next.Pending = &copyPending
		if err = c.persist(ctx, state, next); err != nil {
			return err
		}
		state, err = c.Store.Load(ctx)
		if err != nil {
			return err
		}
		p = state.Pending
	}
	if p == nil || p.Disposition == nil || p.Disposition.Verify(c.Client.Signer) != nil {
		return ErrAuthentication
	}
	next := state
	next.Generation = p.Result.Payload.CredentialGeneration
	next.Pending = nil
	next.Predecessor = nil
	if p.Ack.Disposition == "acknowledged_expired" || p.Ack.Disposition == "acknowledged_superseded" {
		next.Generation = ""
		next.Predecessor = &Predecessor{Key: p.Key, ResultDigest: p.Result.ResultDigest, DispositionDigest: p.Disposition.DispositionDigest}
	}
	return c.persist(ctx, state, next)
}

var ErrJournalCAS = errors.New("control journal changed during attempt")
