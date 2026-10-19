package iscpnodeissuer

import (
	"context"
	"net/http"
	"reflect"
	"sort"
	"time"

	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

type ControlRelay interface {
	Actor() identity.DeviceIdentity
	Authority(context.Context, control.Subject, control.Target) (ControlAuthority, error)
	Attempt(context.Context, control.Request, string) (control.Outcome, error)
}

// ControlAuthority is an internal authenticated service snapshot, not a public
// 0041 wire object. It never establishes authority: admission CAS rechecks it.
type ControlAuthority = control.Authority

func newControlState() *ControlState {
	return &ControlState{HistoryID: control.RandomID(), HistoryComplete: true, Generation: "1", Records: map[string]*control.Record{}, Parents: map[string]*ControlParent{}}
}
func (i *Issuer) ControlHandler() http.Handler {
	return control.NewHandler(i.cfg.Issuer.Identity.DeviceID, i.cfg.Issuer, i)
}
func (i *Issuer) findControlState(ctx context.Context, domain, device string) (*State, error) {
	rows, e := i.store.List(ctx)
	if e != nil {
		return nil, e
	}
	var found *State
	for _, s := range rows {
		if s.Device != nil && s.Device.DomainID == domain && s.Device.DeviceID == device {
			if found != nil {
				return nil, ErrDenied
			}
			found = s
		}
	}
	if found == nil {
		return nil, ErrDenied
	}
	return found, nil
}
func (i *Issuer) ResolveActor(ctx context.Context, domain, device string) (identity.DeviceIdentity, error) {
	s, e := i.findControlState(ctx, domain, device)
	if e != nil {
		return identity.DeviceIdentity{}, e
	}
	return *s.Device, nil
}
func controlFailure(code string) *control.Failure { return &control.Failure{Code: code} }
func (i *Issuer) controlAuthority(s *State, actor identity.DeviceIdentity, intent *control.Intent) error {
	if s.Device == nil || Digest(*s.Device) != Digest(actor) {
		return controlFailure("identity_recovery_required")
	}
	if s.State == "revoked" || !s.RevokedAt.IsZero() {
		rev := control.Number(s.Revision)
		if !s.RelayRevoked {
			return controlFailure("authorization_unavailable")
		}
		return &control.Failure{Code: "authorization_revoked", Revision: &rev}
	}
	if s.State != "active" {
		return controlFailure("authorization_unavailable")
	}
	if intent != nil {
		scopes := append([]string(nil), s.Credential.Scopes...)
		sort.Strings(scopes)
		if intent.SubjectBinding != (control.Subject{DomainID: actor.DomainID, DeviceID: actor.DeviceID, BindingID: s.Credential.ClientID}) || intent.Target != (control.Target{ServiceID: i.cfg.Issuer.Identity.DeviceID, ResourceID: s.Credential.ClientID}) || intent.Namespace != control.CredentialNamespace || intent.Parent != nil {
			return controlFailure("scope_denied")
		}
		if intent.TaskAuthorization.AuthorizationRevision != control.Number(s.Revision) || intent.Preconditions.AuthorizationRevision != control.Number(s.Revision) {
			return controlFailure("scope_denied")
		}
		for _, scope := range intent.Payload.RequestedScopes {
			if n := sort.SearchStrings(scopes, scope); n == len(scopes) || scopes[n] != scope {
				return controlFailure("scope_denied")
			}
		}
	}
	return nil
}
func (i *Issuer) Execute(ctx context.Context, r control.Request, actor identity.DeviceIdentity, credential string) (control.Outcome, error) {
	var out control.Outcome
	if !i.cfg.EnableControlV2 {
		return out, controlFailure("protocol_incompatible")
	}
	if credential != "" {
		return out, controlFailure("authentication_failed")
	}
	if r.Validate() != nil || r.Key.Namespace != control.CredentialNamespace {
		return out, controlFailure("invalid_request")
	}
	initial, e := i.findControlState(ctx, actor.DomainID, actor.DeviceID)
	if e != nil {
		return out, e
	}
	if e = i.controlAuthority(initial, actor, r.Intent); e != nil {
		return out, e
	}
	if e = i.authorized(ctx, initial); e != nil {
		return out, controlFailure("authorization_unavailable")
	}
	pending := false
	e = i.store.Update(ctx, initial.Credential.InvitationID, func(s *State) error {
		if e := i.controlAuthority(s, actor, r.Intent); e != nil {
			return e
		}
		now := i.Now().UTC().Truncate(time.Second)
		ledger := s.Control
		if ledger == nil || !ledger.HistoryComplete || ledger.Closed {
			history := control.RandomID()
			state, code := "unknown", "history_unavailable"
			if ledger != nil {
				history = ledger.HistoryID
				if ledger.Closed {
					state = "namespace_closed"
					code = "namespace_closed"
				}
			}
			status, e := control.SignStatus(control.Status{AttemptID: r.AttemptID, Key: r.Key, SemanticDigest: r.SemanticDigest, State: state, RecordVersion: "0", HistoryID: history, HistoryComplete: false, Code: code, CredentialGeneration: "0", CheckedAt: now}, i.cfg.Issuer)
			out.Status = &status
			return e
		}
		record := ledger.Records[r.Key.StorageKey()]
		if record != nil {
			if e := i.controlAuthority(s, actor, &record.Intent); e != nil {
				return e
			}
			if r.SemanticDigest != record.SemanticDigest {
				status, e := record.Status(r, ledger.HistoryID, true, now, i.cfg.Issuer)
				out.Status = &status
				return e
			}
			if r.Action == "ack" {
				d, e := record.Acknowledge(*r.Ack, ledger.Generation, false, now, i.cfg.Issuer)
				if e != nil {
					return e
				}
				out.Disposition = &d
				return nil
			}
			if record.State == "succeeded" || record.State == "failed" || record.State == "cancelled" {
				out.Result = record.Result
				return nil
			}
			pending = true
			return nil
		}
		if r.Action == "lookup" || r.Action == "ack" {
			status, e := control.SignStatus(control.Status{AttemptID: r.AttemptID, Key: r.Key, SemanticDigest: r.SemanticDigest, State: "absent", RecordVersion: "0", HistoryID: ledger.HistoryID, HistoryComplete: true, Code: "none", CredentialGeneration: ledger.Generation, CheckedAt: now}, i.cfg.Issuer)
			out.Status = &status
			return e
		}
		if r.Intent == nil || r.Intent.Preconditions.ResourceVersion != control.Number(s.Revision) {
			return controlFailure("generation_conflict")
		}
		if len(ledger.Records) >= 1024 {
			return controlFailure("resource_exhausted")
		}
		if e := control.CheckPredecessor(*r.Intent, ledger.Records); e != nil {
			return e
		}
		expected, err := r.Intent.Preconditions.CredentialGeneration.Uint64()
		if err != nil {
			return controlFailure("invalid_request")
		}
		actual, _ := ledger.Generation.Uint64()
		if expected > actual {
			return controlFailure("generation_conflict")
		}
		if expected < actual {
			result, err := control.NewResult(control.ResultPayload{Key: r.Key, SemanticDigest: r.SemanticDigest, ResultVersion: "1", State: "failed", CompletedAt: now, CredentialGeneration: r.Intent.Preconditions.CredentialGeneration, Body: control.ResultBody{Code: "generation_conflict"}}, i.cfg.Issuer)
			if err != nil {
				return err
			}
			ledger.Records[r.Key.StorageKey()] = &control.Record{Key: r.Key, Intent: *r.Intent, SemanticDigest: r.SemanticDigest, State: "failed", Version: "1", Generation: r.Intent.Preconditions.CredentialGeneration, Result: &result, CreatedAt: now}
			out.Result = &result
			return nil
		}
		for _, old := range ledger.Records {
			if old.Intent.SubjectBinding == r.Intent.SubjectBinding && old.Disposition == nil {
				return controlFailure("generation_conflict")
			}
		}
		generation, e := ledger.Generation.Next()
		if e != nil {
			return controlFailure("resource_exhausted")
		}
		grant, e := i.signGrant(s, actor, now)
		if e != nil {
			return e
		}
		record = &control.Record{Key: r.Key, Intent: *r.Intent, SemanticDigest: r.SemanticDigest, State: "running", Version: "1", Generation: generation, CreatedAt: now}
		ledger.Generation = generation
		ledger.Records[r.Key.StorageKey()] = record
		ledger.Parents[r.Key.StorageKey()] = &ControlParent{Grant: &grant, ChildIndex: "0"}
		if r.Intent.Kind == "credential.renew" {
			res, e := control.NewResult(control.ResultPayload{Key: r.Key, SemanticDigest: r.SemanticDigest, ResultVersion: "1", State: "succeeded", CompletedAt: now, CredentialGeneration: generation, Body: control.ResultBody{Grant: &grant}}, i.cfg.Issuer)
			if e != nil {
				return e
			}
			record.Result = &res
			record.State = "succeeded"
			out.Result = &res
			return nil
		}
		if r.Intent.Kind != "credential.recover" {
			return controlFailure("invalid_request")
		}
		pending = true
		return nil
	})
	if e != nil {
		return out, e
	}
	if pending {
		out, e = i.advanceControlParent(ctx, initial.Credential.InvitationID, r, actor)
		if e != nil {
			return out, e
		}
	}
	// Cross-service calls happen outside the store transaction. Before disclosure
	// recheck current managed-client authority and the durable closing/revoke fence.
	latest, e := i.store.Read(ctx, initial.Credential.InvitationID)
	if e != nil {
		return control.Outcome{}, e
	}
	if e = i.controlAuthority(latest, actor, r.Intent); e != nil {
		return control.Outcome{}, e
	}
	if e = i.authorized(ctx, latest); e != nil {
		return control.Outcome{}, controlFailure("authorization_unavailable")
	}
	if out.Result != nil {
		if e = i.publishRegistry(ctx); e != nil {
			return control.Outcome{}, e
		}
	}
	return out, nil
}
func (i *Issuer) advanceControlParent(ctx context.Context, id string, r control.Request, actor identity.DeviceIdentity) (control.Outcome, error) {
	var out control.Outcome
	if i.cfg.ControlRelay == nil {
		return out, controlFailure("authorization_unavailable")
	}
	for step := 0; step < 6; step++ {
		state, e := i.store.Read(ctx, id)
		if e != nil {
			return out, e
		}
		if e = i.controlAuthority(state, actor, nil); e != nil {
			return out, e
		}
		record := state.Control.Records[r.Key.StorageKey()]
		parent := state.Control.Parents[r.Key.StorageKey()]
		if record == nil || parent == nil {
			return out, ErrUnknownOutcome
		}
		if record.State == "succeeded" {
			return control.Outcome{Result: record.Result}, nil
		}
		// Reserve a child intent only after an authenticated lookup reports the
		// Relay's current generation. A missing/incomplete history never permits it.
		if parent.ChildIntent == nil {
			var predecessor *control.Predecessor
			var previous *string
			if parent.ChildDisposition != nil {
				previous = &parent.ChildDisposition.DispositionDigest
				predecessor = &control.Predecessor{Key: parent.ChildDisposition.Key, ResultDigest: parent.ChildDisposition.Ack.ResultDigest, DispositionDigest: *previous}
			}
			childID, e := control.ChildOperationID(r.Key, r.SemanticDigest, state.Credential.RelayID, parent.ChildIndex, previous)
			if e != nil {
				return out, e
			}
			intent := control.Intent{Type: "iscp.operation.intent.v2", Version: 2, Namespace: control.RelayNamespace, OperationID: childID, Kind: "relay.recover", SubjectBinding: record.Intent.SubjectBinding, Target: control.Target{ServiceID: state.Credential.RelayID, ResourceID: state.Credential.ClientID}, TaskAuthorization: control.Standing{Kind: "standing", AuthorizationRevision: control.Number(state.Revision), Scopes: []string{Permission}}, Payload: control.Payload{RequestedScopes: []string{Permission}}, Preconditions: control.Preconditions{ResourceVersion: "1", CredentialGeneration: "0", AuthorizationRevision: control.Number(state.Revision)}, Parent: &control.Parent{Key: r.Key, SemanticDigest: r.SemanticDigest, Step: "relay.credentials.recover", ChildIndex: parent.ChildIndex}, Predecessor: predecessor}

			snapshot, e := i.cfg.ControlRelay.Authority(ctx, intent.SubjectBinding, intent.Target)
			if e != nil {
				return out, e
			}
			if snapshot.Subject != intent.SubjectBinding || snapshot.Target != intent.Target || snapshot.AuthorizationRevision == "0" || snapshot.Generation == "0" {
				return out, ErrDenied
			}
			intent.Preconditions.CredentialGeneration = snapshot.Generation
			intent.Preconditions.ResourceVersion = snapshot.ResourceVersion
			intent.Preconditions.AuthorizationRevision = snapshot.AuthorizationRevision
			intent.TaskAuthorization.AuthorizationRevision = snapshot.AuthorizationRevision

			e = i.store.Update(ctx, id, func(s *State) error {
				if e := i.controlAuthority(s, actor, &record.Intent); e != nil {
					return e
				}
				p := s.Control.Parents[r.Key.StorageKey()]
				if p.ChildIntent == nil && p.ChildIndex == parent.ChildIndex {
					p.ChildIntent = &intent
					p.ChildResult = nil
				}
				return nil
			})
			if e != nil {
				return out, e
			}
			continue
		}
		intent := *parent.ChildIntent
		key := control.Key{DomainID: i.cfg.ControlRelay.Actor().DomainID, DeviceID: i.cfg.ControlRelay.Actor().DeviceID, Namespace: intent.Namespace, OperationID: intent.OperationID}
		digest, _ := control.Digest("ISCP-OPERATION-INTENT-V2\x00", intent)
		if parent.ChildResult == nil {
			reply, e := i.cfg.ControlRelay.Attempt(ctx, control.Request{Action: "recover", Key: key, SemanticDigest: digest, Intent: &intent}, "")
			if e != nil {
				return out, e
			}
			if reply.Result == nil {
				return out, control.ErrUnknown
			}
			child := reply.Result
			if child.Verify(state.Credential.RelaySignerIdentity) != nil || child.Payload.Key != key || child.Payload.SemanticDigest != digest {
				return out, ErrDenied
			}
			failedCAS := child.Payload.State == "failed" && child.Payload.Body.Code == "generation_conflict" && child.Payload.CredentialGeneration == intent.Preconditions.CredentialGeneration
			creds := child.Payload.Body.RelayCredentials
			if creds == nil && !failedCAS {
				return out, ErrDenied
			}
			if creds != nil && (creds.TargetServiceID != state.Credential.RelayID || creds.BindingID != state.Credential.ClientID || creds.AuthorizationRevision != intent.Preconditions.AuthorizationRevision || creds.CredentialGeneration != child.Payload.CredentialGeneration || creds.Access.DomainID != actor.DomainID || creds.Access.DeviceID != actor.DeviceID || creds.Refresh.DomainID != actor.DomainID || creds.Refresh.DeviceID != actor.DeviceID) {
				return out, ErrDenied
			}
			e = i.store.Update(ctx, id, func(s *State) error {
				if e := i.controlAuthority(s, actor, &record.Intent); e != nil {
					return e
				}
				p := s.Control.Parents[r.Key.StorageKey()]
				if p.ChildIntent == nil || !reflect.DeepEqual(*p.ChildIntent, intent) {
					return ErrConflict
				}
				if p.ChildResult == nil {
					p.ChildResult = child
				}
				return nil
			})
			if e != nil {
				return out, e
			}
			continue
		}
		if record.Result == nil && (parent.ChildResult.Payload.State == "failed" || !i.Now().Before(parent.ChildResult.UsableUntil())) {
			ack := control.Ack{ResultDigest: parent.ChildResult.ResultDigest, Disposition: "acknowledged_expired", CredentialGeneration: parent.ChildResult.Payload.CredentialGeneration, RecordedAt: i.Now().UTC().Truncate(time.Second)}
			if parent.ChildResult.Payload.State == "failed" {
				ack.Disposition = "acknowledged_superseded"
			}
			if parent.ChildAck != nil {
				ack = *parent.ChildAck
			} else {
				e = i.store.Update(ctx, id, func(s *State) error {
					if e := i.controlAuthority(s, actor, &record.Intent); e != nil {
						return e
					}
					p := s.Control.Parents[r.Key.StorageKey()]
					if p.ChildAck == nil {
						p.ChildAck = &ack
					} else {
						ack = *p.ChildAck
					}
					return nil
				})
				if e != nil {
					return out, e
				}
			}
			reply, e := i.cfg.ControlRelay.Attempt(ctx, control.Request{Action: "ack", Key: key, SemanticDigest: digest, Ack: &ack}, "")
			if e != nil {
				return out, e
			}
			if reply.Disposition == nil {
				return out, control.ErrUnknown
			}
			e = i.store.Update(ctx, id, func(s *State) error {
				if e := i.controlAuthority(s, actor, &record.Intent); e != nil {
					return e
				}
				p := s.Control.Parents[r.Key.StorageKey()]
				if p.ChildResult == nil || p.ChildResult.ResultDigest != ack.ResultDigest {
					return ErrConflict
				}
				p.ChildDisposition = reply.Disposition
				p.ChildIntent = nil
				p.ChildResult = nil
				p.ChildAck = nil
				var e error
				p.ChildIndex, e = p.ChildIndex.Next()
				return e
			})
			if e != nil {
				return out, e
			}
			continue
		}
		if record.Result == nil {
			e = i.store.Update(ctx, id, func(s *State) error {
				if e := i.controlAuthority(s, actor, &record.Intent); e != nil {
					return e
				}
				rec := s.Control.Records[r.Key.StorageKey()]
				p := s.Control.Parents[r.Key.StorageKey()]
				if rec.Result != nil {
					return nil
				}
				res, e := control.NewResult(control.ResultPayload{Key: r.Key, SemanticDigest: r.SemanticDigest, ResultVersion: "1", State: "succeeded", CompletedAt: i.Now().UTC().Truncate(time.Second), CredentialGeneration: rec.Generation, Body: control.ResultBody{Grant: p.Grant, RelayResult: p.ChildResult}}, i.cfg.Issuer)
				if e == nil {
					rec.Result = &res
				}
				return e
			})
			if e != nil {
				return out, e
			}
			continue
		}
		ack := control.Ack{ResultDigest: parent.ChildResult.ResultDigest, Disposition: "delegated", CredentialGeneration: parent.ChildResult.Payload.CredentialGeneration, RecordedAt: record.Result.Payload.CompletedAt, ParentResultDigest: &record.Result.ResultDigest}
		reply, e := i.cfg.ControlRelay.Attempt(ctx, control.Request{Action: "ack", Key: key, SemanticDigest: digest, Ack: &ack}, "")
		if e != nil {
			return out, e
		}
		if reply.Disposition == nil {
			return out, control.ErrUnknown
		}
		e = i.store.Update(ctx, id, func(s *State) error {
			if e := i.controlAuthority(s, actor, &record.Intent); e != nil {
				return e
			}
			rec := s.Control.Records[r.Key.StorageKey()]
			if rec.Result == nil || rec.Result.ResultDigest != record.Result.ResultDigest {
				return ErrConflict
			}
			s.Control.Parents[r.Key.StorageKey()].ChildDisposition = reply.Disposition
			rec.State = "succeeded"
			out.Result = rec.Result
			return nil
		})
		return out, e
	}
	return out, control.ErrUnknown
}

func (i *Issuer) Disclose(ctx context.Context, r control.Request, actor identity.DeviceIdentity, emit func() error) error {
	initial, err := i.findControlState(ctx, actor.DomainID, actor.DeviceID)
	if err != nil {
		return err
	}
	// The issuer's durable closing transition and this local write share the
	// aggregate row lock. Management/network authorization was checked before it.
	return i.store.Update(ctx, initial.Credential.InvitationID, func(s *State) error {
		intent := r.Intent
		if s.Control != nil {
			if record := s.Control.Records[r.Key.StorageKey()]; record != nil {
				intent = &record.Intent
			}
		}
		if err := i.controlAuthority(s, actor, intent); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return emit()
	})
}
