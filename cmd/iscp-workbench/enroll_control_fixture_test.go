package main

import (
	"context"
	"sync"
	"time"

	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

// The helper test exercises the real HTTPS issuer Handler and durable client
// coordinator. This Relay fixture keeps signed child results keyed by original
// operations; the independent adapter suite exercises the actual PG child.
type helperControlRelay struct {
	mu            sync.Mutex
	signer, actor identity.Device
	registration  *helperRegistration
	records       map[string]*control.Record
	generations   map[string]uint64
}

func (r *helperControlRelay) Actor() identity.DeviceIdentity { return r.actor.Identity }
func (r *helperControlRelay) Authority(_ context.Context, s control.Subject, t control.Target) (n.ControlAuthority, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	g := r.generations[s.DeviceID]
	if g == 0 {
		g = 1
	}
	return n.ControlAuthority{Subject: s, Target: t, Generation: control.Number(g), AuthorizationRevision: "1", ResourceVersion: "1", Scopes: []string{n.Permission}}, nil
}
func (r *helperControlRelay) Attempt(_ context.Context, q control.Request, _ string) (control.Outcome, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Second)
	record := r.records[q.Key.StorageKey()]
	if q.Action == "ack" {
		d, err := record.Acknowledge(*q.Ack, control.Number(r.generations[record.Intent.SubjectBinding.DeviceID]), true, now, r.signer)
		return control.Outcome{Disposition: &d}, err
	}
	if record == nil {
		s := q.Intent.SubjectBinding
		g := r.generations[s.DeviceID]
		if g == 0 {
			g = 1
		}
		g++
		r.generations[s.DeviceID] = g
		tokens := &control.RelayCredentials{TargetServiceID: q.Intent.Target.ServiceID, BindingID: s.BindingID, CredentialGeneration: control.Number(g), AuthorizationRevision: "1", Access: control.Credential{DomainID: s.DomainID, DeviceID: s.DeviceID, Token: "synthetic-access-private-" + string(control.Number(g)), ExpiresAt: now.Add(time.Hour)}, Refresh: control.Credential{DomainID: s.DomainID, DeviceID: s.DeviceID, Token: "synthetic-refresh-private-" + string(control.Number(g)), ExpiresAt: now.Add(time.Hour)}}
		result, err := control.NewResult(control.ResultPayload{Key: q.Key, SemanticDigest: q.SemanticDigest, ResultVersion: "1", State: "succeeded", CompletedAt: now, CredentialGeneration: control.Number(g), Body: control.ResultBody{RelayCredentials: tokens}}, r.signer)
		if err != nil {
			return control.Outcome{}, err
		}
		record = &control.Record{Key: q.Key, Intent: *q.Intent, SemanticDigest: q.SemanticDigest, State: "succeeded", Version: "1", Generation: control.Number(g), Result: &result, CreatedAt: now}
		r.records[q.Key.StorageKey()] = record
		r.registration.mu.Lock()
		r.registration.recoveries++
		r.registration.mu.Unlock()
	}
	return control.Outcome{Result: record.Result}, nil
}
