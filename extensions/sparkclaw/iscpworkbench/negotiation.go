package iscpworkbench

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"slices"
	"time"
)

type TransportLimits struct {
	RequestBytes   int `json:"request_bytes"`
	ResponseBytes  int `json:"response_bytes"`
	BodyBytes      int `json:"body_bytes"`
	Concurrent     int `json:"concurrent"`
	ChunkBytes     int `json:"chunk_bytes"`
	TransferWindow int `json:"transfer_window"`
}
type TransportCapabilities struct {
	StreamSchemaVersion   int             `json:"stream_schema_version,omitempty"`
	SchemaVersion         int             `json:"schema_version"`
	Profile               string          `json:"profile"`
	SessionID             string          `json:"session_id"`
	Revision              string          `json:"revision"`
	AuthorizationRevision uint64          `json:"authorization_revision"`
	ExpiresAt             time.Time       `json:"expires_at"`
	Operations            []string        `json:"operations"`
	QualifiedOperations   []string        `json:"qualified_operations"`
	Binding               *Binding        `json:"binding,omitempty"`
	Limits                TransportLimits `json:"limits"`
}
type SessionInfo struct {
	SessionID, Profile          string
	GrantRevision               uint64
	Binding                     *Binding
	Scopes, QualifiedOperations []string
	CheckAuthorization          func(context.Context) (iscpauth.Policy, error)
}
type sessionInfoKey struct{}

func SessionFromContext(ctx context.Context) (SessionInfo, bool) {
	s, ok := ctx.Value(sessionInfoKey{}).(SessionInfo)
	s.Scopes = slices.Clone(s.Scopes)
	s.QualifiedOperations = slices.Clone(s.QualifiedOperations)
	if s.Binding != nil {
		b := *s.Binding
		s.Binding = &b
	}
	return s, ok
}
func (e *Endpoint) CheckAuthorization(ctx context.Context) error {
	_, err := e.AuthorizationPolicy(ctx)
	return err
}
func (e *Endpoint) AuthorizationPolicy(ctx context.Context) (iscpauth.Policy, error) {
	if e.authorityPolicy != nil {
		p, err := e.authorityPolicy(ctx)
		e.observeAuthorizationError(err)
		return p, err
	}
	if err := verifyGrant(e.config, e.grantMaterial(), time.Now().UTC()); err != nil {
		return iscpauth.Policy{}, err
	}
	if e.lifecycle == nil {
		return iscpauth.Policy{Version: 1, Lifetime: iscpauth.Bounded, Revision: e.grantMaterial().grant.RevocationEpoch, State: iscpauth.Active}, nil
	}
	p, err := e.lifecycle.AuthorizationPolicy(ctx)
	e.observeAuthorizationError(err)
	return p, err
}
func (e *Endpoint) Negotiated() (TransportCapabilities, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session == nil || e.session.capabilities == nil || !time.Now().Before(e.session.capabilities.ExpiresAt) {
		return TransportCapabilities{}, false
	}
	c := *e.session.capabilities
	c.Operations = slices.Clone(c.Operations)
	c.QualifiedOperations = slices.Clone(c.QualifiedOperations)
	if c.Binding != nil {
		b := *c.Binding
		c.Binding = &b
	}
	return c, true
}
func (e *Endpoint) SetCapabilitiesHandler(handler func(TransportCapabilities)) {
	e.mu.Lock()
	e.onCapabilities = handler
	e.mu.Unlock()
}
func (c Config) supportsV2() bool { return slices.Contains(c.ApplicationProfiles, ProfileV2) }

type negotiationOffer struct {
	Negotiation struct {
		Profiles            []string `json:"profiles"`
		UnboundedRPC        bool     `json:"unbounded_rpc,omitempty"`
		ExecutionProgress   bool     `json:"execution_progress,omitempty"`
		StreamSchemaVersion int      `json:"stream_schema_version,omitempty"`
	} `json:"transport_negotiation"`
}
type negotiationReply struct {
	Negotiation *TransportCapabilities `json:"transport_negotiation"`
}

func negotiationRequest(r Request) bool {
	var fields map[string]json.RawMessage
	if r.Operation != OperationIdentity || json.Unmarshal(r.Body, &fields) != nil {
		return false
	}
	_, ok := fields["transport_negotiation"]
	return ok
}
func (e *Endpoint) capabilitiesFor(id string, profile string) TransportCapabilities {
	ops := Operations()
	version := 1
	if profile == ProfileV2 {
		ops = OperationsV2ForMode(e.config.Mode)
		if !slices.Contains(e.config.QualifiedCapabilities, OperationExecutionProgress) {
			ops = withoutProgress(ops)
		}
		version = 2
	}
	streamVersion := 0
	if profile == ProfileV2 {
		streamVersion = 1
	}
	return TransportCapabilities{StreamSchemaVersion: streamVersion, SchemaVersion: version, Profile: profile, SessionID: id, Revision: "2", AuthorizationRevision: e.grantMaterial().grant.RevocationEpoch, ExpiresAt: time.Now().UTC().Add(5 * time.Minute), Operations: ops, QualifiedOperations: slices.Clone(ops), Binding: e.config.Binding, Limits: TransportLimits{MaxRequestBytes, MaxResponseBytes, MaxBodyBytes, MaxConcurrent, 8192, 2}}
}
func (e *Endpoint) answerNegotiation(ctx context.Context, id string, r Request) error {
	var offer negotiationOffer
	if err := strictDecode(r.Body, &offer); err != nil || len(offer.Negotiation.Profiles) == 0 || len(offer.Negotiation.Profiles) > 2 {
		return e.sendResponse(ctx, id, Response{Profile: Profile, ID: r.ID, Status: 400, Error: "invalid transport negotiation"})
	}
	profile := Profile
	for _, p := range offer.Negotiation.Profiles {
		if p != Profile && p != ProfileV2 {
			return e.sendResponse(ctx, id, Response{Profile: Profile, ID: r.ID, Status: 400, Error: "unsupported transport profile"})
		}
	}
	if e.config.supportsV2() && slices.Contains(offer.Negotiation.Profiles, ProfileV2) {
		profile = ProfileV2
	}
	caps := e.capabilitiesFor(id, profile)
	if !offer.Negotiation.ExecutionProgress {
		caps.Operations = withoutProgress(caps.Operations)
		caps.QualifiedOperations = withoutProgress(caps.QualifiedOperations)
	}
	if offer.Negotiation.StreamSchemaVersion != 1 {
		caps.StreamSchemaVersion = 0
		caps.Operations = withoutStream(caps.Operations)
		caps.QualifiedOperations = withoutStream(caps.QualifiedOperations)
	}
	if offer.Negotiation.UnboundedRPC {
		caps.Limits.Concurrent = 0
	}
	body, _ := json.Marshal(negotiationReply{&caps})
	e.installCapabilities(caps)
	if err := e.sendResponse(ctx, id, Response{Profile: Profile, ID: r.ID, Status: 200, Body: body}); err != nil {
		return err
	}
	e.installCapabilities(caps)
	return nil
}
func (e *Endpoint) installCapabilities(c TransportCapabilities) {
	e.mu.Lock()
	if e.session == nil || e.session.id != c.SessionID {
		e.mu.Unlock()
		return
	}
	e.session.capabilities = &c
	e.session.negotiating = false
	notify := e.onCapabilities
	e.mu.Unlock()
	if notify != nil {
		notify(c)
	}
	e.setState("transport_ready")
}
func (e *Endpoint) negotiate(ctx context.Context, id string) {
	defer e.workers.Done()
	profiles := []string{Profile}
	if e.config.supportsV2() {
		profiles = []string{ProfileV2, Profile}
	}
	r, err := requestRPCNegotiation(ctx, e.Call, profiles)
	if err != nil {
		e.negotiationFailed(id)
		return
	}
	if r.Status == 400 || r.Status == 404 || r.Status == 501 {
		e.installCapabilities(e.capabilitiesFor(id, Profile))
		return
	}
	if r.Status != 200 {
		e.negotiationFailed(id)
		return
	}
	var reply negotiationReply
	if json.Unmarshal(r.Body, &reply) != nil || reply.Negotiation == nil {
		e.installCapabilities(e.capabilitiesFor(id, Profile))
		return
	}
	c := *reply.Negotiation
	if err := validateNegotiation(c, id, e.config.Mode); err != nil || c.AuthorizationRevision != e.grantMaterial().grant.RevocationEpoch || (e.config.Binding != nil && (c.Binding == nil || *c.Binding != *e.config.Binding)) {
		e.negotiationFailed(id)
		return
	}
	e.installCapabilities(c)
}

func requestRPCNegotiation(ctx context.Context, caller func(context.Context, Request) (Response, error), profiles []string) (Response, error) {
	var offer negotiationOffer
	offer.Negotiation.Profiles = profiles
	offer.Negotiation.UnboundedRPC = true
	offer.Negotiation.ExecutionProgress = slices.Contains(profiles, ProfileV2)
	if offer.Negotiation.ExecutionProgress {
		offer.Negotiation.StreamSchemaVersion = 1
	}
	call := func() (Response, error) {
		body, _ := json.Marshal(offer)
		return caller(ctx, Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity, Body: body})
	}
	r, err := call()
	// Each retry is only the read-only negotiation, never a user operation.
	// First keep unbounded RPC support when a peer predates progress.
	if err == nil && offer.Negotiation.ExecutionProgress && (r.Status == 400 || r.Status == 404 || r.Status == 501) {
		offer.Negotiation.ExecutionProgress = false
		offer.Negotiation.StreamSchemaVersion = 0
		r, err = call()
	}
	// Older bounded peers require the original offer shape.
	if err == nil && (r.Status == 400 || r.Status == 404 || r.Status == 501) {
		offer.Negotiation.UnboundedRPC = false
		r, err = call()
	}
	return r, err
}
func validateNegotiation(c TransportCapabilities, id string, mode ...string) error {
	version := 1
	ops := Operations()
	if c.Profile == ProfileV2 {
		version = 2
		ops = OperationsV2()
	} else if c.Profile != Profile {
		return errors.New("incompatible selected profile")
	}
	now := time.Now()
	compatible := slices.Equal(c.Operations, ops)
	if c.Profile == ProfileV2 {
		compatible = compatible || slices.Equal(c.Operations, withoutProgress(ops)) || slices.Equal(c.Operations, withoutStream(ops)) || slices.Equal(c.Operations, withoutStream(withoutProgress(ops)))
	}
	if c.Profile == ProfileV2 && (len(mode) == 0 || mode[0] != "node-managed") {
		localOps := OperationsV2ForMode("local-test")
		compatible = compatible || slices.Equal(c.Operations, localOps) || slices.Equal(c.Operations, withoutProgress(localOps)) || slices.Equal(c.Operations, withoutStream(localOps)) || slices.Equal(c.Operations, withoutStream(withoutProgress(localOps)))
	}
	expectedLimits := TransportLimits{MaxRequestBytes, MaxResponseBytes, MaxBodyBytes, c.Limits.Concurrent, 8192, 2}
	// Original v1 Grants predate revocation epochs. negotiate still binds this
	// value to the verified Grant; v2 requires a nonzero authorization revision.
	if c.SessionID != id || c.SchemaVersion != version || c.Revision != "2" || (c.Profile == ProfileV2 && c.AuthorizationRevision == 0) || !c.ExpiresAt.After(now) || c.ExpiresAt.After(now.Add(6*time.Minute)) || !compatible || (c.Limits.Concurrent != 0 && c.Limits.Concurrent != MaxConcurrent) || c.Limits != expectedLimits {
		return errors.New("invalid negotiated capability binding")
	}
	if (slices.Contains(c.Operations, OperationExecutionProgressStream) && c.StreamSchemaVersion != 1) || (!slices.Contains(c.Operations, OperationExecutionProgressStream) && c.StreamSchemaVersion != 0) {
		return errors.New("incompatible stream schema")
	}
	for _, name := range c.QualifiedOperations {
		if !slices.Contains(ops, name) || (name == OperationExecutionProgress && !slices.Contains(c.Operations, name)) {
			return errors.New("unregistered qualified operation")
		}
	}
	return nil
}

func (e *Endpoint) negotiationFailed(id string) {
	e.mu.Lock()
	current := e.session != nil && e.session.id == id
	if current {
		e.session.negotiating = false
		e.session.nextNegotiationAt = time.Now().Add(5 * time.Second)
	}
	e.mu.Unlock()
	if current {
		e.setState("capability_negotiation_failed")
	}
}

// Progress is an optional extension of the original exact v2 registry.
func withoutProgress(ops []string) []string {
	return slices.DeleteFunc(slices.Clone(ops), func(op string) bool { return op == OperationExecutionProgress })
}

func withoutStream(ops []string) []string {
	return slices.DeleteFunc(slices.Clone(ops), func(op string) bool { return op == OperationExecutionProgressStream })
}
