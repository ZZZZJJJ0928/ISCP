package iscpworkbench

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/appstream"
	"slices"
	"sync"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/internal/latencytrace"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
)

const (
	manifestType       = "sparkclaw.workbench.capability.v1"
	pingType           = "sparkclaw.workbench.ping.v1"
	pongType           = "sparkclaw.workbench.pong.v1"
	requestTimeout     = 30 * time.Second
	handshakeTimeout   = 10 * time.Second
	heartbeatInterval  = 10 * time.Second
	heartbeatTimeout   = 35 * time.Second
	maxSessionMessages = 4096
)

// RelayTransport is injectable for encrypted integration tests. Runtime
// construction still requires pinned identities, private files and HTTPS/WSS;
// no configuration flag permits an insecure Relay transport.
type RelayTransport interface {
	Submit(context.Context, any) error
	RunOnceReady(context.Context, func(context.Context, json.RawMessage) error, func()) error
}

type capabilityManifest struct {
	Profile          string   `json:"profile"`
	Role             string   `json:"role"`
	Operations       []string `json:"operations"`
	MaxRequestBytes  int      `json:"max_request_bytes"`
	MaxResponseBytes int      `json:"max_response_bytes"`
	MaxConcurrent    int      `json:"max_concurrent"`
}

type activeSession struct {
	streamAuthority                 *streamAuthority
	streams                         map[string]*pendingStream
	streamSenders                   map[string]*streamSender
	streamCancels                   map[string]time.Time
	id                              string
	local                           session.LocalHello
	state                           *session.State
	manifest                        bool
	capabilities                    *TransportCapabilities
	negotiating                     bool
	nextNegotiationAt               time.Time
	started, timeReceived, timePing time.Time
	messageCount                    int
	cancel                          context.CancelFunc
	ctx                             context.Context
	seenRequests                    map[string]struct{}
	sentRequests                    map[string]struct{}
}

type callResult struct {
	response Response
	err      error
}

type pendingCall struct {
	result          chan callResult
	ctx             context.Context
	responseStarted bool
	trace           latencytrace.Fields
}

type Endpoint struct {
	config               Config
	material             material
	provider             iscpcrypto.Provider
	relay                RelayTransport
	authorityPolicy      func(context.Context) (iscpauth.Policy, error)
	handler              Handler
	onState              func(string)
	onCapabilities       func(TransportCapabilities)
	mu                   sync.Mutex
	grantMu              sync.RWMutex
	renewalMu            sync.Mutex
	lifecycle            grantLifecycle
	lifecycleWorkers     sync.WaitGroup
	session              *activeSession
	stale                []string
	pending              map[string]*pendingCall
	stateName            string
	lastHelloAt          time.Time
	cancel               context.CancelFunc
	running, closed      bool
	authorizationRevoked bool
	slots                chan struct{}
	classSlots           map[string]chan struct{}
	workers              sync.WaitGroup
	verifyDiscovery      func(context.Context) error
}

func NewEndpoint(cfg Config, handler Handler, onState func(string)) (*Endpoint, error) {
	m, err := loadMaterial(cfg)
	if err != nil {
		return nil, err
	}
	relay, err := iscpbridge.NewRelayCredentialClient(cfg.EffectiveRelayProfile(), cfg.EnrollmentFile, m.enrollment, m.device, requestTimeout)
	if err != nil {
		return nil, errors.New("create workbench Relay transport")
	}
	e, err := newEndpoint(cfg, m, relay, handler, onState)
	if err == nil {
		e.verifyDiscovery = func(ctx context.Context) error {
			return iscpbridge.VerifyWorkbenchRelayDiscovery(ctx, cfg.EffectiveRelayProfile(), m.enrollment)
		}
	}
	return e, err
}

func NewEndpointWithRelay(cfg Config, relay RelayTransport, handler Handler, onState func(string)) (*Endpoint, error) {
	m, err := loadMaterial(cfg)
	if err != nil {
		return nil, err
	}
	return newEndpoint(cfg, m, relay, handler, onState)
}

func newEndpoint(cfg Config, m material, relay RelayTransport, handler Handler, onState func(string)) (*Endpoint, error) {
	if relay == nil {
		return nil, errors.New("workbench Relay transport is required")
	}
	if cfg.Role == RoleResponder && handler == nil {
		return nil, errors.New("workbench responder requires a handler")
	}
	e := &Endpoint{config: cfg, material: m, provider: iscpcrypto.NewProvider(), relay: relay, handler: handler, onState: onState, pending: map[string]*pendingCall{}, slots: make(chan struct{}, MaxConcurrent), classSlots: map[string]chan struct{}{"control": make(chan struct{}, CapacityLimit("control")), "bulk": make(chan struct{}, CapacityLimit("bulk")), "events": make(chan struct{}, CapacityLimit("events")), "audio": make(chan struct{}, CapacityLimit("audio"))}}
	if sender, ok := relay.(interface{ SetSessionUsable(func(string) bool) }); ok {
		sender.SetSessionUsable(func(id string) bool {
			e.mu.Lock()
			defer e.mu.Unlock()
			return !e.closed && e.session != nil && e.session.id == id && e.session.state != nil && e.session.state.Ready() && e.session.ctx.Err() == nil
		})
	}
	if cfg.Mode == "node-managed" && cfg.Role == RoleInitiator {
		client, err := newNodeLifecycle(cfg, m)
		if err != nil {
			return nil, err
		}
		e.lifecycle = client
	}
	if cfg.GrantRenewal != nil {
		client, err := iscpbridge.NewGrantLifecycleClient(cfg.GrantRenewal.URL, cfg.GrantRenewal.PendingFile, m.device, m.issuer, m.enrollment.RelayID, m.grant, 5*time.Second)
		if err != nil {
			return nil, err
		}
		e.lifecycle = client
		if cfg.GrantRenewal.AuthorizationLifetime == iscpauth.UntilRevoked {
			client.RequireStandingAuthorization()
		}
	}
	if cfg.Role == RoleResponder && (cfg.EffectiveRelayProfile() == iscpbridge.ProfileLocalLab || cfg.Mode == "node-managed") {
		// The isolated reference queue outlives a Gateway process. A Hello
		// predating this responder cannot recover keys from its old process;
		// let the desktop's bounded retry initiate a fresh session instead.
		e.lastHelloAt = time.Now().UTC().Add(-time.Second)
	}
	return e, nil
}

func (e *Endpoint) setState(state string) {
	e.setStateForSession(state, nil, false)
}

func (e *Endpoint) setStateForSession(state string, expected *activeSession, checkSession bool) {
	e.mu.Lock()
	if (checkSession && e.session != expected) || (e.closed && state != "closed") || (e.authorizationRevoked && state != "authorization_revoked" && state != "closed") {
		e.mu.Unlock()
		return
	}
	changed := e.stateName != state
	e.stateName = state
	e.mu.Unlock()
	if changed && e.onState != nil {
		e.onState(state)
	}
}

// Run owns the authenticated receive connection and retries with bounded
// backoff. Every reconnect discards old keys and causes a fresh desktop Hello.
func (e *Endpoint) Run(ctx context.Context) error {
	ctx = latencytrace.WithFields(ctx, latencytrace.Fields{Role: e.config.Role})
	e.mu.Lock()
	if e.running || e.closed {
		e.mu.Unlock()
		return errors.New("workbench endpoint is already running or closed")
	}
	ctx, cancel := context.WithCancel(ctx)
	e.cancel, e.running = cancel, true
	e.mu.Unlock()
	defer func() {
		cancel()
		e.lifecycleWorkers.Wait()
		e.mu.Lock()
		e.resetLocked()
		e.mu.Unlock()
		e.workers.Wait()
		e.setState("disconnected")
	}()
	if e.lifecycle != nil {
		_ = e.refreshAuthorization(ctx)
		e.lifecycleWorkers.Add(1)
		go func() { defer e.lifecycleWorkers.Done(); e.runGrantLifecycle(ctx) }()
	}
	backoff := time.Second
	for ctx.Err() == nil {
		if e.verifyDiscovery != nil {
			e.setState("verifying_relay")
			if err := e.verifyDiscovery(ctx); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				e.setState("discovery_failed")
				timer := time.NewTimer(backoff)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
				backoff = min(backoff*2, 15*time.Second)
				continue
			}
		}
		e.setState("connecting")
		connCtx, stop := context.WithCancel(ctx)
		var monitor sync.WaitGroup
		err := e.relay.RunOnceReady(connCtx, func(callCtx context.Context, raw json.RawMessage) error { return e.receive(callCtx, raw) }, func() {
			e.setState("relay_ready")
			monitor.Add(1)
			go func() { defer monitor.Done(); e.sessionLoop(connCtx, stop) }()
		})
		stop()
		monitor.Wait()
		e.mu.Lock()
		e.resetLocked()
		e.mu.Unlock()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if recoveryErr := e.recoverLiveNodeTransport(ctx); recoveryErr != nil {
			e.observeAuthorizationError(recoveryErr)
		}
		e.setState("disconnected")
		if err == nil {
			backoff = time.Second
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		backoff = min(backoff*2, 15*time.Second)
	}
	return ctx.Err()
}

func (e *Endpoint) sessionLoop(ctx context.Context, stopConnection context.CancelFunc) {
	if e.config.Role == RoleInitiator {
		_ = e.initiate(ctx)
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := verifyGrant(e.config, e.grantMaterial(), now.UTC()); err != nil {
				e.mu.Lock()
				e.resetLocked()
				e.mu.Unlock()
				e.setState("authorization_expired")
				continue
			}
			e.mu.Lock()
			s := e.session
			missing := s == nil
			timedOut := s != nil && ((!s.manifest && now.Sub(s.started) > handshakeTimeout) || (s.manifest && now.Sub(s.timeReceived) > heartbeatTimeout))
			if timedOut {
				e.resetLocked()
				s = nil
				missing = true
			}
			refresh := s != nil && s.manifest && !s.negotiating && !now.Before(s.nextNegotiationAt) && (s.capabilities == nil || (s.capabilities.Profile == ProfileV2 || s.capabilities.Limits.Concurrent == 0) && time.Until(s.capabilities.ExpiresAt) < 3*time.Minute) && e.config.Role == RoleInitiator
			if refresh {
				s.negotiating = true
			}
			ping := s != nil && s.manifest && now.Sub(s.timePing) >= heartbeatInterval
			if ping {
				s.timePing = now
			}
			e.mu.Unlock()
			if refresh {
				e.workers.Add(1)
				go e.negotiate(ctx, s.id)
			}
			if timedOut {
				e.setState("disconnected")
				// An authenticated but stalled receive socket must be replaced;
				// repeatedly posting Hello cannot repair that WebSocket stream.
				stopConnection()
				return
			}
			if missing && e.config.Role == RoleInitiator {
				_ = e.initiate(ctx)
			}
			if ping {
				raw, _ := json.Marshal(map[string]string{"nonce": newUUID()})
				_ = e.sendPayload(ctx, pingType, raw, s.id)
			}
		}
	}
}

func (e *Endpoint) initiate(ctx context.Context) error {
	if err := e.checkAuthorization(ctx); err != nil {
		return err
	}
	m := e.grantMaterial()
	if err := verifyGrant(e.config, m, time.Now().UTC()); err != nil {
		e.setState("authorization_expired")
		return err
	}
	id := newUUID()
	local, err := session.CreateHello(e.provider, m.device, id, m.peer.DeviceID, m.grant.GrantID, time.Now().UTC())
	if err != nil {
		return errors.New("create workbench Hello")
	}
	e.mu.Lock()
	e.resetLocked()
	e.session = newSession(ctx, id, local)
	e.mu.Unlock()
	e.setState("handshaking")
	return e.sendHandshake(ctx, id, session.TypeHello, local.Hello)
}

func newSession(ctx context.Context, id string, local session.LocalHello) *activeSession {
	ctx, cancel := context.WithCancel(ctx)
	now := time.Now().UTC()
	return &activeSession{streams: map[string]*pendingStream{}, streamSenders: map[string]*streamSender{}, streamCancels: map[string]time.Time{}, id: id, local: local, ctx: ctx, cancel: cancel, started: now, timeReceived: now, timePing: now, seenRequests: map[string]struct{}{}, sentRequests: map[string]struct{}{}}
}

// resetLocked must hold mu; pending calls fail immediately instead of waiting
// for a response that belongs to discarded session keys.
func (e *Endpoint) resetLocked() {
	if e.session != nil {
		e.stopStreamsLocked(e.session, errors.New("workbench session disconnected"))
		e.session.cancel()
		e.stale = append(e.stale, e.session.id)
		if len(e.stale) > 64 {
			e.stale = e.stale[len(e.stale)-64:]
		}
		e.session = nil
	}
	for id, call := range e.pending {
		call.result <- callResult{err: errors.New("workbench session disconnected")}
		delete(e.pending, id)
	}
}

func (e *Endpoint) sendHandshake(ctx context.Context, id, payloadType string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return errors.New("encode workbench handshake")
	}
	b := e.material.enrollment
	env := envelope.SecureEnvelope{Type: envelope.TypeSecureEnvelope, DomainID: b.DomainID, MessageID: newUUID(), SessionID: id, SenderDeviceID: b.DeviceID, RecipientDeviceID: e.material.peer.DeviceID, PayloadType: payloadType, Nonce: iscpcrypto.Base64URL(randomBytes(12)), Route: envelope.Route{RelayID: b.RelayID, TTLSeconds: 30, Priority: 5}, Ciphertext: base64.RawURLEncoding.EncodeToString(raw)}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if err := e.relay.Submit(ctx, env); err != nil {
		return errors.New("submit workbench handshake")
	}
	return nil
}

func (e *Endpoint) receive(ctx context.Context, raw json.RawMessage) error {
	if len(raw) > 100<<10 {
		return errors.New("workbench envelope exceeds limit")
	}
	var env envelope.SecureEnvelope
	if err := strictDecode(raw, &env); err != nil {
		return errors.New("invalid workbench envelope")
	}
	b := e.material.enrollment
	if env.Type != envelope.TypeSecureEnvelope || env.DomainID != b.DomainID || env.SenderDeviceID != e.material.peer.DeviceID || env.RecipientDeviceID != b.DeviceID || env.Route.RelayID != b.RelayID || env.Route.TTLSeconds <= 0 || env.Route.TTLSeconds > 30 || !uuidPattern.MatchString(env.SessionID) || !uuidPattern.MatchString(env.MessageID) {
		return errors.New("workbench envelope identity or route mismatch")
	}
	if err := verifyGrant(e.config, e.grantMaterial(), time.Now().UTC()); err != nil {
		return err
	}
	switch env.PayloadType {
	case session.TypeHello:
		if e.config.Role == RoleInitiator && !e.matchesSession(env.SessionID) {
			return nil
		}
		return e.acceptHello(ctx, env)
	case session.TypeReady:
		if !e.matchesSession(env.SessionID) {
			return nil
		}
		return e.acceptReady(ctx, env)
	case manifestType, RequestType, ResponseType, pingType, pongType, appstream.Type, appstream.ControlType:
		if !e.matchesSession(env.SessionID) {
			return nil
		}
		return e.acceptEncrypted(ctx, env)
	default:
		return errors.New("unsupported workbench payload type")
	}
}

// Queue retention is independent of process/session lifetime. Unknown or
// retired sessions are discarded without decrypting, updating readiness or
// calling business handlers; they must not abort a drain snapshot that also
// contains the fresh peer handshake. Current-session failures still reject.
func (e *Endpoint) matchesSession(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.session != nil && e.session.id == id
}

func handshakeDecode(env envelope.SecureEnvelope, value any) error {
	if env.Sequence != 0 {
		return errors.New("invalid handshake envelope sequence")
	}
	raw, err := base64.RawURLEncoding.DecodeString(env.Ciphertext)
	if err != nil || len(raw) > 8<<10 {
		return errors.New("invalid handshake encoding")
	}
	return strictDecode(raw, value)
}

func (e *Endpoint) acceptHello(ctx context.Context, env envelope.SecureEnvelope) error {
	if err := e.checkAuthorization(ctx); err != nil {
		return err
	}
	var hello session.Hello
	if err := handshakeDecode(env, &hello); err != nil {
		return errors.New("invalid workbench Hello")
	}
	now := time.Now().UTC()
	if hello.SessionID != env.SessionID || hello.PeerDeviceID != e.material.device.Identity.DeviceID || hello.Signature.Alg != "Ed25519" || hello.Signature.KID != e.material.peer.PublicKey.KID || hello.IssuedAt.Sub(now) > 30*time.Second {
		return errors.New("workbench Hello binding or freshness mismatch")
	}
	if err := session.VerifyHello(e.provider, hello, e.material.peer); err != nil {
		return errors.New("workbench Hello signature verification failed")
	}
	if now.Sub(hello.IssuedAt) > handshakeTimeout {
		return nil
	}
	if e.config.Role == RoleResponder && hello.GrantID != e.grantMaterial().grant.GrantID && e.lifecycle != nil {
		// A newly renewed initiator can arrive before the periodic current-
		// grant poll. Only the already verified, fresh peer Hello triggers it.
		_ = e.refreshAuthorization(ctx)
	}
	e.mu.Lock()
	if slices.Contains(e.stale, env.SessionID) {
		e.mu.Unlock()
		return nil
	}
	var local session.LocalHello
	var err error
	if e.config.Role == RoleResponder {
		if hello.GrantID != e.grantMaterial().grant.GrantID {
			e.mu.Unlock()
			return errors.New("workbench initiator grant ID mismatch")
		}
		if e.session != nil && e.session.id == env.SessionID {
			e.mu.Unlock()
			return nil
		}
		if !hello.IssuedAt.After(e.lastHelloAt) {
			e.mu.Unlock()
			return nil
		}
		local, err = session.CreateHello(e.provider, e.material.device, env.SessionID, e.material.peer.DeviceID, "", now)
		if err != nil {
			e.mu.Unlock()
			return errors.New("create workbench responder Hello")
		}
		e.resetLocked()
		e.session = newSession(ctx, env.SessionID, local)
		e.lastHelloAt = hello.IssuedAt
	} else {
		if e.session == nil || e.session.id != env.SessionID || e.session.state != nil {
			e.mu.Unlock()
			return nil
		}
		if hello.GrantID != "" {
			e.mu.Unlock()
			return errors.New("unexpected responder workbench Hello")
		}
		local = e.session.local
	}
	state, err := session.Establish(e.provider, local, hello, e.material.device.Identity, e.material.peer)
	if err != nil {
		e.mu.Unlock()
		return errors.New("establish workbench session")
	}
	ready, err := state.CreateReady(e.provider, e.material.device)
	if err != nil {
		e.mu.Unlock()
		return errors.New("create workbench Ready")
	}
	e.session.state = state
	e.mu.Unlock()
	e.setState("handshaking")
	if e.config.Role == RoleResponder {
		if err := e.sendHandshake(ctx, env.SessionID, session.TypeHello, local.Hello); err != nil {
			return err
		}
	}
	return e.sendHandshake(ctx, env.SessionID, session.TypeReady, ready)
}

func (e *Endpoint) acceptReady(ctx context.Context, env envelope.SecureEnvelope) error {
	var ready session.Ready
	if err := handshakeDecode(env, &ready); err != nil {
		return errors.New("invalid workbench Ready")
	}
	if ready.Signature.Alg != "Ed25519" || ready.Signature.KID != e.material.peer.PublicKey.KID {
		return errors.New("workbench Ready signing key mismatch")
	}
	if ready.SessionID != env.SessionID {
		return errors.New("workbench Ready envelope binding mismatch")
	}
	e.mu.Lock()
	s := e.session
	if s == nil || s.id != env.SessionID {
		e.mu.Unlock()
		return nil
	}
	if s.state == nil {
		e.mu.Unlock()
		return errors.New("unexpected or replayed workbench Ready")
	}
	if s.state.Ready() || ready.TranscriptHash != iscpcrypto.Base64URL(s.state.TranscriptHash) {
		e.mu.Unlock()
		return nil
	}
	if err := s.state.VerifyReady(e.provider, ready, e.material.peer); err != nil {
		e.mu.Unlock()
		return errors.New("workbench Ready verification failed")
	}
	e.mu.Unlock()
	manifest := capabilityManifest{Profile: Profile, Role: e.config.Role, Operations: Operations(), MaxRequestBytes: MaxRequestBytes, MaxResponseBytes: MaxResponseBytes, MaxConcurrent: MaxConcurrent}
	raw, _ := json.Marshal(manifest)
	return e.sendPayload(ctx, manifestType, raw, env.SessionID)
}

func (e *Endpoint) sendPayload(ctx context.Context, payloadType string, raw []byte, id string) error {
	wait, err := e.enqueuePayload(ctx, payloadType, raw, id)
	if err != nil {
		return err
	}
	return wait(ctx)
}
func (e *Endpoint) enqueuePayload(ctx context.Context, payloadType string, raw []byte, id string) (func(context.Context) error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if (payloadType == RequestType || payloadType == ResponseType) && ctx.Value(streamSendContextKey{}) == nil {
		started := latencytrace.Clock()
		err := e.checkAuthorization(ctx)
		latencytrace.Record(ctx, "rpc.send_authorization", started, err, 0)
		if err != nil {
			return nil, err
		}
	}
	if len(raw) > MaxMessageBytes {
		return nil, errors.New("workbench payload exceeds limit")
	}
	if err := verifyGrant(e.config, e.grantMaterial(), time.Now().UTC()); err != nil {
		return nil, err
	}
	e.mu.Lock()
	s := e.session
	if e.closed || s == nil || s.id != id || s.state == nil || !s.state.Ready() || (payloadType != manifestType && !s.manifest) {
		e.mu.Unlock()
		return nil, errors.New("workbench encrypted session is not ready")
	}
	if auth, ok := ctx.Value(streamSendContextKey{}).(streamSendAuthorization); ok && (!e.streamAuthorityValidLocked(auth.session, auth.generation) || auth.session != s) {
		e.mu.Unlock()
		return nil, errStreamAuthority
	}
	priority := 5
	if class, ok := ctx.Value(capacityContextKey{}).(string); ok {
		priority = capacityPriority(class)
	}
	if (payloadType == pingType || payloadType == pongType) && s.capabilities != nil && s.capabilities.Profile == ProfileV2 {
		priority = 9
	}
	env, err := envelope.Encrypt(e.provider, s.state, newUUID(), payloadType, envelope.Route{RelayID: e.material.enrollment.RelayID, TTLSeconds: 30, Priority: priority}, raw)

	if err != nil {
		e.mu.Unlock()
		return nil, fmt.Errorf("encrypt workbench payload: %w", err)
	}
	var wait func(context.Context) error
	if sender, ok := e.relay.(interface {
		Enqueue(context.Context, any) (*iscpbridge.ReceiptFuture, error)
	}); ok {
		future, err := sender.Enqueue(ctx, env)
		e.mu.Unlock()
		if err != nil {
			return nil, fmt.Errorf("enqueue encrypted workbench payload: %w", err)
		}
		wait = func(ctx context.Context) error { _, err := future.Wait(ctx); return err }
	} else {
		e.mu.Unlock()
		if err := e.relay.Submit(ctx, env); err != nil {
			return nil, fmt.Errorf("submit encrypted workbench payload: %w", err)
		}
		wait = func(context.Context) error { return nil }
	}
	return func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, requestTimeout)
		defer cancel()
		if err := wait(ctx); err != nil {
			return fmt.Errorf("submit encrypted workbench payload: %w", err)
		}
		return nil
	}, nil
}

func (e *Endpoint) acceptEncrypted(ctx context.Context, env envelope.SecureEnvelope) error {
	arrived := latencytrace.Clock()
	e.mu.Lock()
	s := e.session
	if s == nil || s.id != env.SessionID {
		e.mu.Unlock()
		return nil
	}
	notReady := s.state == nil || !s.state.Ready()
	if notReady || (env.PayloadType != manifestType && !s.manifest) {
		e.mu.Unlock()
		if e.config.EffectiveRelayProfile() == iscpbridge.ProfileLocalLab && e.config.Role == RoleResponder && notReady {
			return nil
		}
		return errors.New("workbench business payload received before verified manifest")
	}
	if err := authenticateEnvelope(e.provider, s.state, env); err != nil {
		e.mu.Unlock()
		return errors.New("workbench payload authentication failed")
	}
	raw, err := envelope.Decrypt(e.provider, s.state, env)
	if err != nil {
		e.mu.Unlock()
		return errors.New("workbench payload authentication or replay verification failed")
	}
	if len(raw) > MaxMessageBytes {
		e.mu.Unlock()
		return errors.New("workbench plaintext exceeds limit")
	}
	s.timeReceived = time.Now().UTC()
	sessionCtx := s.ctx
	e.mu.Unlock()
	switch env.PayloadType {
	case manifestType:
		return e.acceptManifest(raw, env.SessionID)
	case pingType, pongType:
		var ping struct {
			Nonce string `json:"nonce"`
		}
		if err := strictDecode(raw, &ping); err != nil || !uuidPattern.MatchString(ping.Nonce) {
			return errors.New("invalid workbench heartbeat")
		}
		if env.PayloadType == pingType {
			return e.sendPayload(ctx, pongType, raw, env.SessionID)
		}
		return nil
	case appstream.Type:
		return e.acceptStreamFrame(raw, env.SessionID)
	case appstream.ControlType:
		return e.acceptStreamControl(raw, env.SessionID)
	case ResponseType:
		return e.acceptResponse(sessionCtx, raw, env.SessionID, arrived)
	case RequestType:
		return e.acceptRequest(sessionCtx, raw, env.SessionID)
	}
	return errors.New("unsupported workbench business payload")
}

func (e *Endpoint) acceptManifest(raw []byte, id string) error {
	var manifest capabilityManifest
	if err := strictDecode(raw, &manifest); err != nil {
		return errors.New("invalid workbench manifest")
	}
	role := RoleResponder
	if e.config.Role == RoleResponder {
		role = RoleInitiator
	}
	if manifest.Profile != Profile || manifest.Role != role || !slices.Equal(manifest.Operations, Operations()) || manifest.MaxRequestBytes != MaxRequestBytes || manifest.MaxResponseBytes != MaxResponseBytes || manifest.MaxConcurrent != MaxConcurrent {
		return errors.New("incompatible workbench manifest")
	}
	e.mu.Lock()
	if e.session == nil || e.session.id != id || e.session.manifest {
		e.mu.Unlock()
		return errors.New("unexpected or replayed workbench manifest")
	}
	e.session.manifest = true
	negotiate := e.config.Role == RoleInitiator
	e.session.negotiating = negotiate
	ctx := e.session.ctx
	e.mu.Unlock()
	if negotiate {
		e.setState("negotiating")
		e.workers.Add(1)
		go e.negotiate(ctx, id)
	} else {
		e.installCapabilities(e.capabilitiesFor(id, Profile))
	}
	return nil
}

func (e *Endpoint) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	if e.cancel != nil {
		e.cancel()
	}
	e.resetLocked()
	e.mu.Unlock()
	e.setState("closed")
	return nil
}

func randomBytes(n int) []byte {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		panic("secure random unavailable")
	}
	return raw
}

func newUUID() string {
	raw := randomBytes(16)
	raw[6] = (raw[6] & 15) | 64
	raw[8] = (raw[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[:4], raw[4:6], raw[6:8], raw[8:10], raw[10:])
}

// RelaySubmissionStatus exposes recovery metadata without ciphertext to helper IPC.
func (e *Endpoint) RelaySubmissionStatus(messageID string) (iscpbridge.RelaySubmissionStatus, bool) {
	if source, ok := e.relay.(interface {
		SubmissionStatus(string) (iscpbridge.RelaySubmissionStatus, bool)
	}); ok {
		return source.SubmissionStatus(messageID)
	}
	return iscpbridge.RelaySubmissionStatus{}, false
}
