package iscpbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/gorilla/websocket"
)

// These errors retain the original admission key and session lineage across
// reconnects. Callers must use errors.As instead of interpreting error strings.
type UnknownAcceptance = duplex.Unknown
type RejectedSubmission = duplex.Rejected
type NotSent = duplex.NotSent
type RelaySubmission = duplex.Submission
type AcceptanceReceipt = duplex.Receipt

type ReceiptFuture struct {
	owner              *RelayClient
	sessionCheck       func(string) bool
	uncertain          bool
	Submission         RelaySubmission
	done               chan struct{}
	mu                 sync.Mutex
	result             *AcceptanceReceipt
	err                error
	written            bool
	completed          bool
	observedCredential relayCredentialObservation // guarded by socket.mu; captured at first wire write
}

func (f *ReceiptFuture) finish(r *AcceptanceReceipt, e error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.completed {
		return
	}
	f.result = r
	f.err = e
	f.completed = true
	close(f.done)
}
func (f *ReceiptFuture) Wait(ctx context.Context) (*AcceptanceReceipt, error) {
	select {
	case <-f.done:
	case <-ctx.Done():
	}
	f.mu.Lock()
	if f.completed {
		result, err, uncertain := f.result, f.err, f.uncertain
		f.mu.Unlock()
		if f.owner != nil {
			f.owner.acknowledgeRelayResult(f.Submission, uncertain)
		}
		return result, err
	}
	if !f.written {
		f.err = &NotSent{Cause: ctx.Err()}
		f.completed = true
		close(f.done)
		err := f.err
		f.mu.Unlock()
		return nil, err
	}
	f.uncertain = true
	f.mu.Unlock()
	if f.owner != nil {
		f.owner.markRelayUnknown(f.Submission)
	}
	return nil, &UnknownAcceptance{Submission: f.Submission, Cause: ctx.Err()}
}

type relayCredentialObservation struct {
	binding     CredentialBinding
	generation  CredentialGeneration
	accessToken string
}

func observeRelayCredential(lease CredentialLease) relayCredentialObservation {
	return relayCredentialObservation{lease.Binding, lease.CredentialGeneration, lease.Enrollment.Access.Token}
}

type relayRefreshHint struct {
	reason   CredentialInvalidationReason
	observed relayCredentialObservation
}

type relayWrite struct {
	frame  duplex.Frame
	future *ReceiptFuture
}
type relaySocket struct {
	owner         *RelayClient
	ws            *websocket.Conn
	ctx           context.Context
	cancel        context.CancelFunc
	ready         duplex.Frame
	pin           identity.DeviceIdentity
	epoch         ConnectionEpoch
	mu            sync.Mutex
	request       uint64
	lease         CredentialLease
	pending       map[string]*ReceiptFuture
	queued        map[*ReceiptFuture]int
	bytes         int
	reauthID      string
	reauthLease   CredentialLease
	reauthDone    chan struct{}
	data          chan relayWrite
	control       chan relayWrite
	changed       chan struct{}
	refresh       chan relayRefreshHint
	deliveries    chan json.RawMessage
	deliveryBytes int
	workers       sync.WaitGroup
}

func (c *RelayClient) Submit(ctx context.Context, value any) error {
	f, e := c.Enqueue(ctx, value)
	if e != nil {
		return e
	}
	_, e = f.Wait(ctx)
	return e
}

// Enqueue is deliberately short: it serializes encryption order at the caller,
// reserves bounded memory and queues a frame. No network or receipt wait occurs.
func (c *RelayClient) Enqueue(ctx context.Context, value any) (*ReceiptFuture, error) {
	if e := ctx.Err(); e != nil {
		return nil, &NotSent{Cause: e}
	}
	raw, e := json.Marshal(value)
	if e != nil {
		return nil, &NotSent{Cause: e}
	}
	var env envelope.SecureEnvelope
	if e = json.Unmarshal(raw, &env); e != nil {
		return nil, &NotSent{Cause: e}
	}
	if len(raw) > duplex.MaxEnvelopeBytes || env.MessageID == "" || env.Route.TTLSeconds <= 0 || env.Route.TTLSeconds > 86400 {
		return nil, &NotSent{Cause: errors.New("invalid Relay envelope")}
	}
	digest, e := duplex.Digest(json.RawMessage(raw))
	if e != nil {
		return nil, &NotSent{Cause: e}
	}
	c.socketMu.Lock()
	s := c.socket
	c.socketMu.Unlock()
	if s == nil {
		return nil, &NotSent{Cause: errors.New("Relay is not ready")}
	}
	sub := RelaySubmission{MessageID: env.MessageID, EnvelopeDigest: digest, HistoryID: s.ready.HistoryID, NotAfter: duplex.Timestamp(time.Now().Add(time.Duration(env.Route.TTLSeconds) * time.Second)), SessionID: env.SessionID, Envelope: raw}
	return s.enqueue(sub, false)
}

// Reconcile keeps the original deadline, digest, ciphertext and history. Absent
// is returned as a distinct status; this function never creates a new key.
func (c *RelayClient) Reconcile(ctx context.Context, sub RelaySubmission) (*ReceiptFuture, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	c.socketMu.Lock()
	s := c.socket
	c.socketMu.Unlock()
	if s == nil {
		return nil, &UnknownAcceptance{Submission: sub, Cause: errors.New("Relay is not ready")}
	}
	return s.enqueue(sub, true)
}

type AbsentSubmission struct{ Submission RelaySubmission }

func (e *AbsentSubmission) Error() string { return "Relay confirmed original admission absent" }
func (c *RelayClient) Resubmit(ctx context.Context, sub RelaySubmission) (*ReceiptFuture, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	c.socketMu.Lock()
	s := c.socket
	c.socketMu.Unlock()
	if s == nil {
		return nil, &NotSent{Cause: errors.New("Relay is not ready")}
	}
	if !time.Now().Before(duplex.Time(sub.NotAfter)) {
		return nil, &RejectedSubmission{Code: "deadline_elapsed", Submission: sub}
	}
	return s.enqueue(sub, false)
}
func (s *relaySocket) enqueue(sub RelaySubmission, query bool) (*ReceiptFuture, error) {
	return s.enqueueWithSession(sub, query, nil)
}
func (s *relaySocket) enqueueWithSession(sub RelaySubmission, query bool, check func(string) bool) (*ReceiptFuture, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return nil, &NotSent{Cause: s.ctx.Err()}
	}
	if sub.HistoryID != s.ready.HistoryID {
		return nil, &UnknownAcceptance{Submission: sub, Cause: errors.New("Relay history changed")}
	}
	if s.request == ^uint64(0) {
		return nil, &NotSent{Cause: errors.New("Relay request counter exhausted")}
	}
	f := duplex.Frame{V: 1, Kind: "submit", ConnectionID: s.ready.ConnectionID, OwnerGeneration: s.ready.OwnerGeneration, RequestID: "2", HistoryID: sub.HistoryID, MessageID: sub.MessageID, EnvelopeDigest: sub.EnvelopeDigest, NotAfter: sub.NotAfter, Envelope: sub.Envelope}
	if query {
		f.Kind = "submit.query"
		f.Envelope = nil
	}
	raw, e := duplex.Encode(f)
	if e != nil {
		return nil, &NotSent{Cause: e}
	}
	if s.bytes+len(raw) > 8*duplex.MaxFrameBytes {
		return nil, &NotSent{Cause: errors.New("Relay send queue exhausted")}
	}
	future := &ReceiptFuture{owner: s.owner, sessionCheck: check, Submission: sub, done: make(chan struct{})}
	select {
	case s.data <- relayWrite{frame: f, future: future}:
		s.queued[future] = len(raw)
		s.bytes += len(raw)
		return future, nil
	default:
		return nil, &NotSent{Cause: errors.New("Relay send queue exhausted")}
	}
}
func (c *RelayClient) runSocketOnce(ctx context.Context, handle func(context.Context, json.RawMessage) error, onReady func()) error {
	return c.RunOnceReady(ctx, handle, onReady)
}
func (c *RelayClient) RunOnce(ctx context.Context, handle func(context.Context, json.RawMessage) error) error {
	return c.RunOnceReady(ctx, handle, nil)
}
func (c *RelayClient) RunOnceReady(ctx context.Context, handle func(context.Context, json.RawMessage) error, onReady func()) error {
	c.socketMu.Lock()
	if c.running {
		c.socketMu.Unlock()
		return errors.New("Relay socket already running")
	}
	c.running = true
	c.connectionEpoch++
	epoch := c.connectionEpoch
	c.socketMu.Unlock()
	defer func() { c.socketMu.Lock(); c.running = false; c.socket = nil; c.socketMu.Unlock() }()
	if e := c.initRelayJournal(); e != nil {
		return e
	}
	if e := c.ensureAccess(ctx); e != nil {
		return e
	}
	bundle := c.Enrollment()
	pin, e := c.duplexDiscovery(ctx, bundle)
	if e != nil {
		return e
	}
	d := websocket.Dialer{HandshakeTimeout: c.timeout, Subprotocols: []string{duplex.Protocol}, Proxy: http.ProxyFromEnvironment}
	if c.profile == ProfileLocalLab {
		d.Proxy = nil
	} else if bundle.Mode == BundleModeWorkbenchNodeManaged {
		d.TLSClientConfig, e = VerifiedTLSConfig(bundle.TLSCertificatePEM)
		d.Proxy = nil
		if e != nil {
			return e
		}
	}
	ws, res, e := d.DialContext(ctx, bundle.RelayWebSocketURL, nil)
	if e != nil {
		if res != nil {
			return &relayHTTPError{status: res.StatusCode}
		}
		return fmt.Errorf("connect Relay: %w", e)
	}
	defer ws.Close()
	if ws.Subprotocol() != duplex.Protocol {
		return errors.New("Relay selected wrong subprotocol")
	}
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(life, func() { ws.Close() })
	defer stop()
	ws.SetReadLimit(duplex.MaxFrameBytes)
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	challenge, e := readDuplex(ws)
	if e != nil {
		return e
	}
	limits := duplex.DefaultLimits()
	if challenge.Kind != "challenge" || challenge.RelayID != bundle.RelayID || challenge.DomainID != bundle.DomainID || challenge.Limits == nil || *challenge.Limits != limits || !time.Now().Before(duplex.Time(challenge.ExpiresAt)) {
		return errors.New("Relay challenge binding mismatch")
	}
	h, e := duplex.AuthChallenge(challenge, "authenticate", "1", "0", bundle.Access.Token, c.device.Identity)
	if e != nil {
		return e
	}
	proof, e := c.device.CreateProof(c.provider, bundle.RelayID, h, duplex.RandomID(), time.Now().UTC().Truncate(time.Second))
	if e != nil {
		return e
	}
	auth := duplex.Frame{V: 1, Kind: "authenticate", ConnectionID: challenge.ConnectionID, RequestID: "1", ChallengeID: challenge.ChallengeID, AccessToken: bundle.Access.Token, Proof: &proof}
	if e = writeDuplex(ws, auth); e != nil {
		return e
	}
	ready, e := readDuplex(ws)
	if e != nil {
		return e
	}
	if ready.Kind == "closing" && ready.Code == "authentication_failed" && ready.ConnectionID == challenge.ConnectionID && ready.OwnerGeneration == "0" && c.profile == ProfileLocalLab && bundle.Mode == BundleModeWorkbenchLocalLab && c.CredentialProvider() == nil {
		if err := c.refreshRejectedAccess(life, bundle.Access.Token); err != nil {
			return fmt.Errorf("Relay rejected access; original refresh failed: %w", err)
		}
		return errors.New("Relay rejected access; original refresh rotated credentials for reconnect")
	}
	if ready.Kind != "ready" || ready.ConnectionID != challenge.ConnectionID || ready.RequestID != "1" || ready.DomainID != bundle.DomainID || ready.DeviceID != bundle.DeviceID || ready.HistoryID != challenge.HistoryID || ready.Limits == nil || *ready.Limits != limits || !time.Now().Before(duplex.Time(ready.AuthorityExpiresAt)) {
		return errors.New("Relay ready binding mismatch")
	}
	lease := CredentialLease{Enrollment: bundle, ExpiresAt: duplex.Time(ready.AuthorityExpiresAt)}
	if p := c.CredentialProvider(); p != nil {
		binding := c.providerBinding()
		lease, e = p.EnsureAccess(life, binding)
		if e != nil {
			return e
		}
		if lease.Enrollment.Access.Token != bundle.Access.Token {
			return errors.New("credential changed during Relay authentication")
		}
	}
	s := &relaySocket{owner: c, ws: ws, ctx: life, cancel: cancel, ready: ready, pin: pin, epoch: epoch, request: 1, lease: lease, pending: map[string]*ReceiptFuture{}, queued: map[*ReceiptFuture]int{}, data: make(chan relayWrite, 64), control: make(chan relayWrite, 8), changed: make(chan struct{}, 1), refresh: make(chan relayRefreshHint, 1), deliveries: make(chan json.RawMessage, 64)}
	defer func() { cancel(); ws.Close(); s.workers.Wait(); s.failPending() }()
	c.socketMu.Lock()
	c.socket = s
	c.socketMu.Unlock()
	ws.SetPingHandler(func(data string) error {
		_ = ws.SetReadDeadline(time.Now().Add(60 * time.Second))
		return ws.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(5*time.Second))
	})
	_ = ws.SetReadDeadline(time.Now().Add(60 * time.Second))
	s.workers.Add(4)
	go func() { defer s.workers.Done(); s.recoverPending() }()
	go func() { defer s.workers.Done(); s.writer() }()
	go func() { defer s.workers.Done(); s.credentials() }()
	go func() {
		defer s.workers.Done()
		for {
			select {
			case <-life.Done():
				return
			case raw := <-s.deliveries:
				if handle != nil {
					if err := handle(life, raw); err != nil {
						cancel()
						return
					}
				}
				s.mu.Lock()
				s.deliveryBytes -= len(raw)
				s.mu.Unlock()
			}
		}
	}()
	if onReady != nil {
		s.workers.Add(1)
		go func() { defer s.workers.Done(); onReady() }()
	}
	for life.Err() == nil {
		f, e := readDuplex(ws)
		if e != nil {
			return e
		}
		if e = s.receive(f); e != nil {
			return e
		}
	}
	return life.Err()
}
func (c *RelayClient) providerBinding() CredentialBinding { return c.CredentialBinding() }

func readDuplex(ws *websocket.Conn) (duplex.Frame, error) {
	kind, b, e := ws.ReadMessage()
	if e != nil {
		return duplex.Frame{}, e
	}
	if kind != websocket.TextMessage {
		return duplex.Frame{}, errors.New("Relay requires text frames")
	}
	return duplex.Decode(b)
}
func writeDuplex(ws *websocket.Conn, f duplex.Frame) error {
	b, e := duplex.Encode(f)
	if e != nil {
		return e
	}
	_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return ws.WriteMessage(websocket.TextMessage, b)
}
func (s *relaySocket) writer() {
	var pending *relayWrite
	for {
		s.mu.Lock()
		valid := time.Now().Before(s.lease.ExpiresAt)
		s.mu.Unlock()
		var data <-chan relayWrite
		if pending == nil {
			data = s.data
		}
		if pending != nil && valid {
			w := *pending
			pending = nil
			if s.write(w) != nil {
				s.cancel()
				return
			}
			continue
		}
		select {
		case <-s.ctx.Done():
			return
		case w := <-s.control:
			if s.write(w) != nil {
				s.cancel()
				return
			}
		case w := <-data:
			pending = &w
		case <-s.changed:
		}
	}
}

// Allocate request IDs at the single writer, so control frames may overtake
// paused data without causing the peer to observe decreasing request IDs.
func (s *relaySocket) write(w relayWrite) error {
	if w.future != nil {
		f := w.future
		// Journal the original before any waiter may observe a potentially written
		// request. Cancellation before this lock wins and is definitively NotSent.
		f.mu.Lock()
		if f.completed {
			f.mu.Unlock()
			s.releaseQueued(f)
			return nil
		}
		if w.frame.Kind == "submit" {
			if f.sessionCheck != nil && !f.sessionCheck(f.Submission.SessionID) {
				f.mu.Unlock()
				f.finish(nil, &NotSent{Cause: errors.New("original E2E session ended")})
				s.releaseQueued(f)
				return nil
			}
			if err := s.owner.journalBeforeWrite(f.Submission, f.uncertain); err != nil {
				f.mu.Unlock()
				f.finish(nil, &NotSent{Cause: err})
				s.releaseQueued(f)
				return nil
			}
		}
		f.written = true
		f.mu.Unlock()
	}

	s.mu.Lock()
	if w.frame.Kind != "reauthenticate" {
		if s.request == ^uint64(0) {
			s.mu.Unlock()
			return errors.New("request counter exhausted")
		}
		s.request++
		w.frame.RequestID = strconv.FormatUint(s.request, 10)
		if w.future != nil {
			w.future.observedCredential = observeRelayCredential(s.lease)
			s.pending[w.frame.RequestID] = w.future
		}
		if w.frame.Kind == "reauth.request" {
			s.reauthID = w.frame.RequestID
		}
	}
	s.mu.Unlock()
	return writeDuplex(s.ws, w.frame)
}
func (s *relaySocket) releaseQueued(f *ReceiptFuture) {
	s.mu.Lock()
	s.bytes -= s.queued[f]
	delete(s.queued, f)
	s.mu.Unlock()
}

func (s *relaySocket) failPending() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for f := range s.queued {
		f.mu.Lock()
		written := f.written
		f.mu.Unlock()
		var e error = &NotSent{Cause: errors.New("Relay disconnected before write")}
		if written {
			s.owner.markRelayUnknown(f.Submission)
			e = &UnknownAcceptance{Submission: f.Submission, Cause: errors.New("Relay disconnected before acceptance")}
		}
		f.finish(nil, e)
	}
	s.pending = map[string]*ReceiptFuture{}
	s.queued = map[*ReceiptFuture]int{}
	s.bytes = 0
}
func (s *relaySocket) receive(f duplex.Frame) error {
	if f.ConnectionID != s.ready.ConnectionID || f.OwnerGeneration != s.ready.OwnerGeneration {
		return errors.New("Relay frame owner mismatch")
	}
	switch f.Kind {
	case "closing":
		return fmt.Errorf("Relay closed: %s", f.Code)
	case "delivery":
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.deliveryBytes+len(f.Envelope) > 8*duplex.MaxEnvelopeBytes {
			return errors.New("Relay delivery queue exhausted")
		}
		select {
		case s.deliveries <- append(json.RawMessage(nil), f.Envelope...):
			s.deliveryBytes += len(f.Envelope)
			return nil
		default:
			return errors.New("Relay delivery queue exhausted")
		}
	case "reauth.challenge":
		return s.respondReauth(f)
	case "reauthenticated":
		s.mu.Lock()
		defer s.mu.Unlock()
		if f.RequestID != s.reauthID || s.reauthDone == nil {
			return errors.New("unexpected reauthentication")
		}
		s.lease = s.reauthLease
		s.lease.ExpiresAt = duplex.Time(f.AuthorityExpiresAt)
		close(s.reauthDone)
		s.reauthDone = nil
		s.reauthID = ""
		select {
		case s.changed <- struct{}{}:
		default:
		}
		return nil
	case "accepted", "rejected", "submit.status":
		s.mu.Lock()
		future := s.pending[f.RequestID]
		var observed relayCredentialObservation
		if future != nil {
			observed = future.observedCredential
		}
		s.mu.Unlock()
		if future == nil {
			return errors.New("uncorrelated Relay result")
		}
		if f.MessageID != future.Submission.MessageID || f.EnvelopeDigest != future.Submission.EnvelopeDigest {
			return errors.New("Relay result key mismatch")
		}
		var err error
		if f.Receipt != nil {
			var env envelope.SecureEnvelope
			if json.Unmarshal(future.Submission.Envelope, &env) != nil {
				return errors.New("missing original envelope")
			}
			if e := duplex.VerifyReceipt(*f.Receipt, s.pin, future.Submission, s.owner.Enrollment().RelayID, env.DomainID, env.SenderDeviceID, env.RecipientDeviceID); e != nil {
				return e
			}
		} else if f.Kind == "rejected" {
			err = &RejectedSubmission{Code: f.Code, Submission: future.Submission}
			if f.Code == "auth_required" {
				select {
				case s.refresh <- relayRefreshHint{reason: AuthenticationRequired, observed: observed}:
				default:
				}
			}
		} else if f.State == "absent" {
			err = &AbsentSubmission{Submission: future.Submission}
		} else {
			err = &UnknownAcceptance{Submission: future.Submission, Cause: errors.New(f.Reason)}
		}
		s.mu.Lock()
		delete(s.pending, f.RequestID)
		s.bytes -= s.queued[future]
		delete(s.queued, future)
		if s.bytes < 0 {
			s.bytes = 0
		}
		s.mu.Unlock()
		state := f.State
		if f.Kind == "accepted" {
			state = "accepted"
		}
		if f.Kind == "rejected" {
			state = "rejected"
		}
		s.owner.resolveRelaySubmission(future.Submission, state, f.Receipt)
		future.finish(f.Receipt, err)
		return nil
	default:
		return errors.New("unexpected Relay server frame")
	}
}
func (s *relaySocket) credentials() {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	var events <-chan CredentialEvent
	if p := s.owner.CredentialProvider(); p != nil {
		events = p.Subscribe(s.ctx, s.owner.providerBinding())
	}
	for {
		hint := relayRefreshHint{}
		force := false
		select {
		case <-s.ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			s.mu.Lock()
			current := s.lease
			s.mu.Unlock()
			if event.Binding != current.Binding || event.StateVersion < current.StateVersion {
				continue
			}
			if event.Reason == ScopeChanged && event.Lease != nil && event.StateVersion == current.StateVersion && event.CredentialGeneration == current.CredentialGeneration && event.AuthorizationRevision == current.AuthorizationRevision && event.Lease.Binding == current.Binding && event.Lease.StateVersion == current.StateVersion && event.Lease.CredentialGeneration == current.CredentialGeneration && event.Lease.AuthorizationRevision == current.AuthorizationRevision && event.Lease.Enrollment.Access.Token == current.Enrollment.Access.Token && event.Lease.ExpiresAt.Equal(current.ExpiresAt) {
				continue
			}
			if event.Reason == "revoked" || event.Reason == "identity_changed" || event.Reason == "scope_changed" {
				s.cancel()
				return
			}
			force = event.Lease != nil && event.Lease.Enrollment.Access.Token != current.Enrollment.Access.Token
		case hint = <-s.refresh:
			force = true
		case <-timer.C:
		}
		s.mu.Lock()
		lease := s.lease
		busy := s.reauthDone != nil
		s.mu.Unlock()
		if hint.reason != "" && hint.observed != observeRelayCredential(lease) {
			continue // an old request cannot invalidate the newer authenticated lease
		}
		if busy || (!force && time.Until(lease.ExpiresAt) > time.Minute) {
			continue
		}
		var next CredentialLease
		var e error
		if p := s.owner.CredentialProvider(); p != nil {
			if hint.reason != "" {
				if e = p.Invalidate(hint.observed.binding, hint.observed.generation, hint.reason); e != nil {
					s.cancel()
					return
				}
			}
			next, e = p.EnsureAccess(s.ctx, lease.Binding)
		} else {
			if hint.reason != "" && s.owner.profile == ProfileLocalLab && lease.Enrollment.Mode == BundleModeWorkbenchLocalLab {
				e = s.owner.refreshRejectedAccess(s.ctx, hint.observed.accessToken)
			} else {
				e = s.owner.ensureAccess(s.ctx)
			}
			next = CredentialLease{Enrollment: s.owner.Enrollment(), ExpiresAt: s.owner.Enrollment().Access.ExpiresAt}
		}
		if e != nil {
			if !time.Now().Before(lease.ExpiresAt.Add(10 * time.Second)) {
				s.cancel()
				return
			}
			continue
		}
		if next.Enrollment.DeviceID != lease.Enrollment.DeviceID || next.Enrollment.DomainID != lease.Enrollment.DomainID || next.AuthorizationRevision != lease.AuthorizationRevision {
			s.cancel()
			return
		}
		s.mu.Lock()
		if s.request == ^uint64(0) {
			s.mu.Unlock()
			s.cancel()
			return
		}
		id := "2"
		s.reauthLease = next
		s.reauthDone = make(chan struct{})
		done := s.reauthDone
		s.mu.Unlock()
		request := duplex.Frame{V: 1, Kind: "reauth.request", ConnectionID: s.ready.ConnectionID, OwnerGeneration: s.ready.OwnerGeneration, RequestID: id}
		select {
		case s.control <- relayWrite{frame: request}:
		case <-s.ctx.Done():
			return
		}
		timeout := time.NewTimer(10 * time.Second)
		select {
		case <-s.ctx.Done():
			timeout.Stop()
			return
		case <-done:
			timeout.Stop()
		case <-timeout.C:
			s.cancel()
			return
		}
	}
}
func (s *relaySocket) respondReauth(f duplex.Frame) error {
	s.mu.Lock()
	lease := s.reauthLease
	id := s.reauthID
	s.mu.Unlock()
	if id == "" || f.RequestID != id || !time.Now().Before(duplex.Time(f.ExpiresAt)) {
		return errors.New("reauthentication challenge mismatch")
	}
	f.RelayID = lease.Enrollment.RelayID
	f.HistoryID = s.ready.HistoryID
	f.Limits = s.ready.Limits
	h, e := duplex.AuthChallenge(f, "reauthenticate", id, s.ready.OwnerGeneration, lease.Enrollment.Access.Token, s.owner.device.Identity)
	if e != nil {
		return e
	}
	proof, e := s.owner.device.CreateProof(s.owner.provider, lease.Enrollment.RelayID, h, duplex.RandomID(), time.Now().UTC().Truncate(time.Second))
	if e != nil {
		return e
	}
	response := duplex.Frame{V: 1, Kind: "reauthenticate", ConnectionID: s.ready.ConnectionID, OwnerGeneration: s.ready.OwnerGeneration, RequestID: id, ChallengeID: f.ChallengeID, AccessToken: lease.Enrollment.Access.Token, Proof: &proof}
	select {
	case s.control <- relayWrite{frame: response}:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func (c *RelayClient) duplexDiscovery(ctx context.Context, b EnrollmentBundle) (identity.DeviceIdentity, error) {
	var pin identity.DeviceIdentity
	u, e := url.Parse(b.RelayWebSocketURL)
	if e != nil || u.Path != duplex.Path || u.RawQuery != "" || u.Fragment != "" {
		return pin, errors.New("transport upgrade required: enrollment requires duplex endpoint")
	}
	signed, _, e := fetchSignedDescriptor(ctx, c.client, b.RelayBaseURL, "/.well-known/iscp/relay")
	if e != nil {
		return pin, e
	}
	var desc descriptor.RelayDescriptor
	if e = strictUnmarshal(signed.Descriptor, &desc); e != nil {
		return pin, e
	}
	if b.RelaySignerIdentity != nil {
		pin = *b.RelaySignerIdentity
	} else {
		if e = verifyRelayDiscovery(ctx, c.client, b, time.Now()); e != nil {
			return pin, e
		}
		pin, e = descriptorSelfSigner(desc.SigningKeys, b.DomainID, signed.SignedBy, signed.Signature.KID)
		if e != nil {
			return pin, e
		}
	}
	if signed.SignedBy != pin.DeviceID || signed.Signature.KID != pin.PublicKey.KID || desc.DomainID != b.DomainID || desc.RelayID != b.RelayID || !validDescriptorWindow(desc.IssuedAt, desc.ExpiresAt, time.Now()) {
		return pin, errors.New("Relay discovery identity mismatch")
	}
	if c.profile != ProfileLocalLab && (strings.TrimRight(desc.BaseURL, "/") != strings.TrimRight(b.RelayBaseURL, "/") || desc.WebSocketURL != b.RelayWebSocketURL) {
		return pin, errors.New("Relay discovery endpoint mismatch")
	}
	limits, _ := duplex.Digest(duplex.DefaultLimits())
	if desc.Metadata["duplex_protocol"] != duplex.Protocol || desc.Metadata["duplex_path"] != duplex.Path || desc.Metadata["duplex_limits_sha256"] != limits {
		return pin, errors.New("transport upgrade required: incompatible signed duplex metadata")
	}
	if e = descriptor.Verify(c.provider, signed, pin, config.DefaultGate(config.ProfileProduction), time.Now()); e != nil {
		return pin, e
	}
	return pin, nil
}
