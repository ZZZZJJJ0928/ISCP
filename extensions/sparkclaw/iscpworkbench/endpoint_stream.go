package iscpworkbench

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/appstream"
)

type StreamEmitter interface {
	Send(context.Context, json.RawMessage) error
	Invalidate(context.Context, json.RawMessage) error
}
type streamContextKey struct{}
type streamSendContextKey struct{}
type streamSendAuthorization struct {
	session    *activeSession
	generation uint64
}

func streamSendContext(ctx context.Context, s *activeSession, g uint64) context.Context {
	return context.WithValue(ctx, streamSendContextKey{}, streamSendAuthorization{s, g})
}

func StreamFromContext(ctx context.Context) (StreamEmitter, bool) {
	w, ok := ctx.Value(streamContextKey{}).(StreamEmitter)
	return w, ok
}

type pendingStream struct {
	openDeadline   time.Time
	ctx            context.Context
	generation     uint64
	events         chan json.RawMessage
	completion     chan Response
	completionHash *[32]byte // guarded by Endpoint.mu; first terminal is immutable
	errors         chan error
}

func (s *pendingStream) fail(err error) {
	select {
	case s.errors <- err:
	default:
	}
}

type streamSender struct {
	latestOpenAt time.Time
	mu           sync.Mutex
	e            *Endpoint
	session      *activeSession
	id           string
	generation   uint64
	seq          uint64
	ctx          context.Context
	cancel       context.CancelFunc
}

func (e *Endpoint) stopStreamsLocked(s *activeSession, err error) {
	for _, p := range s.streams {
		p.fail(err)
	}
	for _, p := range s.streamSenders {
		p.cancel()
	}
}
func (e *Endpoint) streamLocalCheck(s *activeSession, g uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.streamAuthorityValidLocked(s, g) {
		return errStreamAuthority
	}
	return nil
}
func (w *streamSender) Send(ctx context.Context, body json.RawMessage) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ctx.Err() != nil {
		return w.ctx.Err()
	}
	if err := w.e.streamLocalCheck(w.session, w.generation); err != nil {
		return err
	}
	f := appstream.Frame{Type: appstream.Type, SchemaVersion: 1, SubscriptionID: w.id, StreamSeq: w.seq + 1, Body: body}
	if f.Validate() != nil {
		return appstream.ErrInvalid
	}
	raw, err := json.Marshal(f)
	if err != nil || len(raw) > appstream.MaxBytes {
		return appstream.ErrInvalid
	}
	if err = w.e.sendPayload(streamSendContext(ctx, w.session, w.generation), appstream.Type, raw, w.session.id); err != nil {
		return err
	}
	w.seq++
	return nil
}
func (w *streamSender) Invalidate(ctx context.Context, body json.RawMessage) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ctx.Err() != nil {
		return w.ctx.Err()
	}
	if err := w.e.streamLocalCheck(w.session, w.generation); err != nil {
		return err
	}
	raw, err := json.Marshal(appstream.Control{Type: appstream.ControlType, SchemaVersion: 1, SubscriptionID: w.id, Action: "invalidate", Body: body})
	if err != nil {
		return err
	}
	if _, err = appstream.DecodeControl(raw); err != nil {
		return err
	}
	return w.e.sendPayload(streamSendContext(ctx, w.session, w.generation), appstream.ControlType, raw, w.session.id)
}

// StreamCall observes an existing operation. Cancellation never invokes the
// business cancellation API and never resets a shared authenticated session.
func (e *Endpoint) StreamCall(ctx context.Context, r Request, onEvent func(json.RawMessage) error) (Response, error) {
	if r.Validate() != nil || r.Profile != ProfileV2 || r.Operation != OperationExecutionProgressStream || r.ID == r.RequestID || onEvent == nil || e.config.Role != RoleInitiator {
		return Response{}, appstream.ErrInvalid
	}
	e.mu.Lock()
	s := e.session
	if s == nil || !s.manifest || s.capabilities == nil || s.capabilities.StreamSchemaVersion != 1 || !slices.Contains(s.capabilities.Operations, r.Operation) {
		e.mu.Unlock()
		return Response{}, errors.New("matched application stream release required")
	}
	e.mu.Unlock()
	g, err := e.ensureStreamAuthority(ctx, s)
	if err != nil {
		return Response{}, err
	}
	// The ten-second open window starts only after authorization is available.
	var fields map[string]json.RawMessage
	if appstream.DecodeStrict(r.Body, &fields) != nil || fields == nil {
		return Response{}, appstream.ErrInvalid
	}
	openDeadline := time.Now().Add(10 * time.Second)
	latest := openDeadline.UTC()
	fields["latest_open_at"], _ = json.Marshal(latest)
	r.Body, _ = json.Marshal(fields)
	raw, err := encodeRequest(r)
	if err != nil {
		return Response{}, err
	}
	p := &pendingStream{ctx: ctx, openDeadline: openDeadline, generation: g, events: make(chan json.RawMessage, 128), completion: make(chan Response, 1), errors: make(chan error, 1)}
	e.mu.Lock()
	if !e.streamAuthorityValidLocked(s, g) {
		e.mu.Unlock()
		return Response{}, errStreamAuthority
	}
	if _, exists := s.sentRequests[r.ID]; exists {
		e.mu.Unlock()
		return Response{}, errors.New("reused stream ID")
	}
	s.sentRequests[r.ID] = struct{}{}
	s.streams[r.ID] = p
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(s.streams, r.ID)
		valid := e.streamAuthorityValidLocked(s, g)
		e.mu.Unlock()
		if valid {
			c, cancel := context.WithTimeout(s.ctx, 2*time.Second)
			defer cancel()
			b, _ := json.Marshal(appstream.Control{Type: appstream.ControlType, SchemaVersion: 1, SubscriptionID: r.ID, Action: "cancel", LatestOpenAt: &latest})
			_ = e.sendPayload(streamSendContext(c, s, g), appstream.ControlType, b, s.id)
		}
	}()
	openCtx, cancelOpen := context.WithDeadline(ctx, openDeadline)
	err = e.sendPayload(streamSendContext(openCtx, s, g), RequestType, raw, s.id)
	cancelOpen()
	if err != nil {
		return Response{}, err
	}
	return e.consumeStream(s, p, r.ID, onEvent)
}

func (e *Endpoint) consumeStream(s *activeSession, p *pendingStream, id string, onEvent func(json.RawMessage) error) (Response, error) {
	openingWindow := 10 * time.Second
	if !p.openDeadline.IsZero() {
		openingWindow = time.Until(p.openDeadline)
	}
	if openingWindow <= 0 {
		return Response{}, errors.New("stream opening deadline exceeded")
	}
	opening := time.NewTimer(openingWindow)
	defer opening.Stop()
	var openC = opening.C
	var gap *time.Timer
	var gapC <-chan time.Time
	defer func() {
		if gap != nil {
			gap.Stop()
		}
	}()
	startGap := func() {
		if gap == nil {
			gap = time.NewTimer(2 * time.Second)
			gapC = gap.C
		}
	}
	clearGap := func() {
		if gap != nil {
			gap.Stop()
			gap = nil
			gapC = nil
		}
	}
	next := uint64(1)
	seen := map[uint64][32]byte{}
	queued := map[uint64]json.RawMessage{}
	var terminal *Response
	var last uint64
	for {
		if err := p.ctx.Err(); err != nil {
			return Response{}, err
		}
		if terminal != nil && next > last {
			if err := e.streamLocalCheck(s, p.generation); err != nil {
				return Response{}, err
			}
			return *terminal, nil
		}
		select {
		case <-p.ctx.Done():
			return Response{}, p.ctx.Err()
		case <-s.ctx.Done():
			return Response{}, errors.New("stream session disconnected")
		case err := <-p.errors:
			return Response{}, err
		case <-openC:
			return Response{}, errors.New("stream opening deadline exceeded")
		case <-gapC:
			return Response{}, errors.New("stream sequence gap")
		case response := <-p.completion:
			if err := p.ctx.Err(); err != nil {
				return Response{}, err
			}
			if err := e.streamLocalCheck(s, p.generation); err != nil {
				return Response{}, err
			}
			if terminal != nil {
				previous, _ := json.Marshal(terminal)
				duplicate, _ := json.Marshal(response)
				if !bytes.Equal(previous, duplicate) {
					return Response{}, appstream.ErrInvalid
				}
				continue
			}
			opening.Stop()
			openC = nil
			if response.Status >= 400 {
				return response, nil
			}
			c, err := appstream.DecodeCompletion(response.Body)
			if err != nil || c.LastStreamSeq < next-1 {
				return Response{}, appstream.ErrInvalid
			}
			terminal = &response
			last = c.LastStreamSeq
			for sequence := range queued {
				if sequence > last {
					return Response{}, appstream.ErrInvalid
				}
			}
			if c.Reason == "canceled" || c.Reason == "reset" || c.Reason == "auth_expired" || c.Reason == "gap" || c.Reason == "preview_unavailable" {
				return response, nil
			}
			if next <= last {
				startGap()
			}
		case raw := <-p.events:
			if err := p.ctx.Err(); err != nil {
				return Response{}, err
			}
			if err := e.streamLocalCheck(s, p.generation); err != nil {
				return Response{}, err
			}
			opening.Stop()
			openC = nil
			var typeField struct {
				Type string `json:"type"`
			}
			_ = json.Unmarshal(raw, &typeField)
			if typeField.Type == appstream.ControlType {
				if err := onEvent(raw); err != nil {
					return Response{}, err
				}
				continue
			}
			f, err := appstream.Decode(raw)
			if err != nil {
				return Response{}, err
			}
			hash := sha256.Sum256(raw)
			if old, ok := seen[f.StreamSeq]; ok {
				if old != hash {
					return Response{}, errors.New("conflicting stream duplicate")
				}
				continue
			}
			if f.StreamSeq < next || terminal != nil && f.StreamSeq > last {
				return Response{}, appstream.ErrInvalid
			}
			if old, ok := queued[f.StreamSeq]; ok {
				if sha256.Sum256(old) != hash {
					return Response{}, appstream.ErrInvalid
				}
				continue
			}
			if len(queued) >= 128 {
				return Response{}, errors.New("stream reorder window exceeded")
			}
			queued[f.StreamSeq] = raw
			for {
				if err := p.ctx.Err(); err != nil {
					return Response{}, err
				}
				v, ok := queued[next]
				if !ok {
					break
				}
				if err = e.streamLocalCheck(s, p.generation); err != nil {
					return Response{}, err
				}
				if err = onEvent(v); err != nil {
					return Response{}, err
				}
				seen[next] = sha256.Sum256(v)
				if next > 128 {
					delete(seen, next-128)
				}
				delete(queued, next)
				next++
			}
			if len(queued) > 0 || terminal != nil && next <= last {
				startGap()
			} else {
				clearGap()
			}
		}
	}
}

func (e *Endpoint) acceptStreamFrame(raw []byte, id string) error {
	f, err := appstream.Decode(raw)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.session
	if s == nil || s.id != id || e.config.Role != RoleInitiator {
		return nil
	}
	p := s.streams[f.SubscriptionID]
	if p == nil {
		return nil
	}
	if !e.streamAuthorityValidLocked(s, p.generation) {
		p.fail(errStreamAuthority)
		return nil
	}
	select {
	case p.events <- append(json.RawMessage(nil), raw...):
	default:
		p.fail(errors.New("stream receive queue full"))
	}
	return nil
}
func (e *Endpoint) acceptStreamCompletion(raw []byte, id string) (bool, error) {
	var r Response
	if strictDecode(raw, &r) != nil {
		return false, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.session
	if s == nil || s.id != id {
		return false, nil
	}
	p := s.streams[r.ID]
	if p == nil {
		return false, nil
	}
	if r.Validate() != nil {
		p.fail(appstream.ErrInvalid)
		return true, nil
	}
	if !e.streamAuthorityValidLocked(s, p.generation) {
		p.fail(errStreamAuthority)
		return true, nil
	}
	hash := sha256.Sum256(raw)
	if p.completionHash != nil {
		if *p.completionHash != hash {
			p.fail(errors.New("conflicting stream completion"))
		}
		return true, nil
	}
	p.completionHash = &hash
	select {
	case p.completion <- r:
	default:
		p.fail(errors.New("duplicate stream completion"))
	}
	return true, nil
}

func (e *Endpoint) acceptStreamControl(raw []byte, id string) error {
	c, err := appstream.DecodeControl(raw)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.session
	if s == nil || s.id != id {
		return nil
	}
	if c.Action == "invalidate" {
		if e.config.Role != RoleInitiator {
			return appstream.ErrInvalid
		}
		p := s.streams[c.SubscriptionID]
		if p == nil {
			return nil
		}
		if !e.streamAuthorityValidLocked(s, p.generation) {
			p.fail(errStreamAuthority)
			return nil
		}
		select {
		case p.events <- append(json.RawMessage(nil), raw...):
		default:
			p.fail(errors.New("stream receive queue full"))
		}
		return nil
	}
	if e.config.Role != RoleResponder {
		return appstream.ErrInvalid
	}
	// Cancellation fences an original authenticated identity/session; it cannot
	// extend the declared opening horizon and cannot cancel a business execution.
	if w := s.streamSenders[c.SubscriptionID]; w != nil {
		if !w.latestOpenAt.Equal(*c.LatestOpenAt) {
			return appstream.ErrInvalid
		}
		w.cancel()
		return nil
	}
	now := time.Now()
	for key, deadline := range s.streamCancels {
		if now.After(deadline.Add(30 * time.Second)) {
			delete(s.streamCancels, key)
		}
	}
	if c.LatestOpenAt.After(now.Add(40*time.Second)) || c.LatestOpenAt.Before(now.Add(-30*time.Second)) {
		return appstream.ErrInvalid
	}
	// Authenticated cancellation only removes this peer's observation. It
	// cannot publish data; preserve its tombstone even before the first snapshot.
	if old, ok := s.streamCancels[c.SubscriptionID]; !ok || c.LatestOpenAt.Before(old) {
		s.streamCancels[c.SubscriptionID] = *c.LatestOpenAt
	}
	if w := s.streamSenders[c.SubscriptionID]; w != nil {
		w.cancel()
	}
	return nil
}

func (e *Endpoint) acceptStreamRequest(ctx context.Context, r Request, id string) error {
	var open struct {
		SchemaVersion int             `json:"schema_version"`
		InputDigest   string          `json:"input_digest"`
		LatestOpenAt  time.Time       `json:"latest_open_at"`
		Cursor        json.RawMessage `json:"cursor,omitempty"`
	}
	if appstream.DecodeStrict(r.Body, &open) != nil || open.SchemaVersion != 1 || r.Profile != ProfileV2 || r.ID == r.RequestID || !uuidPattern.MatchString(r.RequestID) || !uuidPattern.MatchString(r.InstallationID) || len(open.InputDigest) != 64 {
		return appstream.ErrInvalid
	}
	now := time.Now()
	if open.LatestOpenAt.Before(now.Add(-30*time.Second)) || open.LatestOpenAt.After(now.Add(40*time.Second)) {
		return appstream.ErrInvalid
	}
	if e.config.Role != RoleResponder || e.config.ExpectedInstallationID != "" && r.InstallationID != e.config.ExpectedInstallationID {
		return appstream.ErrInvalid
	}
	e.mu.Lock()
	s := e.session
	if s == nil || s.id != id || s.capabilities == nil || s.capabilities.StreamSchemaVersion != 1 {
		e.mu.Unlock()
		return errors.New("matched application stream release required")
	}
	for key, deadline := range s.streamCancels {
		if now.After(deadline.Add(30 * time.Second)) {
			delete(s.streamCancels, key)
		}
	}
	if _, seen := s.seenRequests[r.ID]; seen {
		e.mu.Unlock()
		return nil
	}
	s.seenRequests[r.ID] = struct{}{}
	callCtx, cancel := context.WithCancel(s.ctx)
	w := &streamSender{latestOpenAt: open.LatestOpenAt, e: e, session: s, id: r.ID, ctx: callCtx, cancel: cancel}
	s.streamSenders[r.ID] = w
	if _, canceled := s.streamCancels[r.ID]; canceled {
		cancel()
	}
	e.workers.Add(1)
	e.mu.Unlock()
	go e.runStreamRequest(callCtx, r, open.LatestOpenAt, w)
	return nil
}
func (e *Endpoint) runStreamRequest(ctx context.Context, r Request, latest time.Time, w *streamSender) {
	defer e.workers.Done()
	defer w.cancel()
	defer func() { e.mu.Lock(); delete(w.session.streamSenders, r.ID); e.mu.Unlock() }()
	g, err := e.ensureStreamAuthority(ctx, w.session)
	if err != nil {
		return
	}
	w.generation = g
	if ctx.Err() != nil || time.Now().After(latest.Add(30*time.Second)) {
		return
	}
	e.mu.Lock()
	a := w.session.streamAuthority
	info := SessionInfo{SessionID: w.session.id, Profile: ProfileV2, GrantRevision: e.grantMaterial().grant.RevocationEpoch, Binding: e.config.Binding, Scopes: slices.Clone(a.policy.Scopes), QualifiedOperations: slices.Clone(w.session.capabilities.QualifiedOperations)}
	e.mu.Unlock()
	info.CheckAuthorization = func(context.Context) (iscpauth.Policy, error) {
		e.mu.Lock()
		defer e.mu.Unlock()
		if !e.streamAuthorityValidLocked(w.session, g) {
			return iscpauth.Policy{}, errStreamAuthority
		}
		p := a.policy
		p.Scopes = slices.Clone(p.Scopes)
		return p, nil
	}
	ctx = context.WithValue(ctx, sessionInfoKey{}, info)
	ctx = context.WithValue(ctx, streamContextKey{}, StreamEmitter(w))
	response := e.handler(ctx, r)
	if ctx.Err() != nil || e.streamLocalCheck(w.session, g) != nil {
		return
	}
	var terminal struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(response.Body, &terminal)
	if terminal.Reason == "" {
		terminal.Reason = "terminal"
	}
	w.mu.Lock()
	last := w.seq
	w.mu.Unlock()
	completion := appstream.Completion{SchemaVersion: 1, LastStreamSeq: last, Reason: terminal.Reason}
	if completion.Validate() != nil {
		completion.Reason = "preview_unavailable"
	}
	if response.Status < 400 {
		response.Body, _ = json.Marshal(completion)
	}
	response.ID = r.ID
	response.Profile = r.Profile
	_ = e.sendResponse(streamSendContext(ctx, w.session, g), w.session.id, response)
}
