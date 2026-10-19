package iscpworkbench

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/appstream"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
)

func recoveryPending(ctx context.Context) *pendingStream {
	return &pendingStream{ctx: ctx, generation: 1, events: make(chan json.RawMessage, 128), completion: make(chan Response, 1), errors: make(chan error, 1)}
}
func recoveryFrame(t *testing.T, id string, seq uint64, text string) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(appstream.Frame{Type: appstream.Type, SchemaVersion: 1, SubscriptionID: id, StreamSeq: seq, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func recoveryCompletion(t *testing.T, id string, last uint64) Response {
	t.Helper()
	body, err := json.Marshal(appstream.Completion{SchemaVersion: 1, LastStreamSeq: last, Reason: "terminal"})
	if err != nil {
		t.Fatal(err)
	}
	return Response{Type: ResponseType, Profile: ProfileV2, ID: id, Status: 200, Body: body}
}
func awaitRecoveryResult(t *testing.T, ch <-chan callResult) callResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("stream consumer did not finish")
	}
	return callResult{}
}

func TestStreamEarlyCompletionWaitsForContiguousOutOfOrderTail(t *testing.T) {
	e, s := streamAuthorityUnitEndpoint(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	id, p := newUUID(), recoveryPending(ctx)
	out := make(chan uint64, 4)
	finished := make(chan callResult, 1)
	p.completion <- recoveryCompletion(t, id, 2)
	go func() {
		r, err := e.consumeStream(s, p, id, func(raw json.RawMessage) error {
			f, err := appstream.Decode(raw)
			if err == nil {
				out <- f.StreamSeq
			}
			return err
		})
		finished <- callResult{response: r, err: err}
	}()
	select {
	case r := <-finished:
		t.Fatalf("completion swallowed missing tail: %+v", r)
	case <-time.After(20 * time.Millisecond):
	}
	p.events <- recoveryFrame(t, id, 2, "second")
	select {
	case seq := <-out:
		t.Fatalf("noncontiguous sequence published: %d", seq)
	case <-time.After(20 * time.Millisecond):
	}
	p.events <- recoveryFrame(t, id, 1, "first")
	for expected := uint64(1); expected <= 2; expected++ {
		select {
		case seq := <-out:
			if seq != expected {
				t.Fatalf("order %d want %d", seq, expected)
			}
		case <-time.After(time.Second):
			t.Fatal("contiguous tail not published")
		}
	}
	if r := awaitRecoveryResult(t, finished); r.err != nil || r.response.Status != 200 {
		t.Fatalf("tail failed: %+v", r)
	}
}

func TestStreamConflictingSecondCompletionCannotShortenPendingTail(t *testing.T) {
	e, s := streamAuthorityUnitEndpoint(t, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	id, p := newUUID(), recoveryPending(ctx)
	p.completion <- recoveryCompletion(t, id, 2)
	finished := make(chan callResult, 1)
	go func() {
		r, err := e.consumeStream(s, p, id, func(json.RawMessage) error {
			t.Error("no tail frame was supplied")
			return nil
		})
		finished <- callResult{response: r, err: err}
	}()
	// The first completion must leave the channel before the second arrives;
	// otherwise only the channel-overflow duplicate check would be exercised.
	for len(p.completion) > 0 && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("first completion was not consumed")
	}
	p.completion <- recoveryCompletion(t, id, 0)
	if r := awaitRecoveryResult(t, finished); !errors.Is(r.err, appstream.ErrInvalid) {
		t.Fatalf("second terminal changed the first missing-tail watermark: response=%+v err=%v", r.response, r.err)
	}
}

func TestStreamDuplicateFramesAreIdempotentOrRejectedOnConflict(t *testing.T) {
	for _, kind := range []string{"identical-delivered", "conflicting-delivered", "conflicting-queued"} {
		t.Run(kind, func(t *testing.T) {
			e, s := streamAuthorityUnitEndpoint(t, nil)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			id, p := newUUID(), recoveryPending(ctx)
			var published []uint64
			p.events <- recoveryFrame(t, id, 1, "first")
			if kind == "conflicting-queued" {
				p.events <- recoveryFrame(t, id, 3, "original")
				p.events <- recoveryFrame(t, id, 3, "changed")
			} else {
				text := "first"
				if kind == "conflicting-delivered" {
					text = "changed"
				}
				p.events <- recoveryFrame(t, id, 1, text)
				p.events <- recoveryFrame(t, id, 2, "last")
			}
			_, err := e.consumeStream(s, p, id, func(raw json.RawMessage) error {
				f, err := appstream.Decode(raw)
				if err == nil {
					published = append(published, f.StreamSeq)
					if f.StreamSeq == 2 {
						p.completion <- recoveryCompletion(t, id, 2)
					}
				}
				return err
			})
			if kind == "identical-delivered" {
				if err != nil || !slices.Equal(published, []uint64{1, 2}) {
					t.Fatalf("identical duplicate altered projection: %v %v", published, err)
				}
			} else if err == nil || errors.Is(err, context.DeadlineExceeded) || !slices.Equal(published, []uint64{1}) {
				t.Fatalf("conflict was not fenced: %v %v", published, err)
			}
		})
	}
}

func TestStreamCompletionRejectsBufferedFramesPastWatermark(t *testing.T) {
	e, s := streamAuthorityUnitEndpoint(t, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	id, p := newUUID(), recoveryPending(ctx)
	// An invalidate callback acts as an observable read-loop barrier after the
	// future frame is buffered; it does not change the generic sequence cursor.
	p.events <- recoveryFrame(t, id, 2, "must-not-publish")
	control, _ := json.Marshal(appstream.Control{Type: appstream.ControlType, SchemaVersion: 1, SubscriptionID: id, Action: "invalidate", Body: json.RawMessage(`{"reason":"test-barrier"}`)})
	p.events <- control
	var published []uint64
	_, err := e.consumeStream(s, p, id, func(raw json.RawMessage) error {
		if _, e := appstream.DecodeControl(raw); e == nil {
			p.completion <- recoveryCompletion(t, id, 1)
			return nil
		}
		f, e := appstream.Decode(raw)
		if e == nil {
			published = append(published, f.StreamSeq)
		}
		return e
	})
	if !errors.Is(err, appstream.ErrInvalid) || len(published) != 0 {
		t.Fatalf("invalid completion watermark was not rejected: %v %v", published, err)
	}
}

func TestStreamQueuedCompletionRechecksExpiredAuthority(t *testing.T) {
	e, s := streamAuthorityUnitEndpoint(t, nil)
	id, p := newUUID(), recoveryPending(t.Context())
	e.mu.Lock()
	s.streams[id] = p
	e.mu.Unlock()
	raw, _ := json.Marshal(recoveryCompletion(t, id, 0))
	if accepted, err := e.acceptStreamCompletion(raw, s.id); !accepted || err != nil {
		t.Fatalf("completion not queued: %v %v", accepted, err)
	}
	e.mu.Lock()
	s.streamAuthority.deadline = time.Now().Add(-time.Second)
	e.mu.Unlock()
	_, err := e.consumeStream(s, p, id, func(json.RawMessage) error { t.Fatal("unexpected publication"); return nil })
	if !errors.Is(err, errStreamAuthority) {
		t.Fatalf("queued success crossed authority expiry: %v", err)
	}
}

func TestStreamCancellationInsideCallbackStopsBufferedTail(t *testing.T) {
	e, s := streamAuthorityUnitEndpoint(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	id, p := newUUID(), recoveryPending(ctx)
	p.events <- recoveryFrame(t, id, 2, "must-not-publish")
	p.events <- recoveryFrame(t, id, 1, "first")
	var published []uint64
	_, err := e.consumeStream(s, p, id, func(raw json.RawMessage) error {
		f, err := appstream.Decode(raw)
		if err == nil {
			published = append(published, f.StreamSeq)
			cancel()
		}
		return err
	})
	if !errors.Is(err, context.Canceled) || !slices.Equal(published, []uint64{1}) {
		t.Fatalf("canceled observer published queued tail: %v %v", published, err)
	}
}

func TestStreamGapDeadlineDoesNotRestartOnMoreOutOfOrderFrames(t *testing.T) {
	e, s := streamAuthorityUnitEndpoint(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	id, p := newUUID(), recoveryPending(ctx)
	p.events <- recoveryFrame(t, id, 2, "second")
	finished := make(chan callResult, 1)
	started := time.Now()
	go func() {
		r, err := e.consumeStream(s, p, id, func(json.RawMessage) error { return errors.New("noncontiguous publication") })
		finished <- callResult{response: r, err: err}
	}()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
		p.events <- recoveryFrame(t, id, 3, "third")
	case r := <-finished:
		t.Fatalf("gap ended too early: %+v", r)
	}
	r := awaitRecoveryResult(t, finished)
	if r.err == nil || !strings.Contains(r.err.Error(), "sequence gap") || time.Since(started) > 2750*time.Millisecond {
		t.Fatalf("gap deadline reset or invalid: %v after %s", r.err, time.Since(started))
	}
}

func TestStreamCancelBeforeFirstOpenFencesOriginalRequest(t *testing.T) {
	var called atomic.Int32
	_, r, _ := profileEndpoints(t, true, true, func(context.Context, Request) Response { called.Add(1); return Response{Status: 200} })
	request := streamTestRequest()
	var open struct {
		Latest time.Time `json:"latest_open_at"`
	}
	if json.Unmarshal(request.Body, &open) != nil {
		t.Fatal("invalid fixture")
	}
	r.mu.Lock()
	s := r.session
	initial := s.streamAuthority
	r.mu.Unlock()
	if initial != nil {
		t.Fatal("fixture accidentally prewarmed stream authority")
	}
	control, _ := json.Marshal(appstream.Control{Type: appstream.ControlType, SchemaVersion: 1, SubscriptionID: request.ID, Action: "cancel", LatestOpenAt: &open.Latest})
	if err := r.acceptStreamControl(control, s.id); err != nil {
		t.Fatal(err)
	}
	if err := r.acceptStreamRequest(t.Context(), request, s.id); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		r.mu.Lock()
		_, pending := s.streamSenders[request.ID]
		_, seen := s.seenRequests[request.ID]
		r.mu.Unlock()
		if !pending && seen {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("canceled open did not leave dispatcher")
		}
		time.Sleep(time.Millisecond)
	}
	if called.Load() != 0 {
		t.Fatal("cancel-before-open was dropped before first authority snapshot")
	}
	if err := r.acceptStreamRequest(t.Context(), request, s.id); err != nil || called.Load() != 0 {
		t.Fatalf("original canceled open revived: %v", err)
	}
}

func TestStreamLateFramesFromCanceledSubscriptionCannotReachNewObserver(t *testing.T) {
	e, s := streamAuthorityUnitEndpoint(t, nil)
	oldID, newID := newUUID(), newUUID()
	old := recoveryPending(t.Context())
	current := recoveryPending(t.Context())
	e.mu.Lock()
	s.streams[oldID] = old
	delete(s.streams, oldID)
	s.streams[newID] = current
	e.mu.Unlock()
	if err := e.acceptStreamFrame(recoveryFrame(t, oldID, 1, "late"), s.id); err != nil {
		t.Fatal(err)
	}
	control, _ := json.Marshal(appstream.Control{Type: appstream.ControlType, SchemaVersion: 1, SubscriptionID: oldID, Action: "invalidate", Body: json.RawMessage(`{"reason":"late"}`)})
	if err := e.acceptStreamControl(control, s.id); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(recoveryCompletion(t, oldID, 0))
	if accepted, err := e.acceptStreamCompletion(raw, s.id); accepted || err != nil {
		t.Fatalf("closed subscription accepted late completion: %v %v", accepted, err)
	}
	if len(old.events) != 0 || len(current.events) != 0 || len(current.completion) != 0 || len(current.errors) != 0 {
		t.Fatal("old subscription control crossed identity")
	}
	if err := e.acceptStreamFrame(recoveryFrame(t, newID, 1, "current"), fmt.Sprint(s.id, "-old")); err != nil {
		t.Fatal(err)
	}
	if len(current.events) != 0 {
		t.Fatal("old session frame crossed session identity")
	}
}

func TestStreamNodeResponderFastPathAuthenticatesBeforeCancelWithoutRegistryRead(t *testing.T) {
	i, r, _ := profileEndpoints(t, true, true)
	r.mu.Lock()
	s := r.session
	id := newUUID()
	// The opening window has passed, but this exact active subscription must
	// remain cancellable for as long as it runs.
	latest := time.Now().UTC().Add(-time.Minute)
	senderCtx, cancelSender := context.WithCancel(s.ctx)
	defer cancelSender()
	s.streamSenders[id] = &streamSender{latestOpenAt: latest, ctx: senderCtx, cancel: cancelSender}
	r.mu.Unlock()
	var validations atomic.Int32
	n := &NodeResponder{
		config: Config{PeerRegistryFile: filepath.Join(t.TempDir(), "unavailable-registry.json")},
		peers:  map[string]*nodePeer{i.material.device.Identity.DeviceID: {endpoint: r}},
		validate: func(context.Context, ManagedPeer) error {
			validations.Add(1)
			return errors.New("authority source unavailable")
		},
	}
	control, err := json.Marshal(appstream.Control{Type: appstream.ControlType, SchemaVersion: 1, SubscriptionID: id, Action: "cancel", LatestOpenAt: &latest})
	if err != nil {
		t.Fatal(err)
	}
	i.mu.Lock()
	env, err := envelope.Encrypt(i.provider, i.session.state, newUUID(), appstream.ControlType, envelope.Route{RelayID: i.material.enrollment.RelayID, TTLSeconds: 30, Priority: 5}, control)
	i.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(v envelope.SecureEnvelope) {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := n.receive(t.Context(), raw); err != nil {
			t.Fatalf("stream path read unavailable registry: %v", err)
		}
	}
	for _, kind := range []string{"ciphertext", "sender", "recipient", "session", "payload-type"} {
		t.Run(kind, func(t *testing.T) {
			forged := env
			switch kind {
			case "ciphertext":
				forged.Ciphertext = "AAAA"
			case "sender":
				forged.SenderDeviceID = newUUID()
			case "recipient":
				forged.RecipientDeviceID = newUUID()
			case "session":
				forged.SessionID = newUUID()
			case "payload-type":
				forged.PayloadType = appstream.Type
			}
			deliver(forged)
			r.mu.Lock()
			sameSession := r.session == s
			r.mu.Unlock()
			if !sameSession || senderCtx.Err() != nil {
				t.Fatal("unauthenticated stream control canceled active subscription or session")
			}
		})
	}
	deliver(env)
	if !errors.Is(senderCtx.Err(), context.Canceled) {
		t.Fatal("authenticated late cancel was lost or forged input consumed its receive sequence")
	}
	// A duplicate ciphertext must not be authenticated a second time, even if
	// a local consumer now occupies the same subscription map entry.
	replacementCtx, cancelReplacement := context.WithCancel(s.ctx)
	defer cancelReplacement()
	r.mu.Lock()
	s.streamSenders[id] = &streamSender{latestOpenAt: latest, ctx: replacementCtx, cancel: cancelReplacement}
	r.mu.Unlock()
	deliver(env)
	if replacementCtx.Err() != nil {
		t.Fatal("replayed encrypted cancellation reached replacement consumer")
	}
	if validations.Load() != 0 {
		t.Fatalf("stream fast path queried Client authority %d times", validations.Load())
	}
}
