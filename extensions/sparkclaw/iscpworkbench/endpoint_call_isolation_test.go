package iscpworkbench

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
)

func TestCallDeadlineAndCancellationKeepConcurrentCallsAndLateResponsesIsolated(t *testing.T) {
	for _, profile := range []string{Profile, ProfileV2} {
		for _, reverse := range []bool{false, true} {
			if reverse && profile == Profile {
				continue
			}
			for _, deadline := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/reverse=%v/deadline=%v", profile, reverse, deadline), func(t *testing.T) {
					entered := make(chan struct{}, 2)
					release := make(chan struct{})
					var once sync.Once
					unblock := func() { once.Do(func() { close(release) }) }
					defer unblock()
					var handled atomic.Int32
					handler := func(ctx context.Context, r Request) Response {
						handled.Add(1)
						if string(r.Body) != `"next"` {
							entered <- struct{}{}
							select {
							case <-release:
							case <-ctx.Done():
							}
						}
						return Response{Status: 200, Body: r.Body}
					}
					i, r, _ := profileEndpoints(t, profile == ProfileV2, profile == ProfileV2, handler, handler)
					caller, op := i, OperationIdentity
					if profile == ProfileV2 {
						op = OperationSettingsOwnerGet
					}
					if reverse {
						caller, op = r, OperationBrowserCommand
					}
					caller.mu.Lock()
					original := caller.session
					caller.mu.Unlock()
					ctx, cancel := context.WithCancel(t.Context())
					if deadline {
						cancel()
						ctx, cancel = context.WithTimeout(t.Context(), 150*time.Millisecond)
					}
					defer cancel()
					request := Request{Type: RequestType, Profile: profile, ID: newUUID(), Operation: op, Body: json.RawMessage(`"late"`)}
					lost := asyncIsolationCall(caller, ctx, request)
					awaitResponseSignal(t, entered)
					other := request
					other.ID = newUUID()
					other.Body = json.RawMessage(`"concurrent"`)
					pending := asyncIsolationCall(caller, t.Context(), other)
					awaitResponseSignal(t, entered)
					if !deadline {
						cancel()
					}
					answer := awaitResponseResult(t, lost)
					want := context.Canceled
					if deadline {
						want = context.DeadlineExceeded
					}
					if !errors.Is(answer.err, want) {
						t.Fatalf("call error = %v", answer.err)
					}
					assertIsolationSession(t, caller, original)
					if _, err := caller.Call(t.Context(), request); err == nil {
						t.Fatal("timed-out RPC ID was reused")
					}
					unblock() // Both the late encrypted reply and the valid reply now arrive.
					answer = awaitResponseResult(t, pending)
					if answer.err != nil || string(answer.response.Body) != `"concurrent"` {
						t.Fatalf("unrelated call failed: %+v", answer)
					}
					other.ID = newUUID()
					other.Body = json.RawMessage(`"next"`)
					answer = awaitResponseResult(t, asyncIsolationCall(caller, t.Context(), other))
					if answer.err != nil || string(answer.response.Body) != `"next"` {
						t.Fatalf("next call failed: %+v", answer)
					}
					assertIsolationSession(t, caller, original)
					if handled.Load() != 3 {
						t.Fatalf("unexpected replay/dispatch: %d", handled.Load())
					}
					caller.mu.Lock()
					count := len(caller.pending)
					caller.mu.Unlock()
					if count != 0 {
						t.Fatal("pending call leaked")
					}
				})
			}
		}
	}
}

func TestSubmitContextFailureKeepsSessionAndUnknownOutcome(t *testing.T) {
	for _, failure := range []string{"caller-cancel", "caller-deadline", "post-deadline"} {
		t.Run(failure, func(t *testing.T) {
			i, _, bus, _ := testEndpoints(t, func(_ context.Context, r Request) Response { return Response{Status: 200, Body: r.Body} })
			i.mu.Lock()
			original := i.session
			i.mu.Unlock()
			entered := make(chan struct{}, 1)
			var attempts atomic.Int32
			bus.mu.Lock()
			bus.beforeSubmit = func(ctx context.Context, env envelope.SecureEnvelope) error {
				if env.PayloadType != RequestType || env.SenderDeviceID != "desktop" {
					return nil
				}
				if attempts.Add(1) != 1 {
					return nil
				}
				entered <- struct{}{}
				if failure == "post-deadline" {
					return fmt.Errorf("private submit details: %w", context.DeadlineExceeded)
				}
				<-ctx.Done()
				return errors.New("opaque submit failure")
			}
			bus.mu.Unlock()
			ctx, cancel := context.WithCancel(t.Context())
			if failure == "caller-deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 100*time.Millisecond)
			}
			defer cancel()
			r := Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity}
			lost := asyncIsolationCall(i, ctx, r)
			awaitResponseSignal(t, entered)
			if failure == "caller-cancel" {
				cancel()
			}
			answer := awaitResponseResult(t, lost)
			if callContextError(answer.err) == nil {
				t.Fatal("context classification lost", answer.err)
			}
			var notSent *TransportError
			if errors.As(answer.err, &notSent) && notSent.NotSent {
				t.Fatal("timeout claimed non-delivery")
			}
			assertIsolationSession(t, i, original)
			r.ID = newUUID()
			answer = awaitResponseResult(t, asyncIsolationCall(i, t.Context(), r))
			if answer.err != nil || answer.response.Status != 200 {
				t.Fatalf("sequence gap broke next call: %+v", answer)
			}
			if attempts.Load() != 2 {
				t.Fatal("failed submit was replayed")
			}
		})
	}
}

func TestLateSubmitFailureCannotDisconnectReplacementSession(t *testing.T) {
	i, _, bus, _ := testEndpoints(t, func(_ context.Context, r Request) Response { return Response{Status: 200} })
	entered, release := make(chan struct{}, 1), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var attempts atomic.Int32
	bus.mu.Lock()
	bus.beforeSubmit = func(ctx context.Context, env envelope.SecureEnvelope) error {
		if env.PayloadType == RequestType && env.SenderDeviceID == "desktop" && attempts.Add(1) == 1 {
			entered <- struct{}{}
			<-release
			return errors.New("old transport failed")
		}
		return nil
	}
	bus.mu.Unlock()
	r := Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity}
	old := asyncIsolationCall(i, t.Context(), r)
	awaitResponseSignal(t, entered)
	if err := i.initiate(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitReady(t, i)
	i.mu.Lock()
	replacement := i.session
	i.mu.Unlock()
	unblock()
	if answer := awaitResponseResult(t, old); answer.err == nil {
		t.Fatal("old failed submit succeeded")
	}
	assertIsolationSession(t, i, replacement)
	r.ID = newUUID()
	if answer := awaitResponseResult(t, asyncIsolationCall(i, t.Context(), r)); answer.err != nil {
		t.Fatal(answer.err)
	}
}

func TestResponseAuthorizationDeadlineFailsOnlyOriginalCall(t *testing.T) {
	var checks atomic.Int32
	e, s := responseUnitEndpoint(t, func(context.Context) (iscpauth.Policy, error) {
		if checks.Add(1) == 1 {
			return iscpauth.Policy{}, fmt.Errorf("fresh authority: %w", context.DeadlineExceeded)
		}
		return activeResponsePolicy(), nil
	})
	id, first := responsePending(e, t.Context())
	otherID, other := responsePending(e, t.Context())
	if err := e.acceptResponse(s.ctx, responseBytes(id, "must not deliver"), s.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if result := awaitResponseResult(t, first.result); !errors.Is(result.err, context.DeadlineExceeded) || result.response.Status != 0 {
		t.Fatalf("authorization did not fail closed: %+v", result)
	}
	e.mu.Lock()
	retained := e.session == s && e.pending[otherID] == other
	e.mu.Unlock()
	if !retained {
		t.Fatal("authorization timeout canceled unrelated call")
	}
	if err := e.acceptResponse(s.ctx, responseBytes(otherID, "freshly authorized"), s.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if result := awaitResponseResult(t, other.result); result.err != nil || string(result.response.Body) != `"freshly authorized"` {
		t.Fatal("independent fresh authorization failed", result.err)
	}
	if checks.Load() != 2 {
		t.Fatal("authority result was cached")
	}
}

func TestHeartbeatLossStillFailsPendingCallsAndReplacesSession(t *testing.T) {
	entered := make(chan struct{}, 1)
	i, _, _, _ := testEndpoints(t, func(ctx context.Context, _ Request) Response {
		entered <- struct{}{}
		<-ctx.Done()
		return Response{Status: 200}
	})
	r := Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity}
	pending := asyncIsolationCall(i, t.Context(), r)
	awaitResponseSignal(t, entered)
	i.mu.Lock()
	original := i.session
	original.timeReceived = time.Now().Add(-heartbeatTimeout - time.Second)
	i.mu.Unlock()
	if answer := awaitResponseResult(t, pending); answer.err == nil {
		t.Fatal("dead peer did not fail pending call")
	}
	waitReady(t, i)
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.session == original || original.ctx.Err() == nil {
		t.Fatal("dead receive session retained its keys")
	}
}

func asyncIsolationCall(e *Endpoint, ctx context.Context, r Request) <-chan callResult {
	ch := make(chan callResult, 1)
	go func() { response, err := e.Call(ctx, r); ch <- callResult{response: response, err: err} }()
	return ch
}

func assertIsolationSession(t *testing.T, e *Endpoint, original *activeSession) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session != original || e.stateName != "transport_ready" || original.ctx.Err() != nil {
		t.Fatalf("healthy session lost: %s", e.stateName)
	}
}
