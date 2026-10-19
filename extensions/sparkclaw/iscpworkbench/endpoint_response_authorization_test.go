package iscpworkbench

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
)

func TestResponseAuthorizationCoalescesActualSignedChecksWithoutBlockingReceive(t *testing.T) {
	desktop, backend := testMaterials(t)
	client, gate, issuer, grant := signedResponseAuthority(t, desktop, backend)
	desktop.issuer, backend.issuer, desktop.grant, backend.grant = issuer, issuer, grant, grant
	bus := &testRelayBus{peers: map[string]*testRelay{}}
	d := &testRelay{bus: bus, inbox: make(chan json.RawMessage, 128), disrupt: make(chan struct{}, 1)}
	b := &testRelay{bus: bus, inbox: make(chan json.RawMessage, 128), disrupt: make(chan struct{}, 1)}
	bus.peers[desktop.device.Identity.DeviceID], bus.peers[backend.device.Identity.DeviceID] = d, b
	const calls = 8
	joined, handled, responses := make(chan struct{}, 32), make(chan struct{}, 32), make(chan struct{})
	initiator, err := newEndpoint(Config{Role: RoleInitiator}, desktop, d, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	initiator.authorityPolicy = func(ctx context.Context) (iscpauth.Policy, error) {
		if gate.enabled.Load() {
			ctx = &responseWaiterContext{Context: ctx, joined: joined}
		}
		return client.AuthorizationPolicy(ctx)
	}
	responder, err := newEndpoint(Config{Role: RoleResponder}, backend, b, func(ctx context.Context, _ Request) Response {
		handled <- struct{}{}
		select {
		case <-responses:
		case <-ctx.Done():
			return Response{Status: 503}
		}
		return Response{Status: 200, Body: json.RawMessage(`{"verified":true}`)}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan struct{}, 2)
	go func() { _ = initiator.Run(ctx); done <- struct{}{} }()
	go func() { _ = responder.Run(ctx); done <- struct{}{} }()
	t.Cleanup(func() {
		gate.unblock()
		cancel()
		_ = initiator.Close()
		_ = responder.Close()
		for range 2 {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("response endpoint did not stop")
			}
		}
	})
	waitReady(t, initiator)
	waitReady(t, responder)
	results := make(chan callResult, calls)
	for range calls {
		go func() {
			r, err := initiator.Call(ctx, Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity})
			results <- callResult{r, err}
		}()
	}
	for range calls {
		awaitResponseSignal(t, handled)
	}
	gate.enabled.Store(true)
	close(responses)
	awaitResponseSignal(t, gate.started)
	for range calls {
		awaitResponseSignal(t, joined)
	}
	if gate.checks.Load() != 1 {
		t.Fatal("concurrent responses performed serial issuer checks", gate.checks.Load())
	}
	select {
	case <-results:
		t.Fatal("response escaped before fresh signed authorization")
	default:
	}
	// A heartbeat behind all blocked responses still passes the sole receive
	// owner. No decryption or sequence processing is moved into the workers.
	responder.mu.Lock()
	id := responder.session.id
	responder.mu.Unlock()
	ping, _ := json.Marshal(map[string]string{"nonce": newUUID()})
	if err := responder.sendPayload(ctx, pingType, ping, id); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	var replay envelope.SecureEnvelope
	for time.Now().Before(deadline) {
		pong := false
		bus.mu.Lock()
		for _, env := range bus.envelopes {
			if env.PayloadType == pongType {
				pong = true
			}
			if env.PayloadType == ResponseType && env.RecipientDeviceID == desktop.device.Identity.DeviceID {
				replay = env
			}
		}
		bus.mu.Unlock()
		if pong {
			break
		}
		time.Sleep(time.Millisecond)
	}
	bus.mu.Lock()
	pong := false
	for _, env := range bus.envelopes {
		pong = pong || env.PayloadType == pongType
	}
	bus.mu.Unlock()
	if !pong {
		t.Fatal("fresh response checks blocked later heartbeats")
	}
	raw, _ := json.Marshal(replay)
	if err := initiator.receive(ctx, raw); err == nil {
		t.Fatal("asynchronous authority bypassed encrypted replay protection")
	}
	if gate.checks.Load() != 1 {
		t.Fatal("replayed ciphertext started another issuer check")
	}
	gate.unblock()
	for range calls {
		answer := awaitResponseResult(t, results)
		if answer.err != nil || answer.response.Status != 200 {
			t.Fatal("authorized response failed", answer.err)
		}
	}
	if gate.checks.Load() != 1 {
		t.Fatal("overlapping response waiters did not share one fresh check", gate.checks.Load())
	}
	if _, err := initiator.Call(ctx, Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity}); err != nil {
		t.Fatal(err)
	}
	if gate.checks.Load() != 3 {
		t.Fatal("later send/response reused a completed authorization result", gate.checks.Load())
	}
}

func TestResponseValidationAndDuplicateAdmissionPrecedeAuthorization(t *testing.T) {
	entered, release := make(chan struct{}, 8), make(chan struct{})
	var checks atomic.Int32
	e, s := responseUnitEndpoint(t, func(ctx context.Context) (iscpauth.Policy, error) {
		checks.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return iscpauth.Policy{}, ctx.Err()
		}
		return activeResponsePolicy(), nil
	})
	t.Cleanup(func() { close(release) })
	id, call := responsePending(e, t.Context())
	for _, raw := range []string{`{"unknown":"field"}`, `{"type":"task.result","profile":"sparkclaw.workbench.transport.v1","id":"` + id + `","status":999}`} {
		if e.acceptResponse(s.ctx, []byte(raw), s.id, time.Now()) == nil {
			t.Fatal("invalid response was queued")
		}
	}
	if err := e.acceptResponse(s.ctx, responseBytes(newUUID(), "orphan"), s.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if checks.Load() != 0 {
		t.Fatal("invalid/orphan response performed authorization")
	}
	for range 20 {
		if err := e.acceptResponse(s.ctx, responseBytes(id, "once"), s.id, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	awaitResponseSignal(t, entered)
	if checks.Load() != 1 {
		t.Fatal("duplicate response started multiple workers")
	}
	select {
	case <-call.result:
		t.Fatal("response delivered before authorization")
	default:
	}
	// Explicit release is deferred so assertions above all inspect the held
	// authorization state. Close cancellation is itself exercised below.
}

func TestDelayedResponseCannotAffectReplacementSessionOrReusedID(t *testing.T) {
	for _, outcome := range []string{"active", "transient-error"} {
		for _, replaceSession := range []bool{true, false} {
			t.Run(outcome+map[bool]string{true: "/new-session", false: "/same-session-new-call"}[replaceSession], func(t *testing.T) {
				entered, release := make(chan struct{}, 1), make(chan struct{})
				var checks atomic.Int32
				e, old := responseUnitEndpoint(t, func(context.Context) (iscpauth.Policy, error) {
					if checks.Add(1) == 1 {
						entered <- struct{}{}
						<-release
						if outcome == "transient-error" {
							return iscpauth.Policy{}, errors.New("temporary issuer failure")
						}
					}
					return activeResponsePolicy(), nil
				})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				t.Cleanup(unblock)
				id, original := responsePending(e, t.Context())
				if err := e.acceptResponse(old.ctx, responseBytes(id, "old private result"), old.id, time.Now()); err != nil {
					t.Fatal(err)
				}
				awaitResponseSignal(t, entered)
				e.mu.Lock()
				if replaceSession {
					e.resetLocked()
					e.session = newSession(t.Context(), newUUID(), session.LocalHello{})
					e.session.manifest = true
				}
				current := e.session
				replacement := &pendingCall{ctx: t.Context(), result: make(chan callResult, 1)}
				e.pending[id] = replacement
				e.stateName = "ready"
				e.mu.Unlock()
				unblock()
				waitResponseWorkers(t, e)
				e.mu.Lock()
				unchanged := e.session == current && e.pending[id] == replacement && e.stateName == "ready" && !e.authorizationRevoked
				e.mu.Unlock()
				if !unchanged {
					t.Fatal("late response worker changed replacement authority/session/call")
				}
				select {
				case <-replacement.result:
					t.Fatal("old response crossed the original pending channel fence")
				default:
				}
				if replaceSession {
					if answer := awaitResponseResult(t, original.result); answer.err == nil {
						t.Fatal("reset did not fail original pending call")
					}
				}
				if err := e.acceptResponse(current.ctx, responseBytes(id, "new result"), current.id, time.Now()); err != nil {
					t.Fatal(err)
				}
				answer := awaitResponseResult(t, replacement.result)
				if answer.err != nil || string(answer.response.Body) != `"new result"` {
					t.Fatal("replacement response was not independently authorized", answer.err)
				}
			})
		}
	}
}

func TestResponseAuthorizationCloseRevocationAndCallerCancellation(t *testing.T) {
	for _, action := range []string{"close", "revoke", "caller-cancel", "caller-deadline"} {
		t.Run(action, func(t *testing.T) {
			entered, release, canceled := make(chan struct{}, 1), make(chan struct{}), make(chan struct{})
			e, s := responseUnitEndpoint(t, func(ctx context.Context) (iscpauth.Policy, error) {
				entered <- struct{}{}
				<-ctx.Done()
				close(canceled)
				<-release
				return activeResponsePolicy(), nil
			})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			var ctx context.Context
			var cancel context.CancelFunc
			if action == "caller-deadline" {
				ctx, cancel = context.WithTimeout(t.Context(), 30*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(t.Context())
			}
			defer cancel()
			id, call := responsePending(e, ctx)
			if err := e.acceptResponse(s.ctx, responseBytes(id, "must not deliver"), s.id, time.Now()); err != nil {
				t.Fatal(err)
			}
			awaitResponseSignal(t, entered)
			switch action {
			case "close":
				_ = e.Close()
			case "revoke":
				e.observeAuthorizationError(iscpbridge.ErrAuthorizationRevoked)
			case "caller-cancel":
				cancel()
			}
			awaitResponseSignal(t, canceled)
			if action == "close" || action == "revoke" {
				if answer := awaitResponseResult(t, call.result); answer.err == nil {
					t.Fatal("terminal authority/lifetime did not fail pending call")
				}
			}
			// The authority stub deliberately returns active after cancellation;
			// the original channel/context fence must still prevent delivery.
			unblock()
			waitResponseWorkers(t, e)
			select {
			case answer := <-call.result:
				if answer.err == nil {
					t.Error("canceled authorization delivered response")
				}
			default:
			}
		})
	}
}

func TestResponseAuthorizationFailureIsFailClosedAndSignedRevokeIsTerminal(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "transient", true: "signed-revoke"}[revoked], func(t *testing.T) {
			err := errors.New("temporary issuer failure")
			if revoked {
				err = iscpbridge.ErrAuthorizationRevoked
			}
			e, s := responseUnitEndpoint(t, func(context.Context) (iscpauth.Policy, error) { return iscpauth.Policy{}, err })
			id, call := responsePending(e, t.Context())
			if err := e.acceptResponse(s.ctx, responseBytes(id, "private"), s.id, time.Now()); err != nil {
				t.Fatal(err)
			}
			if answer := awaitResponseResult(t, call.result); answer.err == nil {
				t.Fatal("failed authorization delivered private result")
			}
			waitResponseWorkers(t, e)
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.session != nil || e.authorizationRevoked != revoked {
				t.Fatal("authorization failure changed revocation semantics")
			}
			if revoked && e.stateName != "authorization_revoked" {
				t.Fatal("signed revoke did not remain terminal")
			}
		})
	}
}

func TestResponseAuthorizationRechecksGrantExpiryBeforeDelivery(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	e, s := responseUnitEndpoint(t, func(context.Context) (iscpauth.Policy, error) {
		entered <- struct{}{}
		<-release
		return activeResponsePolicy(), nil
	})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	id, call := responsePending(e, t.Context())
	if err := e.acceptResponse(s.ctx, responseBytes(id, "private"), s.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	awaitResponseSignal(t, entered)
	e.grantMu.Lock()
	e.material.grant.ExpiresAt = time.Now().Add(-time.Second)
	e.grantMu.Unlock()
	unblock()
	if answer := awaitResponseResult(t, call.result); answer.err == nil {
		t.Fatal("authorization wait extended expired Grant")
	}
}

func responseUnitEndpoint(t *testing.T, policy func(context.Context) (iscpauth.Policy, error)) (*Endpoint, *activeSession) {
	t.Helper()
	desktop, _ := testMaterials(t)
	e, err := newEndpoint(Config{Role: RoleInitiator}, desktop, &testRelay{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.authorityPolicy = policy
	e.session = newSession(t.Context(), newUUID(), session.LocalHello{})
	e.session.manifest = true
	e.stateName = "ready"
	t.Cleanup(func() { _ = e.Close() })
	return e, e.session
}
func responsePending(e *Endpoint, ctx context.Context) (string, *pendingCall) {
	id := newUUID()
	call := &pendingCall{ctx: ctx, result: make(chan callResult, 1)}
	e.mu.Lock()
	e.pending[id] = call
	e.mu.Unlock()
	return id, call
}
func responseBytes(id, body string) []byte {
	encoded, _ := json.Marshal(body)
	raw, _ := json.Marshal(Response{Type: ResponseType, Profile: Profile, ID: id, Status: 200, Body: encoded})
	return raw
}
func activeResponsePolicy() iscpauth.Policy {
	return iscpauth.Policy{Version: 2, Lifetime: iscpauth.UntilRevoked, Revision: 1, State: iscpauth.Active, Scopes: []string{"workbench.read"}}
}
func awaitResponseSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("response coordination did not reach expected state")
	}
}
func awaitResponseResult(t *testing.T, ch <-chan callResult) callResult {
	t.Helper()
	select {
	case answer := <-ch:
		return answer
	case <-time.After(3 * time.Second):
		t.Fatal("response call did not complete")
		return callResult{}
	}
}
func waitResponseWorkers(t *testing.T, e *Endpoint) {
	t.Helper()
	done := make(chan struct{})
	go func() { e.workers.Wait(); close(done) }()
	awaitResponseSignal(t, done)
}
