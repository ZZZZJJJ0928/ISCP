package iscpworkbench

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/appstream"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
)

func streamTestRequest() Request {
	return Request{Type: RequestType, Profile: ProfileV2, ID: newUUID(), RequestID: newUUID(), InstallationID: newUUID(), Operation: OperationExecutionProgressStream, Body: json.RawMessage(fmt.Sprintf(`{"schema_version":1,"input_digest":"%s","latest_open_at":"%s"}`, strings.Repeat("a", 64), time.Now().UTC().Add(10*time.Second).Format(time.RFC3339Nano)))}
}

func TestStreamCallRejectsNullBodyWithoutResettingSession(t *testing.T) {
	i, _, _ := v2Endpoints(t, true)
	r := streamTestRequest()
	r.Body = json.RawMessage(`null`)
	if _, err := i.StreamCall(t.Context(), r, func(json.RawMessage) error { return nil }); !errors.Is(err, appstream.ErrInvalid) {
		t.Fatalf("null stream body: %v", err)
	}
	response, err := i.Call(t.Context(), Request{Type: RequestType, Profile: ProfileV2, ID: newUUID(), Operation: OperationSettingsOwnerGet})
	if err != nil || response.Status != 200 {
		t.Fatalf("unrelated call lost: %+v %v", response, err)
	}
}

func TestStreamOpeningDeadlineIncludesSendTime(t *testing.T) {
	e, s := streamAuthorityUnitEndpoint(t, nil)
	p := recoveryPending(t.Context())
	p.openDeadline = time.Now().Add(-time.Millisecond)
	id := newUUID()
	p.events <- recoveryFrame(t, id, 1, "already queued")
	_, err := e.consumeStream(s, p, id, func(json.RawMessage) error { t.Fatal("published after opening deadline"); return nil })
	if err == nil || !strings.Contains(err.Error(), "opening deadline") {
		t.Fatalf("restarted opening window: %v", err)
	}
}

func TestEncryptedStreamIsIncrementalAndDoesNotWaitForPerBatchAuthority(t *testing.T) {
	allowFinish := make(chan struct{})
	produced := make(chan struct{})
	i, r, _ := profileEndpoints(t, true, true, func(ctx context.Context, request Request) Response {
		if request.Operation != OperationExecutionProgressStream {
			return Response{Status: 200}
		}
		w, ok := StreamFromContext(ctx)
		if !ok {
			t.Error("missing stream writer")
			return Response{Status: 500}
		}
		for n := 0; n < 6; n++ {
			if err := w.Send(ctx, json.RawMessage(fmt.Sprintf(`{"text":"你好","batch":%d}`, n))); err != nil {
				return Response{Status: 500}
			}
			if n == 0 {
				close(produced)
			}
			select {
			case <-ctx.Done():
				return Response{Status: 500}
			case <-time.After(10 * time.Millisecond):
			}
		}
		select {
		case <-allowFinish:
		case <-ctx.Done():
		}
		return Response{Status: 200, Body: json.RawMessage(`{"reason":"terminal"}`)}
	})
	var checks atomic.Int32
	for _, e := range []*Endpoint{i, r} {
		e.authorityPolicy = func(context.Context) (iscpauth.Policy, error) {
			checks.Add(1)
			return iscpauth.Policy{Version: 2, State: iscpauth.Active, Revision: 1, Scopes: []string{"workbench.text"}}, nil
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	got := make(chan uint64, 8)
	done := make(chan error, 1)
	go func() {
		response, err := i.StreamCall(ctx, streamTestRequest(), func(raw json.RawMessage) error {
			f, err := appstream.Decode(raw)
			if err == nil {
				got <- f.StreamSeq
			}
			return err
		})
		if err == nil && response.Status != 200 {
			err = fmt.Errorf("status %d", response.Status)
		}
		done <- err
	}()
	<-produced
	for n := uint64(1); n <= 6; n++ {
		select {
		case seq := <-got:
			if seq != n {
				t.Fatalf("sequence %d", seq)
			}
		case <-ctx.Done():
			t.Fatal("did not receive increments before completion")
		}
	}
	if checks.Load() != 2 {
		t.Fatalf("per-batch authority query: %d", checks.Load())
	}
	close(allowFinish)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStreamCancellationLeavesOrdinaryCallsAndTaskAlone(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	i, _, _ := profileEndpoints(t, true, true, func(ctx context.Context, r Request) Response {
		if r.Operation == OperationExecutionProgressStream {
			close(started)
			<-ctx.Done()
			close(stopped)
		}
		return Response{Status: 200}
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := i.StreamCall(ctx, streamTestRequest(), func(json.RawMessage) error { return nil })
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not open")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("remote observer leaked")
	}
	response, err := i.Call(t.Context(), Request{Type: RequestType, Profile: ProfileV2, ID: newUUID(), Operation: OperationSettingsOwnerGet})
	if err != nil || response.Status != 200 {
		t.Fatalf("unrelated RPC lost: %v %+v", err, response)
	}
}

func TestFailedCiphertextCannotAdvanceReceiveSequence(t *testing.T) {
	i, r, _ := v2Endpoints(t, true)
	r.mu.Lock()
	s := r.session
	raw, _ := json.Marshal(map[string]string{"nonce": newUUID()})
	env, err := envelope.Encrypt(r.provider, s.state, newUUID(), pongType, envelope.Route{RelayID: r.material.enrollment.RelayID, TTLSeconds: 30, Priority: 5}, raw)
	r.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	bad := env
	bad.Ciphertext = "AAAA"
	if i.acceptEncrypted(t.Context(), bad) == nil {
		t.Fatal("forged ciphertext accepted")
	}
	if err = i.acceptEncrypted(t.Context(), env); err != nil {
		t.Fatalf("forgery consumed authentic sequence: %v", err)
	}
	if i.acceptEncrypted(t.Context(), env) == nil {
		t.Fatal("authenticated replay accepted")
	}
}
