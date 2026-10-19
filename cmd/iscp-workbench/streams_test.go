package main

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpworkbench"
)

type observedStreamCaller struct {
	pipeCaller
	stopped chan struct{}
}

func (c *observedStreamCaller) StreamCall(ctx context.Context, r iscpworkbench.Request, emit func(json.RawMessage) error) (iscpworkbench.Response, error) {
	if err := emit(json.RawMessage(`{"verified":true}`)); err != nil {
		return iscpworkbench.Response{}, err
	}
	<-ctx.Done()
	close(c.stopped)
	return iscpworkbench.Response{}, ctx.Err()
}

type ipcCapture struct {
	frames chan map[string]json.RawMessage
}

func (w *ipcCapture) Write(raw []byte) (int, error) {
	var frame map[string]json.RawMessage
	if err := json.Unmarshal(raw, &frame); err != nil {
		return 0, err
	}
	w.frames <- frame
	return len(raw), nil
}
func TestPipeStreamEventsCarryAuthorityAndCancelOnlyObservation(t *testing.T) {
	input, feed := io.Pipe()
	defer input.Close()
	defer feed.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	caller := &observedStreamCaller{stopped: make(chan struct{})}
	capture := &ipcCapture{frames: make(chan map[string]json.RawMessage, 8)}
	done := make(chan error, 1)
	go func() { done <- serve(ctx, input, &ipcWriter{writer: capture}, caller) }()
	send := func(frame any) {
		t.Helper()
		raw, err := json.Marshal(frame)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = feed.Write(append(raw, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	next := func() map[string]json.RawMessage {
		t.Helper()
		select {
		case f := <-capture.frames:
			return f
		case <-ctx.Done():
			t.Fatal("IPC response missing")
			return nil
		}
	}
	id := "11111111-1111-4111-8111-111111111111"
	request := iscpworkbench.Request{Type: iscpworkbench.RequestType, Profile: iscpworkbench.ProfileV2, ID: id, RequestID: "22222222-2222-4222-8222-222222222222", InstallationID: "33333333-3333-4333-8333-333333333333", Operation: iscpworkbench.OperationExecutionProgressStream, Body: json.RawMessage(`{"schema_version":1}`)}
	send(map[string]any{"ipc_version": 1, "type": "stream_call", "id": id, "request": request})
	frame := next()
	if string(frame["type"]) != `"stream_event"` || string(frame["authority_valid_for_ms"]) != "60000" || string(frame["id"]) != `"`+id+`"` {
		t.Fatalf("event lost verified authority/binding: %+v", frame)
	}
	// An ordinary RPC is usable while the stream observer remains active.
	send(map[string]any{"ipc_version": 1, "type": "call", "id": "ordinary", "request": iscpworkbench.Request{Type: iscpworkbench.RequestType, Profile: iscpworkbench.ProfileV2, ID: "44444444-4444-4444-8444-444444444444", Operation: iscpworkbench.OperationIdentity}})
	frame = next()
	if string(frame["id"]) != `"ordinary"` {
		t.Fatalf("ordinary RPC blocked: %+v", frame)
	}
	send(map[string]any{"ipc_version": 1, "type": "stream_cancel", "id": id})
	select {
	case <-caller.stopped:
	case <-ctx.Done():
		t.Fatal("observer cancellation lost")
	}
	frame = next()
	if string(frame["type"]) != `"response"` || string(frame["id"]) != `"`+id+`"` {
		t.Fatalf("completion binding lost: %+v", frame)
	}
	send(map[string]any{"ipc_version": 1, "type": "shutdown"})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("helper did not stop")
	}
}

type finiteAuthorityCaller struct {
	pipeCaller
	deadline time.Time
}

func (c *finiteAuthorityCaller) StreamCall(ctx context.Context, r iscpworkbench.Request, emit func(json.RawMessage) error) (iscpworkbench.Response, error) {
	c.deadline = time.Now().Add(150 * time.Millisecond)
	err := emit(json.RawMessage(`{"verified":true}`))
	return iscpworkbench.Response{Type: iscpworkbench.ResponseType, Profile: r.Profile, ID: r.ID, Status: 200}, err
}
func (c *finiteAuthorityCaller) StreamAuthorityRemaining(string) (time.Duration, error) {
	return time.Until(c.deadline), nil
}

type blockedIPCWriter struct {
	ipcCapture
	entered chan struct{}
	release chan struct{}
	once    bool
}

func (w *blockedIPCWriter) Write(raw []byte) (int, error) {
	if !w.once {
		w.once = true
		close(w.entered)
		<-w.release
	}
	return w.ipcCapture.Write(raw)
}
func TestPipeQueueDelayCannotMoveRelativeAuthorityDeadline(t *testing.T) {
	input, feed := io.Pipe()
	defer input.Close()
	defer feed.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	caller := &finiteAuthorityCaller{}
	output := &blockedIPCWriter{ipcCapture: ipcCapture{frames: make(chan map[string]json.RawMessage, 4)}, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- serve(ctx, input, &ipcWriter{writer: output}, caller) }()
	id := "11111111-1111-4111-8111-111111111111"
	request := iscpworkbench.Request{Type: iscpworkbench.RequestType, Profile: iscpworkbench.ProfileV2, ID: id, RequestID: "22222222-2222-4222-8222-222222222222", InstallationID: "33333333-3333-4333-8333-333333333333", Operation: iscpworkbench.OperationExecutionProgressStream, Body: json.RawMessage(`{"schema_version":1}`)}
	raw, _ := json.Marshal(map[string]any{"ipc_version": 1, "type": "stream_call", "id": id, "request": request})
	sent := time.Now()
	if _, err := feed.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	select {
	case <-output.entered:
	case <-ctx.Done():
		t.Fatal("event did not reach pipe")
	}
	time.Sleep(time.Until(caller.deadline) + 20*time.Millisecond)
	close(output.release)
	var frame map[string]json.RawMessage
	select {
	case frame = <-output.frames:
	case <-ctx.Done():
		t.Fatal("blocked event not released")
	}
	var deadline int64
	if err := json.Unmarshal(frame["authority_deadline_ms"], &deadline); err != nil {
		t.Fatal(err)
	}
	if deadline <= 0 || deadline >= time.Since(sent).Milliseconds() {
		t.Fatalf("queued event renewed authority: deadline=%d elapsed=%d", deadline, time.Since(sent).Milliseconds())
	}
	// This elapsed deadline is rejected by the paired Electron transport, even
	// though the old event still carries its originally sampled valid_for value.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("helper cleanup failed")
	}
}
