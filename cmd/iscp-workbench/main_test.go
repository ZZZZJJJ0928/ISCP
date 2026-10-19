package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpworkbench"
)

type concurrentPipeCaller struct {
	pipeCaller
	entered chan struct{}
}

func (c *concurrentPipeCaller) Call(ctx context.Context, r iscpworkbench.Request) (iscpworkbench.Response, error) {
	c.entered <- struct{}{}
	<-ctx.Done()
	return iscpworkbench.Response{Type: iscpworkbench.ResponseType, Profile: r.Profile, ID: r.ID, Status: 503}, nil
}

func TestHelperPipeDoesNotImposeBusinessOrControlQuotas(t *testing.T) {
	const count = 80
	input, feed := io.Pipe()
	defer input.Close()
	defer feed.Close()
	caller := &concurrentPipeCaller{entered: make(chan struct{}, count)}
	var output bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { err := serve(ctx, input, &ipcWriter{writer: &output}, caller); _ = input.Close(); done <- err }()
	for j := 0; j < count; j++ {
		operation := iscpworkbench.OperationIdentity
		if j >= 40 {
			operation = iscpworkbench.OperationAck
		}
		requestID := fmt.Sprintf("00000000-0000-4000-8000-%012x", j+1)
		raw, _ := json.Marshal(map[string]any{"ipc_version": 1, "type": "call", "id": fmt.Sprintf("pipe-%d", j), "request": iscpworkbench.Request{Type: iscpworkbench.RequestType, Profile: iscpworkbench.Profile, ID: requestID, RequestID: requestID, Operation: operation}})
		if _, err := feed.Write(append(raw, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	for j := 0; j < count; j++ {
		select {
		case <-caller.entered:
		case <-time.After(time.Second):
			t.Fatal("helper rejected or blocked a parallel request")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("helper leaked in-flight calls on shutdown")
	}
}

type reverseRecordWriter struct{ requests chan iscpworkbench.Request }

func (w *reverseRecordWriter) Write(raw []byte) (int, error) {
	var frame struct {
		Request iscpworkbench.Request `json:"request"`
	}
	if err := json.Unmarshal(raw, &frame); err != nil {
		return 0, err
	}
	w.requests <- frame.Request
	return len(raw), nil
}

func TestReversePipeRemovesWindowQuotaAndKeepsResponseAndCancellationBinding(t *testing.T) {
	const count = 80
	recorded := &reverseRecordWriter{requests: make(chan iscpworkbench.Request, count)}
	bridge := newReverseBridge(&ipcWriter{writer: recorded})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	results := make(chan iscpworkbench.Response, count)
	for j := 0; j < count; j++ {
		request := iscpworkbench.Request{ID: fmt.Sprintf("reverse-%d", j), Operation: iscpworkbench.OperationBrowserCommand}
		go func() { results <- bridge.handle(ctx, request) }()
	}
	requests := make([]iscpworkbench.Request, 0, count)
	for j := 0; j < count; j++ {
		select {
		case request := <-recorded.requests:
			requests = append(requests, request)
		case response := <-results:
			t.Fatalf("reverse request rejected before pipe dispatch: %+v", response)
		case <-ctx.Done():
			t.Fatal("reverse pipe still has an artificial window quota")
		}
	}
	bridge.accept(requests[0].ID, iscpworkbench.Response{ID: "wrong-id", Status: 200})
	for _, request := range requests[:count/2] {
		bridge.accept(request.ID, iscpworkbench.Response{ID: request.ID, Status: 200})
	}
	for j := 0; j < count/2; j++ {
		select {
		case response := <-results:
			if response.Status != 200 || response.ID == "wrong-id" {
				t.Fatalf("response binding lost: %+v", response)
			}
		case <-ctx.Done():
			t.Fatal("original reverse response did not arrive")
		}
	}
	cancel()
	for j := 0; j < count/2; j++ {
		if response := <-results; response.Status != 504 || response.Code != iscpworkbench.ErrorOutcomeUnknown {
			t.Fatalf("canceled reverse request lost unknown-outcome fence: %+v", response)
		}
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if len(bridge.pending) != 0 {
		t.Fatal("reverse request leaked after cancellation")
	}
}

func TestPrivateIPCOriginalBodyAndSchema(t *testing.T) {
	body := []byte("{\n \"text\": \"original\"\n}")
	frame := map[string]any{"ipc_version": 1, "type": "call", "id": "pipe-call", "body_base64": base64.StdEncoding.EncodeToString(body), "request": map[string]any{"type": iscpworkbench.RequestType, "profile": iscpworkbench.Profile, "id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "operation": iscpworkbench.OperationIdentity}}
	raw, _ := json.Marshal(frame)
	decoded, err := decodeCall(raw)
	if err != nil || !bytes.Equal(decoded.Request.Body, body) {
		t.Fatalf("original body lost: %s %v", decoded.Request.Body, err)
	}
	for _, raw := range []string{`{"ipc_version":2,"type":"shutdown"}`, `{"ipc_version":1,"type":"shutdown","token":"secret"}`, `{"ipc_version":1,"type":"shutdown"} {}`, `{"ipc_version":1,"type":"call","id":"x","request":{"type":"task.invoke","profile":"sparkclaw.workbench.transport.v1","id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","operation":"http.proxy"}}`} {
		if _, err := decodeCall([]byte(raw)); err == nil {
			t.Fatalf("invalid frame accepted %s", raw)
		}
	}
}

type pipeCaller struct {
	mu     sync.Mutex
	body   []byte
	closed bool
}

func (c *pipeCaller) Run(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
func (c *pipeCaller) Close() error                  { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *pipeCaller) Call(ctx context.Context, request iscpworkbench.Request) (iscpworkbench.Response, error) {
	c.mu.Lock()
	c.body = append([]byte(nil), request.Body...)
	c.mu.Unlock()
	return iscpworkbench.Response{Type: iscpworkbench.ResponseType, Profile: iscpworkbench.Profile, ID: request.ID, Status: 200}, nil
}

func TestEOFAndShutdownCloseHelper(t *testing.T) {
	for _, input := range []string{"", `{"ipc_version":1,"type":"shutdown"}` + "\n"} {
		caller := &pipeCaller{}
		var output bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := serve(ctx, strings.NewReader(input), &ipcWriter{writer: &output}, caller)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		caller.mu.Lock()
		closed := caller.closed
		caller.mu.Unlock()
		if !closed {
			t.Fatal("helper did not close endpoint")
		}
	}
}

func (c *pipeCaller) DeleteAuthorization(context.Context, string, uint64) (iscpauth.DeletionReceipt, error) {
	return iscpauth.DeletionReceipt{}, nil
}
func (c *pipeCaller) AuthorizationDeletionReceipt(context.Context, string, uint64) (iscpauth.DeletionReceipt, error) {
	return iscpauth.DeletionReceipt{}, nil
}

func TestControlOnlyRejectsBusinessPipeFrames(t *testing.T) {
	body := `{"ipc_version":1,"type":"call","id":"x","request":{"type":"task.invoke","profile":"sparkclaw.workbench.transport.v1","id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","operation":"workbench.identity"}}` + "\n"
	var output bytes.Buffer
	err := serveFrames(context.Background(), strings.NewReader(body), &ipcWriter{writer: &output}, &pipeCaller{}, nil, true)
	if err == nil {
		t.Fatal("control-only pipe accepted a business call")
	}
}
func TestDeletionControlSchema(t *testing.T) {
	valid := `{"ipc_version":1,"type":"authorization_delete_receipt","id":"receipt","operation_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","expected_revision":1}`
	if _, err := decodeCall([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCall([]byte(strings.Replace(valid, `"expected_revision":1`, `"expected_revision":0`, 1))); err == nil {
		t.Fatal("zero deletion revision accepted")
	}
}

func (c *pipeCaller) StreamCall(ctx context.Context, r iscpworkbench.Request, onEvent func(json.RawMessage) error) (iscpworkbench.Response, error) {
	return c.Call(ctx, r)
}

func (c *pipeCaller) StreamAuthorityRemaining(string) (time.Duration, error) { return time.Minute, nil }
