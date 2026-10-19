package main

import (
	"context"
	"sync"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpworkbench"
)

// reverseBridge carries only the registry's reverse operations through the same
// private pipe. Frame sizes and per-request deadlines remain bounded. It never
// listens on a socket or invokes a local tool.
type reverseBridge struct {
	mu      sync.Mutex
	writer  *ipcWriter
	pending map[string]chan iscpworkbench.Response
}

func newReverseBridge(w *ipcWriter) *reverseBridge {
	return &reverseBridge{writer: w, pending: map[string]chan iscpworkbench.Response{}}
}
func (b *reverseBridge) handle(ctx context.Context, r iscpworkbench.Request) iscpworkbench.Response {
	spec, ok := iscpworkbench.LookupOperation(r.Operation)
	if !ok || spec.Direction != "reverse" {
		return iscpworkbench.Response{Status: 403, Code: iscpworkbench.ErrorPermissionDenied, Error: "reverse operation denied"}
	}
	b.mu.Lock()
	ch := make(chan iscpworkbench.Response, 1)
	b.pending[r.ID] = ch
	b.mu.Unlock()
	defer func() { b.mu.Lock(); delete(b.pending, r.ID); b.mu.Unlock() }()
	if err := b.writer.send(map[string]any{"ipc_version": ipcVersion, "type": "reverse_request", "id": r.ID, "request": r}); err != nil {
		return iscpworkbench.Response{Status: 503, Code: iscpworkbench.ErrorOutcomeUnknown, Error: "host pipe unavailable"}
	}
	select {
	case response := <-ch:
		return response
	case <-ctx.Done():
		return iscpworkbench.Response{Status: 504, Code: iscpworkbench.ErrorOutcomeUnknown, Error: "host command outcome requires reconciliation"}
	}
}
func (b *reverseBridge) accept(id string, r iscpworkbench.Response) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ch := b.pending[id]; ch != nil && r.ID == id {
		select {
		case ch <- r:
		default:
		}
	}
}
