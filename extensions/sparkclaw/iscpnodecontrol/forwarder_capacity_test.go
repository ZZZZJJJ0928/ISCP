package iscpnodecontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

type waitingCaller struct {
	entered chan struct{}
	release <-chan struct{}
}

func (c waitingCaller) Call(ctx context.Context, _ string, _, out any) error {
	c.entered <- struct{}{}
	select {
	case <-c.release:
		*out.(*n.ExchangeResponse) = n.ExchangeResponse{Version: 1, Frame: json.RawMessage(`{}`)}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestForwarderHasNoFixedInflightQuota(t *testing.T) {
	const count = 80
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{}, count)
	f, err := NewForwarder("node-a", waitingCaller{entered, release}, &verifyingAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewForwarderRouter([]*Forwarder{f})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan int, count)
	for i := 0; i < count; i++ {
		go func(i int) {
			raw := fmt.Sprintf(`{"version":1,"issuer_route":"node-a","operation_id":"operation-%d","invitation_id":"invitation-id","step":"hello","frame":{}}`, i)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, n.ExchangePath, strings.NewReader(raw)))
			finished <- w.Code
		}(i)
	}
	for i := 0; i < count; i++ {
		select {
		case <-entered:
		case status := <-finished:
			t.Fatalf("request rejected before upstream completed: %d", status)
		case <-time.After(3 * time.Second):
			t.Fatal("forwarding did not admit all cancellable requests")
		}
	}
}

func TestPeerHasNoFixedPendingOrHandlerQuota(t *testing.T) {
	const count = 80
	f := newHelloFixture(t)
	driveHello(t, f)
	quietHello(t, f)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{}, count)
	f.agent.SetHandler(func(ctx context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return json.RawMessage(`{"ok":true}`), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	finished := make(chan error, count)
	for i := 0; i < count; i++ {
		go func() { finished <- f.broker.Call(ctx, "issuer.exchange", map[string]string{"frame": "opaque"}, nil) }()
		// Deliver requests in production send order while keeping all previous
		// upstream calls pending. No quota may reject the 17th or 65th call.
		tick := time.NewTicker(time.Millisecond)
		waiting := true
		for waiting {
			select {
			case <-tick.C:
				drainHello(t, f.agent, f.broker)
			case <-entered:
				waiting = false
			case err := <-finished:
				t.Fatalf("call %d ended before upstream response: %v", i, err)
			case <-ctx.Done():
				t.Fatalf("call %d never reached handler", i)
			}
		}
		tick.Stop()
	}
	cancel()
	for i := 0; i < count; i++ {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("canceled pending call did not release")
		}
	}
	f.broker.mu.Lock()
	remaining := len(f.broker.pending)
	f.broker.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("cancellation leaked %d pending calls", remaining)
	}
}

func TestControlProofReceiptsHaveNoRequestQuotaAndRetainReplayFence(t *testing.T) {
	f := newHelloFixture(t)
	first := ControlGrantUpdate{Version: 1, IssuerRoute: "node-a", Grant: f.broker.cfg.Grant, Proof: identity.DeviceProof{Nonce: "proof-0", IssuedAt: time.Now().UTC()}}
	for i := 0; i < 150; i++ {
		req := first
		req.Proof.Nonce = fmt.Sprintf("proof-%d", i)
		if err := f.broker.recordGrantProof(req); err != nil {
			t.Fatalf("valid proof receipt hit request quota at %d: %v", i, err)
		}
	}
	if err := f.broker.recordGrantProof(first); err != nil {
		t.Fatalf("exact receipt replay changed: %v", err)
	}
	first.Grant.GrantID = "changed-under-original-nonce"
	if err := f.broker.recordGrantProof(first); err != n.ErrDenied {
		t.Fatalf("receipt quota removal lost replay protection: %v", err)
	}
}
