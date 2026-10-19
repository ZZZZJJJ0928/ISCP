package iscpnodecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
)

type authorityChangedRelay struct{ queuedRelay }

func (r authorityChangedRelay) RunOnceReady(_ context.Context, _ func(context.Context, json.RawMessage) error, ready func()) error {
	ready()
	return n.ErrUnavailable
}

func TestServiceAuthorityConnectionExitRetiresOldSessionAndPendingRPC(t *testing.T) {
	f := newHelloFixture(t)
	driveHello(t, f)
	original := currentSession(f.agent)
	f.agent.mu.Lock()
	oldState := f.agent.state
	ch := make(chan rpc, 1)
	f.agent.pending["old-request"] = pendingRPC{ch: ch, sessionID: original}
	f.agent.mu.Unlock()
	transport := f.agent.relay.(queuedRelay)
	f.agent.relay = authorityChangedRelay{transport}
	if err := f.agent.receiveContinuous(t.Context()); !errors.Is(err, n.ErrUnavailable) {
		t.Fatal(err)
	}
	f.agent.mu.Lock()
	retired := f.agent.state == nil && f.agent.local.Hello.SessionID == "" && len(f.agent.pending) == 0
	f.agent.mu.Unlock()
	if !retired || f.agent.Ready() {
		t.Fatal("old authority retained ready E2E state")
	}
	select {
	case reply := <-ch:
		if reply.Error != "unavailable" {
			t.Fatal("pending call was completed falsely")
		}
	default:
		t.Fatal("pending call was not fenced")
	}
	f.agent.relay = transport
	driveHello(t, f)
	f.agent.mu.Lock()
	defer f.agent.mu.Unlock()
	if f.agent.state == oldState || f.agent.state.SessionID == original {
		t.Fatal("new connection reused old session/key state")
	}
}
