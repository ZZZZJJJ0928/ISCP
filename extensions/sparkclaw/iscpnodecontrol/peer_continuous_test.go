package iscpnodecontrol

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

type continuousControlRelay struct {
	queuedRelay
	connections atomic.Int32
}

func (r *continuousControlRelay) RunOnceReady(ctx context.Context, handle func(context.Context, json.RawMessage) error, ready func()) error {
	r.connections.Add(1)
	ready()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := r.queuedRelay.RunOnceReady(ctx, handle, func() {}); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func TestContinuousControlReceiveReestablishesRotatedSessionWithoutSocketRotation(t *testing.T) {
	f := newHelloFixture(t)
	agentRelay := &continuousControlRelay{queuedRelay: f.agent.relay.(queuedRelay)}
	brokerRelay := &continuousControlRelay{queuedRelay: f.broker.relay.(queuedRelay)}
	f.agent.relay, f.broker.relay = agentRelay, brokerRelay
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	finished := make(chan error, 2)
	go func() { finished <- f.agent.Run(ctx) }()
	go func() { finished <- f.broker.Run(ctx) }()
	defer func() {
		cancel()
		for i := 0; i < 2; i++ {
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Error("continuous control receive did not stop")
			}
		}
	}()
	awaitReady := func() {
		t.Helper()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for !f.agent.Ready() || !f.broker.Ready() {
			select {
			case <-ctx.Done():
				t.Fatal("continuous receive never established session")
			case <-ticker.C:
			}
		}
	}
	awaitReady()
	original := currentSession(f.agent)
	f.agent.mu.Lock()
	grant := f.agent.cfg.Grant
	f.agent.mu.Unlock()
	grant.GrantID = "continuous-replacement-grant"
	grant.NotBefore = time.Now().UTC()
	grant.ExpiresAt = grant.NotBefore.Add(time.Hour)
	grant.RevocationEpoch++
	grant, err := trust.SignGrant(c.NewProvider(), f.signer, grant)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.agent.UpdateGrant(grant); err != nil {
		t.Fatal(err)
	}
	if err := f.broker.UpdateGrant(grant); err != nil {
		t.Fatal(err)
	}
	awaitReady()
	if currentSession(f.agent) == original || agentRelay.connections.Load() != 1 || brokerRelay.connections.Load() != 1 {
		t.Fatal("grant rotation depended on replacing the healthy receive socket")
	}
	var out struct {
		OK bool `json:"ok"`
	}
	if err := f.broker.Call(ctx, "issuer.exchange", map[string]string{"frame": "opaque"}, &out); err != nil || !out.OK {
		t.Fatalf("rotated session failed RPC: %+v %v", out, err)
	}
}
