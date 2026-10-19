package iscpnodecontrol

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

func TestControlGrantReplacementFencesInflightAndSuppressesOldWorkerReply(t *testing.T) {
	f := newHelloFixture(t)
	driveHello(t, f)
	quietHello(t, f)
	entered, release := make(chan struct{}), make(chan struct{})
	f.broker.SetHandler(func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		close(entered)
		<-release
		return json.RawMessage(`{"ok":true}`), nil
	})
	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		result <- f.agent.Call(ctx, "durable-original-operation", map[string]string{"operation_id": "unchanged-operation-id"}, nil)
	}()
	for i := 0; i < 50; i++ {
		drainHello(t, f.agent, f.broker)
		select {
		case <-entered:
			goto admitted
		default:
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("control request did not arrive")
admitted:
	g := f.agent.cfg.Grant
	g.GrantID = "replacement-control-grant"
	g.NotBefore = time.Now().UTC()
	g.ExpiresAt = g.NotBefore.Add(time.Hour)
	g.RevocationEpoch++
	g, e := trust.SignGrant(c.NewProvider(), f.signer, g)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.agent.UpdateGrant(g); e != nil {
		t.Fatal(e)
	}
	if e = f.broker.UpdateGrant(g); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-result:
		if e != n.ErrUnavailable {
			t.Fatal("old inflight survived the Grant boundary", e)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("pending call was not released on Grant replacement")
	}
	driveHello(t, f)
	quietHello(t, f)
	f.hub.mu.Lock()
	before := len(f.hub.messages)
	f.hub.mu.Unlock()
	close(release)
	time.Sleep(10 * time.Millisecond)
	f.hub.mu.Lock()
	after := len(f.hub.messages)
	f.hub.mu.Unlock()
	if after != before {
		t.Fatal("old-session worker reply was sent under the replacement session")
	}
	if !f.agent.Ready() || !f.broker.Ready() {
		t.Fatal("old worker invalidated the replacement session")
	}
}
