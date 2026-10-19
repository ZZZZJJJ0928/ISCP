package iscpnodecontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
)

type routeCaller struct {
	route string
	calls atomic.Int32
}

func (c *routeCaller) Call(ctx context.Context, method string, in, out any) error {
	c.calls.Add(1)
	x, ok := in.(n.Exchange)
	if !ok || x.IssuerRoute != c.route || method != "issuer.exchange" {
		return n.ErrDenied
	}
	*out.(*n.ExchangeResponse) = n.ExchangeResponse{Version: 1, OperationID: x.OperationID, Step: x.Step, Frame: json.RawMessage(`{}`)}
	return nil
}
func TestRouterExactRouteBoundedRequestsAndFailureIsolation(t *testing.T) {
	ca, cb := &routeCaller{route: "node-a"}, &routeCaller{route: "node-b"}
	a, e := NewForwarder(ca.route, ca, &verifyingAdapter{})
	if e != nil {
		t.Fatal(e)
	}
	b, e := NewForwarder(cb.route, cb, &verifyingAdapter{})
	if e != nil {
		t.Fatal(e)
	}
	h, e := NewForwarderRouter([]*Forwarder{a, b})
	if e != nil {
		t.Fatal(e)
	}
	post := func(raw string, path string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(raw)))
		return w.Code
	}
	request := func(route string) string {
		raw, _ := json.Marshal(n.Exchange{Version: 1, IssuerRoute: route, OperationID: "shared-operation-id", InvitationID: "invitation-id", Step: "hello", Frame: json.RawMessage(`{}`)})
		return string(raw)
	}
	if post(request("node-a"), n.ExchangePath) != 200 || post(request("node-b"), n.ExchangePath) != 200 || ca.calls.Load() != 1 || cb.calls.Load() != 1 {
		t.Fatal("route isolation failed")
	}
	if post(request("unknown"), n.ExchangePath) != 403 {
		t.Fatal("unknown route accepted")
	}
	if post(strings.Replace(request("node-a"), `"issuer_route":"node-a"`, `"issuer_route":"node-a","issuer_route":"node-b"`, 1), n.ExchangePath) != 400 {
		t.Fatal("duplicate routing field accepted")
	}
	if post(request("node-a")+strings.Repeat(" ", n.MaxFrameBytes), n.ExchangePath) != 400 {
		t.Fatal("oversized body accepted")
	}
	// More than the former per-minute allowance still uses exact routing.
	for i := 0; i < 650; i++ {
		if post(request("node-a"), n.ExchangePath) != 200 {
			t.Fatalf("artificial forwarding quota at request %d", i)
		}
	}
	if post(request("node-b"), n.ExchangePath) != 200 {
		t.Fatal("one authority's traffic blocked another authority")
	}
	if _, e = NewForwarderRouter([]*Forwarder{a, a}); e == nil {
		t.Fatal("duplicate route configuration accepted")
	}
	// Control-grant selection uses the same strict route parser; the selected
	// original handler still requires the independently pinned service peer.
	if post(`{"version":1,"issuer_route":"unknown","identity":{},"grant":{},"proof":{}}`, ControlGrantPath) != 403 {
		t.Fatal("unknown control-grant route accepted")
	}
	if post(`{"version":1,"issuer_route":"node-b","identity":{},"grant":{},"proof":{}}`, ControlGrantPath) != 403 {
		t.Fatal("unverified control-grant identity accepted")
	}
}

func TestForwarderConfigKeepsSchemaOneAndRejectsAmbiguousSchemaTwo(t *testing.T) {
	original := ForwarderConfig{SchemaVersion: 1, Bind: "127.0.0.1:55127", IssuerRoute: "legacy-route", PeerConfigFile: "/private/legacy-peer.json", RelaySocket: "/run/legacy.sock"}
	if original.Validate() != nil || len(original.NodeConfigs()) != 1 {
		t.Fatal("legacy config refused")
	}
	cfg := ForwarderConfig{SchemaVersion: 2, Bind: original.Bind, Nodes: []ForwarderNodeConfig{{"node-a", "/private/a.json", "/run/a.sock"}, {"node-b", "/private/b.json", "/run/b.sock"}}}
	if cfg.Validate() != nil {
		t.Fatal("valid multiple nodes refused")
	}
	for _, field := range []string{"route", "peer", "socket", "legacy", "bind"} {
		raw, _ := json.Marshal(cfg)
		var changed ForwarderConfig
		json.Unmarshal(raw, &changed)
		switch field {
		case "route":
			changed.Nodes[1].IssuerRoute = changed.Nodes[0].IssuerRoute
		case "peer":
			changed.Nodes[1].PeerConfigFile = changed.Nodes[0].PeerConfigFile
		case "socket":
			changed.Nodes[1].RelaySocket = changed.Nodes[0].RelaySocket
		case "legacy":
			changed.IssuerRoute = "legacy-route"
		case "bind":
			changed.Bind = "0.0.0.0:55127"
		}
		if changed.Validate() == nil {
			t.Fatal("ambiguous config accepted", field)
		}
	}
	raw, _ := json.Marshal(cfg)
	bad := bytes.Replace(raw, []byte(`"schema_version":2`), []byte(`"schema_version":2,"schema_version":1`), 1)
	var parsed ForwarderConfig
	if n.StrictDecode(bad, &parsed) == nil {
		t.Fatal("duplicate config field accepted")
	}
}
