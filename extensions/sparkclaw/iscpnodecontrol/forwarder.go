package iscpnodecontrol

import (
	"context"
	"encoding/json"
	"errors"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"io"
	"net/http"
	"sync"
	"time"
)

type Caller interface {
	Call(context.Context, string, any, any) error
}
type Forwarder struct {
	Route     string
	Peer      Caller
	Adapter   n.RelayRegistration
	controlMu sync.Mutex
}

func NewForwarder(route string, peer Caller, adapter n.RelayRegistration) (*Forwarder, error) {
	if !issuerRoutePattern.MatchString(route) || peer == nil || adapter == nil {
		return nil, n.ErrInvalid
	}
	return &Forwarder{Route: route, Peer: peer, Adapter: adapter}, nil
}
func (f *Forwarder) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" || (r.URL.Path != n.ExchangePath && r.URL.Path != ControlGrantPath) || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		if f.handleControlGrant(w, r) {
			return
		}
		b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, n.MaxFrameBytes))
		if e != nil {
			writeError(w, 400, "invalid")
			return
		}
		var x n.Exchange
		if n.StrictDecode(b, &x) != nil || x.Validate() != nil {
			writeError(w, 400, "invalid")
			return
		}
		if x.IssuerRoute != f.Route {
			writeError(w, 403, "denied")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var out n.ExchangeResponse
		e = f.Peer.Call(ctx, "issuer.exchange", x, &out)
		if e != nil {
			status := 503
			switch {
			case errors.Is(e, n.ErrInvalid):
				status = 400
			case errors.Is(e, n.ErrDenied):
				status = 403
			case errors.Is(e, n.ErrConflict):
				status = 409
			case errors.Is(e, n.ErrExpired):
				status = 410
			}
			writeError(w, status, errorCode(e))
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	})
}
func writeError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(n.WireError{Version: 1, Code: code})
}

// PrivateHandler is invoked only after the independently pinned control peer's
// authenticated Ready and envelope verification. It is never an HTTP surface.
func (f *Forwarder) PrivateHandler(ctx context.Context, method string, raw json.RawMessage) (json.RawMessage, error) {
	switch method {
	case "relay.prepare":
		var p n.RegistrationPreparation
		if n.StrictDecode(raw, &p) != nil {
			return nil, n.ErrInvalid
		}
		if e := f.Adapter.Prepare(ctx, p); e != nil {
			return nil, e
		}
		return json.Marshal(map[string]any{"ok": true})
	case "relay.commit":
		var p n.RegistrationCommit
		if n.StrictDecode(raw, &p) != nil {
			return nil, n.ErrInvalid
		}
		r, e := f.Adapter.Commit(ctx, p)
		if e != nil {
			return nil, e
		}
		return json.Marshal(r)
	case "relay.status":
		var p struct {
			OperationID   string `json:"operation_id"`
			BindingDigest string `json:"binding_digest"`
		}
		if n.StrictDecode(raw, &p) != nil {
			return nil, n.ErrInvalid
		}
		r, e := f.Adapter.Status(ctx, p.OperationID, p.BindingDigest)
		if e != nil {
			return nil, e
		}
		return json.Marshal(r)
	case "relay.revoke":
		var p struct {
			OperationID string `json:"operation_id"`
			DeviceID    string `json:"device_id"`
			Revision    uint64 `json:"revision"`
		}
		if n.StrictDecode(raw, &p) != nil {
			return nil, n.ErrInvalid
		}
		if e := f.Adapter.Revoke(ctx, p.OperationID, p.DeviceID, p.Revision); e != nil {
			return nil, e
		}
		return json.Marshal(map[string]any{"ok": true})
	case "relay.recover":
		var p n.RegistrationRecovery
		if n.StrictDecode(raw, &p) != nil {
			return nil, n.ErrInvalid
		}
		r, e := f.Adapter.Recover(ctx, p)
		if e != nil {
			return nil, e
		}
		return json.Marshal(r)
	default:
		return nil, n.ErrDenied
	}
}

// RemoteRelay always calls the already-authenticated control session. It never
// gets the Relay admin token or targets a caller-selected URL.
type RemoteRelay struct{ Peer Caller }

func (r RemoteRelay) Prepare(ctx context.Context, p n.RegistrationPreparation) error {
	var out struct {
		OK bool `json:"ok"`
	}
	return r.Peer.Call(ctx, "relay.prepare", p, &out)
}
func (r RemoteRelay) Commit(ctx context.Context, p n.RegistrationCommit) (n.RegistrationReceipt, error) {
	var out n.RegistrationReceipt
	e := r.Peer.Call(ctx, "relay.commit", p, &out)
	return out, e
}
func (r RemoteRelay) Status(ctx context.Context, op, binding string) (n.RegistrationReceipt, error) {
	var out n.RegistrationReceipt
	e := r.Peer.Call(ctx, "relay.status", map[string]string{"operation_id": op, "binding_digest": binding}, &out)
	return out, e
}
func (r RemoteRelay) Revoke(ctx context.Context, op, device string, revision uint64) error {
	var out struct {
		OK bool `json:"ok"`
	}
	return r.Peer.Call(ctx, "relay.revoke", struct {
		OperationID string `json:"operation_id"`
		DeviceID    string `json:"device_id"`
		Revision    uint64 `json:"revision"`
	}{op, device, revision}, &out)
}
func (r RemoteRelay) Recover(ctx context.Context, p n.RegistrationRecovery) (n.RegistrationReceipt, error) {
	var out n.RegistrationReceipt
	e := r.Peer.Call(ctx, "relay.recover", p, &out)
	return out, e
}
