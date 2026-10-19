// Package iscpnodecontrol carries a bounded application RPC over ordinary ISCP
// encrypted sessions and Relay HTTPS/WSS. It never uses a reverse TCP tunnel.
package iscpnodecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"sync"
	"time"
)

const ControlPermission = "sparkclaw.issuer.control.v1"
const payloadType = "sparkclaw.issuer.control.rpc.v1"

type Relay interface {
	Submit(context.Context, any) error
	RunOnceReady(context.Context, func(context.Context, json.RawMessage) error, func()) error
}
type Handler func(context.Context, string, json.RawMessage) (json.RawMessage, error)
type PeerConfig struct {
	Initiator bool
	Device    identity.Device
	Peer      identity.DeviceIdentity
	Issuer    identity.DeviceIdentity
	Grant     trust.Grant
	RelayID   string
}
type rpc struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	Kind    string          `json:"kind"`
	Method  string          `json:"method,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}
type pendingRPC struct {
	ch        chan rpc
	sessionID string
}
type Peer struct {
	mu              sync.Mutex
	cfg             PeerConfig
	relay           Relay
	handler         Handler
	local           session.LocalHello
	state           *session.State
	lastHello       time.Time
	lastHelloDigest string
	lastHelloSent   time.Time
	pending         map[string]pendingRPC
	standing        bool
	active          bool
	grantFile       string
	enrollmentFile  string
	minimumRevision uint64
	running         bool
}

func NewPeer(cfg PeerConfig, relay Relay, h Handler) (*Peer, error) {
	return newPeer(cfg, relay, h, false, true, "")
}
func newPeer(cfg PeerConfig, relay Relay, h Handler, standing, active bool, grantFile string) (*Peer, error) {
	if relay == nil || iscpnodeissuer.ValidateIdentity(cfg.Device.Identity) != nil || iscpnodeissuer.ValidateIdentity(cfg.Peer) != nil || cfg.Device.Identity.DomainID != cfg.Peer.DomainID || cfg.Device.Identity.DeviceID == cfg.Peer.DeviceID || cfg.RelayID == "" {
		return nil, iscpnodeissuer.ErrInvalid
	}
	p := &Peer{cfg: cfg, relay: relay, handler: h, pending: map[string]pendingRPC{}, standing: standing, active: active, grantFile: grantFile, minimumRevision: cfg.Grant.RevocationEpoch}
	at := time.Now().UTC()
	if standing {
		at = cfg.Grant.NotBefore
	}
	if !active || p.minimumRevision == 0 || p.validateGrant(cfg.Grant, at) != nil {
		return nil, iscpnodeissuer.ErrDenied
	}
	if e := p.loadHelloWatermark(); e != nil {
		return nil, e
	}
	if sender, ok := relay.(interface{ SetSessionUsable(func(string) bool) }); ok {
		sender.SetSessionUsable(func(id string) bool {
			p.mu.Lock()
			defer p.mu.Unlock()
			return p.state != nil && p.state.SessionID == id && p.state.Ready() && p.verifyGrant() == nil
		})
	}
	return p, nil
}
func (p *Peer) verifyGrant() error {
	if !p.active {
		return iscpnodeissuer.ErrDenied
	}
	return p.validateGrant(p.cfg.Grant, time.Now().UTC())
}
func (p *Peer) Ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state != nil && p.state.Ready() && p.verifyGrant() == nil
}
func (p *Peer) begin(ctx context.Context) error {
	p.mu.Lock()
	if p.state != nil && p.state.Ready() {
		p.mu.Unlock()
		return nil
	}
	if p.verifyGrant() != nil {
		p.mu.Unlock()
		return iscpnodeissuer.ErrDenied
	}
	if !p.lastHelloSent.IsZero() && time.Since(p.lastHelloSent) < 5*time.Second {
		p.mu.Unlock()
		return nil
	}
	local := p.local
	if local.Hello.SessionID == "" || time.Since(local.Hello.IssuedAt) > 45*time.Second {
		var e error
		local, e = session.CreateHello(c.NewProvider(), p.cfg.Device, "ctl-"+c.Base64URL(c.RandomBytes(18)), p.cfg.Peer.DeviceID, p.cfg.Grant.GrantID, time.Now().UTC())
		if e != nil {
			p.mu.Unlock()
			return e
		}
		p.local = local
		p.state = nil
	}
	p.lastHelloSent = time.Now()
	p.mu.Unlock()
	return p.sendHandshake(ctx, session.TypeHello, local.Hello, local.Hello.SessionID)
}
func (p *Peer) sendHandshake(ctx context.Context, kind string, v any, sid string) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return p.relay.Submit(ctx, envelope.SecureEnvelope{Type: envelope.TypeSecureEnvelope, DomainID: p.cfg.Device.Identity.DomainID, MessageID: "ctl-hs-" + c.Base64URL(c.RandomBytes(18)), SessionID: sid, SenderDeviceID: p.cfg.Device.Identity.DeviceID, RecipientDeviceID: p.cfg.Peer.DeviceID, Sequence: 0, Nonce: c.Base64URL(c.RandomBytes(12)), PayloadType: kind, Route: envelope.Route{RelayID: p.cfg.RelayID, TTLSeconds: 60}, Ciphertext: c.Base64URL(b)})
}
func (p *Peer) receive(ctx context.Context, raw json.RawMessage) error {
	var env envelope.SecureEnvelope
	if iscpnodeissuer.StrictDecode(raw, &env) != nil || env.DomainID != p.cfg.Device.Identity.DomainID || env.SenderDeviceID != p.cfg.Peer.DeviceID || env.RecipientDeviceID != p.cfg.Device.Identity.DeviceID || env.Route.RelayID != p.cfg.RelayID {
		return nil
	}
	if env.PayloadType == session.TypeHello {
		return p.receiveHello(ctx, env)
	}
	if env.PayloadType == session.TypeReady {
		b, e := c.DecodeBase64URL(env.Ciphertext)
		if e != nil {
			return nil
		}
		var ready session.Ready
		if iscpnodeissuer.StrictDecode(b, &ready) != nil {
			return nil
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.state == nil || env.SessionID != ready.SessionID || ready.Signature.Alg != "Ed25519" || ready.Signature.KID != p.cfg.Peer.PublicKey.KID {
			return nil
		}
		_ = p.state.VerifyReady(c.NewProvider(), ready, p.cfg.Peer)
		return nil
	}
	if env.PayloadType != payloadType {
		return nil
	}
	p.mu.Lock()
	if p.state == nil || !p.state.Ready() || p.verifyGrant() != nil {
		p.mu.Unlock()
		return nil
	}
	b, e := envelope.Decrypt(c.NewProvider(), p.state, env)
	p.mu.Unlock()
	if e != nil || len(b) > iscpnodeissuer.MaxFrameBytes {
		return nil
	}
	var msg rpc
	if iscpnodeissuer.StrictDecode(b, &msg) != nil || msg.Version != 1 || len(msg.ID) < 8 || len(msg.ID) > 200 {
		return nil
	}
	if msg.Kind == "response" {
		p.mu.Lock()
		pending, ok := p.pending[msg.ID]
		p.mu.Unlock()
		if ok && pending.sessionID == env.SessionID {
			select {
			case pending.ch <- msg:
			default:
			}
		}
		return nil
	}
	p.mu.Lock()
	handler := p.handler
	p.mu.Unlock()
	if msg.Kind != "request" || handler == nil {
		return nil
	}
	go func() {
		callCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		result, e := handler(callCtx, msg.Method, msg.Payload)
		reply := rpc{Version: 1, ID: msg.ID, Kind: "response", Payload: result}
		if e != nil {
			reply.Payload = nil
			reply.Error = errorCode(e)
		}
		_ = p.sendForSession(callCtx, reply, env.SessionID)
	}()
	return nil
}
func errorCode(e error) string {
	switch {
	case errors.Is(e, iscpnodeissuer.ErrInvalid):
		return "invalid"
	case errors.Is(e, iscpnodeissuer.ErrDenied):
		return "denied"
	case errors.Is(e, iscpnodeissuer.ErrConflict):
		return "conflict"
	case errors.Is(e, iscpnodeissuer.ErrExpired):
		return "expired"
	default:
		return "unavailable"
	}
}
func wireError(code string) error {
	switch code {
	case "invalid":
		return iscpnodeissuer.ErrInvalid
	case "denied":
		return iscpnodeissuer.ErrDenied
	case "conflict":
		return iscpnodeissuer.ErrConflict
	case "expired":
		return iscpnodeissuer.ErrExpired
	default:
		return iscpnodeissuer.ErrUnavailable
	}
}
func (p *Peer) send(ctx context.Context, msg rpc) error {
	return p.sendForSession(ctx, msg, "")
}
func (p *Peer) sendForSession(ctx context.Context, msg rpc, sessionID string) error {
	raw, e := json.Marshal(msg)
	if e != nil || len(raw) > iscpnodeissuer.MaxFrameBytes {
		return iscpnodeissuer.ErrInvalid
	}
	p.mu.Lock()
	if p.state == nil || !p.state.Ready() || p.verifyGrant() != nil || sessionID != "" && p.state.SessionID != sessionID {
		p.mu.Unlock()
		return iscpnodeissuer.ErrUnavailable
	}
	env, e := envelope.Encrypt(c.NewProvider(), p.state, "ctl-rpc-"+c.Base64URL(c.RandomBytes(18)), payloadType, envelope.Route{RelayID: p.cfg.RelayID, TTLSeconds: 60}, raw)

	if e != nil {
		p.mu.Unlock()
		return e
	}
	if sender, ok := p.relay.(interface {
		Enqueue(context.Context, any) (*iscpbridge.ReceiptFuture, error)
	}); ok {
		future, err := sender.Enqueue(ctx, env)
		p.mu.Unlock()
		if err != nil {
			return err
		}
		_, err = future.Wait(ctx)
		return err
	}
	p.mu.Unlock()
	return p.relay.Submit(ctx, env)
}
func (p *Peer) Call(ctx context.Context, method string, input, out any) error {
	if len(method) > 80 {
		return iscpnodeissuer.ErrInvalid
	}
	raw, e := json.Marshal(input)
	if e != nil || len(raw) > iscpnodeissuer.MaxFrameBytes-1024 {
		return iscpnodeissuer.ErrInvalid
	}
	id := "rpc-" + c.Base64URL(c.RandomBytes(18))
	ch := make(chan rpc, 1)
	p.mu.Lock()
	if p.state == nil || !p.state.Ready() || p.verifyGrant() != nil {
		p.mu.Unlock()
		return iscpnodeissuer.ErrUnavailable
	}
	sessionID := p.state.SessionID
	p.pending[id] = pendingRPC{ch, sessionID}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.pending, id); p.mu.Unlock() }()
	if e = p.sendForSession(ctx, rpc{Version: 1, ID: id, Kind: "request", Method: method, Payload: raw}, sessionID); e != nil {
		return e
	}
	select {
	case <-ctx.Done():
		return iscpnodeissuer.ErrUnavailable
	case r := <-ch:
		if r.Error != "" {
			return wireError(r.Error)
		}
		if out == nil {
			return nil
		}
		return iscpnodeissuer.StrictDecode(r.Payload, out)
	}
}

// Run owns the continuous Relay receive connection; fresh process/session
// handshakes remain explicit and independently proven.
func (p *Peer) Run(ctx context.Context) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return iscpnodeissuer.ErrConflict
	}
	p.running = true
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.running = false; p.mu.Unlock() }()
	for ctx.Err() == nil {
		if e := p.maintainServiceCredentials(ctx); e != nil {
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		_ = p.receiveContinuous(ctx)
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return ctx.Err()
}

// Session maintenance must not depend on a healthy receive connection ending.
// Grant rotation and service credential recovery may reset the encrypted session
// while leaving the authenticated Relay socket alive.
func (p *Peer) receiveContinuous(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			maintenance, stop := context.WithTimeout(ctx, 25*time.Second)
			err := p.maintainServiceCredentials(maintenance)
			if err == nil {
				err = p.begin(maintenance)
			}
			stop()
			if err != nil {
				cancel()
				return
			}
		}
	}()
	err := p.relay.RunOnceReady(ctx, p.receive, func() { _ = p.begin(ctx) })
	cancel()
	<-done
	return err
}
