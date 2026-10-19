package iscpnodecontrol

import (
	"context"
	"encoding/json"
	"os"
	"time"

	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
)

type helloWatermark struct {
	Version             int       `json:"version"`
	LocalIdentityDigest string    `json:"local_identity_digest"`
	PeerIdentityDigest  string    `json:"peer_identity_digest"`
	RelayID             string    `json:"relay_id"`
	IssuedAt            time.Time `json:"issued_at"`
	SessionID           string    `json:"session_id"`
	HelloDigest         string    `json:"hello_digest"`
}

func (p *Peer) loadHelloWatermark() error {
	if p.grantFile == "" {
		return nil
	}
	var v helloWatermark
	e := ReadPrivate(p.grantFile+".hello-watermark", &v)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if v.Version != 1 || v.LocalIdentityDigest != n.Digest(p.cfg.Device.Identity) || v.PeerIdentityDigest != n.Digest(p.cfg.Peer) || v.RelayID != p.cfg.RelayID || v.IssuedAt.IsZero() || v.HelloDigest == "" || v.SessionID == "" || v.IssuedAt.After(time.Now().Add(time.Minute)) {
		return n.ErrDenied
	}
	p.lastHello = v.IssuedAt
	p.lastHelloDigest = v.HelloDigest
	return nil
}
func (p *Peer) saveHelloWatermark(h session.Hello) error {
	if p.grantFile == "" {
		return nil
	}
	raw, _ := json.Marshal(helloWatermark{1, n.Digest(p.cfg.Device.Identity), n.Digest(p.cfg.Peer), p.cfg.RelayID, h.IssuedAt, h.SessionID, n.Digest(h)})
	return n.WritePrivateAtomic(p.grantFile+".hello-watermark", raw)
}
func (p *Peer) failPendingLocked() {
	for _, pending := range p.pending {
		select {
		case pending.ch <- rpc{Error: "unavailable"}:
		default:
		}
	}
}

func (p *Peer) receiveHello(ctx context.Context, env envelope.SecureEnvelope) error {
	raw, e := c.DecodeBase64URL(env.Ciphertext)
	if e != nil {
		return nil
	}
	var hello session.Hello
	if n.StrictDecode(raw, &hello) != nil {
		return nil
	}
	p.mu.Lock()
	if hello.PeerDeviceID != p.cfg.Device.Identity.DeviceID || hello.GrantID != p.cfg.Grant.GrantID || hello.SessionID != env.SessionID || hello.SessionID == "" || hello.Signature.Alg != "Ed25519" || hello.Signature.KID != p.cfg.Peer.PublicKey.KID || time.Since(hello.IssuedAt) > time.Minute || hello.IssuedAt.After(time.Now().Add(time.Minute)) || p.verifyGrant() != nil || session.VerifyHello(c.NewProvider(), hello, p.cfg.Peer) != nil {
		p.mu.Unlock()
		return nil
	}
	digest := n.Digest(hello)
	// Exact repeat is a retransmission, never permission to rederive the same
	// session keys and reset its anti-replay sequence state.
	if !hello.IssuedAt.After(p.lastHello) {
		if hello.IssuedAt.Equal(p.lastHello) && digest == p.lastHelloDigest && p.state != nil && p.state.SessionID == hello.SessionID {
			ready, e := p.state.CreateReady(c.NewProvider(), p.cfg.Device)
			local := p.local
			needHello := !p.state.Ready()
			p.mu.Unlock()
			if e != nil {
				return e
			}
			if needHello {
				if e = p.sendHandshake(ctx, session.TypeHello, local.Hello, hello.SessionID); e != nil {
					return e
				}
			}
			return p.sendHandshake(ctx, session.TypeReady, ready, hello.SessionID)
		}
		p.mu.Unlock()
		return nil
	}
	if p.state != nil && p.state.SessionID == hello.SessionID {
		p.mu.Unlock()
		return nil
	}
	local := p.local
	replyHello := false
	if local.Hello.SessionID != hello.SessionID {
		// A simultaneous cold start selects the original initiator's proposal. A
		// signed fresh restart from either side is accepted once an old session is
		// Ready, and does not rely on unauthenticated timers clearing live sessions.
		if p.cfg.Initiator && local.Hello.SessionID != "" && (p.state == nil || !p.state.Ready()) && time.Since(local.Hello.IssuedAt) < 10*time.Second {
			p.mu.Unlock()
			return nil
		}
		local, e = session.CreateHello(c.NewProvider(), p.cfg.Device, hello.SessionID, p.cfg.Peer.DeviceID, p.cfg.Grant.GrantID, time.Now().UTC())
		if e != nil {
			p.mu.Unlock()
			return e
		}
		replyHello = true
	}
	state, e := session.Establish(c.NewProvider(), local, hello, p.cfg.Device.Identity, p.cfg.Peer)
	if e != nil {
		p.mu.Unlock()
		return nil
	}
	ready, e := state.CreateReady(c.NewProvider(), p.cfg.Device)
	if e != nil {
		p.mu.Unlock()
		return e
	}
	// No state or high-water advance is accepted until its private durable
	// checkpoint succeeds. Broken storage cannot weaken freshness on restart.
	if e = p.saveHelloWatermark(hello); e != nil {
		p.mu.Unlock()
		return e
	}
	if p.state != nil && p.state.SessionID != state.SessionID {
		p.failPendingLocked()
	}
	p.local = local
	p.state = state
	p.lastHello = hello.IssuedAt
	p.lastHelloDigest = digest
	p.lastHelloSent = time.Now()
	p.mu.Unlock()
	if replyHello {
		if e = p.sendHandshake(ctx, session.TypeHello, local.Hello, hello.SessionID); e != nil {
			return e
		}
	}
	return p.sendHandshake(ctx, session.TypeReady, ready, hello.SessionID)
}
