package iscpnodecontrol

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"io"
	"net/http"
	"os"
	"time"
)

const ControlGrantPath = "/api/sparkclaw/iscp-control/v1/control-grant"

type ControlGrantUpdate struct {
	Version     int                     `json:"version"`
	IssuerRoute string                  `json:"issuer_route"`
	Identity    identity.DeviceIdentity `json:"identity"`
	Grant       trust.Grant             `json:"grant"`
	Proof       identity.DeviceProof    `json:"proof"`
}

func ControlGrantChallenge(route string, g trust.Grant) string {
	return "sparkclaw/iscp-node/control-grant/v1\x00" + n.Digest(struct {
		Route string      `json:"issuer_route"`
		Grant trust.Grant `json:"grant"`
	}{route, g})
}
func (p *Peer) validateGrant(g trust.Grant, at time.Time) error {
	subject, audience := p.cfg.Device.Identity, p.cfg.Peer
	if !p.cfg.Initiator {
		subject, audience = audience, subject
	}
	if len(g.Permissions) != 1 || g.Permissions[0] != ControlPermission || len(g.RelayConstraints) != 1 || g.RelayConstraints[0] != p.cfg.RelayID || g.RevocationEpoch < p.minimumRevision || g.ExpiresAt.Sub(g.NotBefore) > 7*24*time.Hour {
		return n.ErrDenied
	}
	return trust.VerifyGrant(c.NewProvider(), g, p.cfg.Issuer, trust.VerifyOptions{SubjectDeviceID: subject.DeviceID, Audience: audience.DeviceID, ConfirmationThumbprint: subject.PublicKey.KID, Permission: ControlPermission, RelayID: p.cfg.RelayID, Now: at})
}
func (p *Peer) UpdateGrant(g trust.Grant) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.standing || !p.active || p.validateGrant(g, time.Now().UTC()) != nil || g.RevocationEpoch < p.cfg.Grant.RevocationEpoch || g.NotBefore.Before(p.cfg.Grant.NotBefore) {
		return n.ErrDenied
	}
	if g.GrantID == p.cfg.Grant.GrantID {
		return nil
	}
	if p.grantFile != "" {
		raw, _ := json.Marshal(g)
		if e := n.WritePrivateAtomic(p.grantFile, raw); e != nil {
			return e
		}
	}
	p.cfg.Grant = g
	p.failPendingLocked()
	p.state = nil
	p.local = session.LocalHello{}
	p.lastHelloSent = time.Time{}
	return nil
}
func (f *Forwarder) handleControlGrant(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != ControlGrantPath {
		return false
	}
	if r.Method != "POST" || r.URL.RawQuery != "" {
		writeError(w, 400, "invalid")
		return true
	}
	peer, ok := f.Peer.(*Peer)
	if !ok || !peer.standing || !peer.active || peer.cfg.Initiator {
		writeError(w, 403, "denied")
		return true
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, n.MaxFrameBytes))
	if e != nil {
		writeError(w, 400, "invalid")
		return true
	}
	var req ControlGrantUpdate
	if n.StrictDecode(raw, &req) != nil || req.Version != 1 || req.IssuerRoute != f.Route || n.Digest(req.Identity) != n.Digest(peer.cfg.Peer) || identity.VerifyProof(c.NewProvider(), req.Identity, req.Proof, peer.cfg.Device.Identity.DeviceID, ControlGrantChallenge(f.Route, req.Grant), time.Now().UTC(), 5*time.Minute) != nil {
		writeError(w, 403, "denied")
		return true
	}
	f.controlMu.Lock()
	defer f.controlMu.Unlock()
	verifier, ok := f.Adapter.(interface {
		VerifyServicePeer(context.Context, identity.DeviceIdentity, identity.DeviceProof, string) error
	})
	if !ok {
		writeError(w, 503, "unavailable")
		return true
	}
	if e = verifier.VerifyServicePeer(r.Context(), req.Identity, req.Proof, ControlGrantChallenge(f.Route, req.Grant)); e != nil {
		writeError(w, 403, "denied")
		return true
	}
	if e = peer.recordGrantProof(req); e != nil {
		writeError(w, 403, "denied")
		return true
	}
	if e = peer.UpdateGrant(req.Grant); e != nil {
		writeError(w, 403, "denied")
		return true
	}
	_ = json.NewEncoder(w).Encode(struct {
		Version  int    `json:"version"`
		GrantID  string `json:"grant_id"`
		Revision uint64 `json:"revision"`
	}{1, req.Grant.GrantID, req.Grant.RevocationEpoch})
	return true
}

// RotateControlGrant is restricted by the durable operator-approved service
// identity pair. It cannot mint or update business/device permissions.
func (p *Peer) RotateControlGrant(ctx context.Context, signer identity.Device, route string, bundle iscpbridge.EnrollmentBundle) error {
	p.mu.Lock()
	if !p.cfg.Initiator || !p.standing || !p.active || n.Digest(signer.Identity) != n.Digest(p.cfg.Issuer) {
		p.mu.Unlock()
		return n.ErrDenied
	}
	current := p.cfg.Grant
	device, peer, relay := p.cfg.Device, p.cfg.Peer, p.cfg.RelayID
	p.mu.Unlock()
	if current.ExpiresAt.Sub(time.Now()) < 24*time.Hour {
		now := time.Now().UTC()
		g, e := trust.SignGrant(c.NewProvider(), signer, trust.Grant{GrantID: "control-" + c.Base64URL(c.RandomBytes(18)), SubjectDeviceID: device.Identity.DeviceID, ConfirmationThumbprint: device.Identity.PublicKey.KID, Audience: peer.DeviceID, Permissions: []string{ControlPermission}, RelayConstraints: []string{relay}, NotBefore: now, ExpiresAt: now.Add(7 * 24 * time.Hour), RevocationEpoch: current.RevocationEpoch})
		if e != nil {
			return e
		}
		if e = p.UpdateGrant(g); e != nil {
			return e
		}
		current = g
	}
	if n.ValidateOrigin(bundle.RelayBaseURL, bundle.TLSCertificatePEM, time.Now(), false) != nil {
		return n.ErrInvalid
	}
	proof, e := device.CreateProof(c.NewProvider(), peer.DeviceID, ControlGrantChallenge(route, current), c.Base64URL(c.RandomBytes(24)), time.Now().UTC())
	if e != nil {
		return e
	}
	raw, _ := json.Marshal(ControlGrantUpdate{1, route, device.Identity, current, proof})
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(bundle.TLSCertificatePEM)) {
		return n.ErrInvalid
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return n.ErrDenied }}
	req, e := http.NewRequestWithContext(ctx, "POST", bundle.RelayBaseURL+ControlGrantPath, bytes.NewReader(raw))
	if e != nil {
		return n.ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := client.Do(req)
	if e != nil {
		return n.ErrUnavailable
	}
	defer res.Body.Close()
	body, e := io.ReadAll(io.LimitReader(res.Body, 4096))
	if e != nil {
		return n.ErrUnavailable
	}
	if res.StatusCode != 200 {
		return n.ErrUnavailable
	}
	var ack struct {
		Version  int    `json:"version"`
		GrantID  string `json:"grant_id"`
		Revision uint64 `json:"revision"`
	}
	if n.StrictDecode(body, &ack) != nil || ack.Version != 1 || ack.GrantID != current.GrantID || ack.Revision != current.RevocationEpoch {
		return n.ErrDenied
	}
	return nil
}

type grantProofReceipt struct {
	Nonce     string    `json:"nonce"`
	Digest    string    `json:"digest"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (p *Peer) recordGrantProof(req ControlGrantUpdate) error {
	if p.grantFile == "" {
		return n.ErrInvalid
	}
	path := p.grantFile + ".proof-receipts"
	receipts := []grantProofReceipt{}
	if raw, e := ReadPrivateBytes(path); e == nil {
		if json.Unmarshal(raw, &receipts) != nil {
			return n.ErrDenied
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	digest := n.Digest(req)
	active := []grantProofReceipt{}
	now := time.Now()
	for _, v := range receipts {
		if v.Nonce == req.Proof.Nonce && v.Digest != digest {
			return n.ErrDenied
		}
		if v.Nonce == req.Proof.Nonce && v.Digest == digest {
			return nil
		}
		if now.Before(v.ExpiresAt) {
			active = append(active, v)
		}
	}
	active = append(active, grantProofReceipt{req.Proof.Nonce, digest, req.Proof.IssuedAt.Add(5 * time.Minute)})
	raw, _ := json.Marshal(active)
	return n.WritePrivateAtomic(path, raw)
}
func (p *Peer) RunControlRotation(ctx context.Context, signer identity.Device, route string) error {
	source, ok := p.relay.(interface {
		Enrollment() iscpbridge.EnrollmentBundle
	})
	if !ok {
		return n.ErrInvalid
	}
	for ctx.Err() == nil {
		_ = p.RotateControlGrant(ctx, signer, route, source.Enrollment())
		timer := time.NewTimer(5 * time.Minute)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return ctx.Err()
}
