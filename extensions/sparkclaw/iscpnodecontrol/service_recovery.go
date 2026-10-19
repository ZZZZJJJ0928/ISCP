package iscpnodecontrol

import (
	"context"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
	"time"
)

func (p *Peer) maintainServiceCredentials(ctx context.Context) error {
	if p.enrollmentFile == "" {
		return nil
	}
	client, ok := p.relay.(*iscpbridge.RelayClient)
	if !ok {
		return n.ErrInvalid
	}
	bundle := client.Enrollment()
	if time.Now().Before(bundle.ExpiresAt) && time.Now().Before(bundle.Refresh.ExpiresAt) {
		return nil
	}
	pending := p.enrollmentFile + ".service-recovery"
	updated, e := iscpbridge.RecoverNodeServiceCredentials(ctx, bundle, p.cfg.Device, pending)
	if e != nil {
		return e
	}
	if e = client.UpdateEnrollment(func(v *iscpbridge.EnrollmentBundle) { *v = updated }); e != nil {
		return e
	}
	if e = iscpbridge.CommitNodeServiceRecovery(pending); e != nil {
		return e
	}
	p.mu.Lock()
	p.failPendingLocked()
	p.state = nil
	p.local = session.LocalHello{}
	p.lastHelloSent = time.Time{}
	p.mu.Unlock()
	return nil
}
