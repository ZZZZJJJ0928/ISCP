package iscpbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
)

// CredentialRecovery must return only a verified target-local lease. It owns the
// durable control intent and leaves its exact result pending until the provider
// installation has succeeded. The provider never calls it with a socket lock.
type CredentialRecovery func(context.Context, CredentialBinding, CredentialGeneration) (CredentialLease, error)
type credentialState struct {
	Binding               CredentialBinding
	Lease                 *CredentialLease
	Generation            CredentialGeneration
	AuthorizationRevision string
	Version               uint64
	Reason                CredentialEventReason
	Invalidated           bool
}
type credentialFlight struct {
	done  chan struct{}
	lease CredentialLease
	err   error
}
type managedCredentialProvider struct {
	mu          sync.Mutex
	relay       *RelayClient
	binding     CredentialBinding
	recovery    CredentialRecovery
	root        context.Context
	cancel      context.CancelFunc
	state       credentialState
	flight      *credentialFlight
	subscribers map[chan CredentialEvent]struct{}
	closed      bool
	key         []byte
	path        string
}

func (r *RelayClient) CredentialProvider() CredentialProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.credentialProvider
}
func (r *RelayClient) CredentialBinding() CredentialBinding {
	r.mu.RLock()
	p := r.credentialProvider
	r.mu.RUnlock()
	if owned, ok := p.(*managedCredentialProvider); ok {
		return owned.binding
	}
	return CredentialBinding{}
}

// ConfigureCredentialProvider is called from the lifecycle constructor once the
// original subject/resource/pins have been verified. No binding is guessed from
// transport URLs. It must precede starting the socket owner.
func (r *RelayClient) ConfigureCredentialProvider(binding CredentialBinding, recovery CredentialRecovery) error {
	if recovery == nil || binding.TLSCertificateSHA256 != c.Base64URL(c.SHA256([]byte(r.enrollment.TLSCertificatePEM))) || binding.DomainID != r.device.Identity.DomainID || binding.DeviceID != r.device.Identity.DeviceID || binding.ResourceBindingID == "" || binding.TargetServiceID == "" || binding.RelayPublicKey == "" || binding.IssuerPublicKey == "" || binding.TLSCertificateSHA256 == "" {
		return errors.New("credential provider needs original verified binding and pins")
	}
	key, e := c.NewProvider().HKDF(r.device.Private.BytesForDevStore(), nil, []byte("iscp/credential-state/v2\x00"+r.device.Identity.PublicKey.KID), 32)
	if e != nil {
		return e
	}
	root, cancel := context.WithCancel(context.Background())
	p := &managedCredentialProvider{relay: r, binding: binding, recovery: recovery, root: root, cancel: cancel, key: key, path: r.enrollmentPath + ".credentials.v2", subscribers: map[chan CredentialEvent]struct{}{}, state: credentialState{Binding: binding}}
	if e = p.load(); e != nil {
		cancel()
		return e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.credentialProvider != nil {
		cancel()
		return errors.New("credential provider already configured")
	}
	r.credentialProvider = p
	if p.state.Lease != nil {
		r.enrollment = p.state.Lease.Enrollment
	}
	return nil
}
func (p *managedCredentialProvider) load() error {
	info, e := os.Lstat(p.path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return errors.New("invalid private credential state")
	}
	raw, e := os.ReadFile(p.path)
	if e != nil {
		return e
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(string(raw))
	if e != nil || len(b) < 28 {
		return errors.New("invalid credential state encoding")
	}
	plain, e := c.NewProvider().Open(p.key, b[:12], b[12:], []byte(p.path))
	if e != nil {
		return e
	}
	var state credentialState
	if json.Unmarshal(plain, &state) != nil || state.Binding != p.binding {
		return errors.New("credential state binding differs")
	}
	if state.Lease != nil && (state.Lease.Binding != p.binding || state.Lease.CredentialGeneration != state.Generation || state.Lease.StateVersion != state.Version) {
		return errors.New("credential state CAS metadata differs")
	}
	p.state = state
	return nil
}
func (p *managedCredentialProvider) persist(state credentialState) error {
	raw, e := json.Marshal(state)
	if e != nil {
		return e
	}
	nonce := c.RandomBytes(12)
	ct, e := c.NewProvider().Seal(p.key, nonce, raw, []byte(p.path))
	if e != nil {
		return e
	}
	return writeSecretFile(p.path, []byte(c.Base64URL(append(nonce, ct...))))
}
func (p *managedCredentialProvider) EnsureAccess(ctx context.Context, binding CredentialBinding) (CredentialLease, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return CredentialLease{}, context.Canceled
	}
	if binding != p.binding {
		p.mu.Unlock()
		return CredentialLease{}, errors.New("credential binding changed")
	}
	if p.state.Reason == CredentialRevoked {
		p.mu.Unlock()
		return CredentialLease{}, ErrAuthorizationRevoked
	}
	if p.state.Lease != nil && !p.state.Invalidated && time.Now().Add(10*time.Second).Before(p.state.Lease.ExpiresAt) {
		lease := copyCredentialLease(*p.state.Lease)
		p.mu.Unlock()
		return lease, nil
	}
	f := p.flight
	if f == nil {
		f = &credentialFlight{done: make(chan struct{})}
		p.flight = f
		expected := p.state.Generation
		go p.recover(f, expected)
	}
	p.mu.Unlock()
	select {
	case <-ctx.Done():
		return CredentialLease{}, ctx.Err()
	case <-f.done:
		return copyCredentialLease(f.lease), f.err
	}
}
func (p *managedCredentialProvider) recover(f *credentialFlight, expected CredentialGeneration) {
	ctx, cancel := context.WithTimeout(p.root, 30*time.Second)
	defer cancel()
	lease, err := p.recovery(ctx, p.binding, expected)
	p.mu.Lock()
	defer p.mu.Unlock()
	defer close(f.done)
	defer func() { p.flight = nil }()
	if p.closed {
		f.err = context.Canceled
		return
	}
	if expected != p.state.Generation {
		f.err = errors.New("credential recovery CAS lost")
		return
	}
	if err != nil {
		var typed *control.Error
		if errors.As(err, &typed) && (typed.Code == "authorization_revoked" || typed.Code == "authorization_ended") && typed.AuthorizationRevision != nil {
			next := p.state
			next.Lease = nil
			next.Version++
			next.Reason = CredentialRevoked
			next.AuthorizationRevision = string(*typed.AuthorizationRevision)
			if e := p.persist(next); e == nil {
				p.state = next
				p.publishLocked()
			} else {
				err = e
			}
		}
		f.err = err
		return
	}
	nextGen, e := strconv.ParseUint(string(lease.CredentialGeneration), 10, 64)
	oldGen, _ := strconv.ParseUint(string(expected), 10, 64)
	if e != nil || nextGen == 0 || nextGen < oldGen || (p.state.Invalidated && nextGen == oldGen) || lease.Binding != p.binding || lease.Enrollment.DomainID != p.binding.DomainID || lease.Enrollment.DeviceID != p.binding.DeviceID || lease.Enrollment.RelayID != p.binding.TargetServiceID || lease.Enrollment.RelaySignerIdentity == nil || lease.Enrollment.RelaySignerIdentity.PublicKey.Public != p.binding.RelayPublicKey || lease.ExpiresAt.IsZero() || !time.Now().Before(lease.ExpiresAt) || lease.ExpiresAt.After(lease.Enrollment.Access.ExpiresAt) {
		f.err = errors.New("recovered credential lease failed binding/generation/deadline checks")
		return
	}
	if lease.Enrollment.ValidateCredentials(time.Now().UTC()) != nil {
		f.err = errors.New("recovered credential enrollment invalid")
		return
	}
	newRevision, revisionErr := strconv.ParseUint(lease.AuthorizationRevision, 10, 64)
	oldRevision, _ := strconv.ParseUint(p.state.AuthorizationRevision, 10, 64)
	if revisionErr != nil || newRevision == 0 || newRevision < oldRevision {
		f.err = errors.New("credential authority revision regressed")
		return
	}
	lease.StateVersion = p.state.Version + 1
	next := credentialState{Binding: p.binding, Lease: &lease, Generation: lease.CredentialGeneration, AuthorizationRevision: lease.AuthorizationRevision, Version: lease.StateVersion, Reason: CredentialRotated}
	if oldGen == 0 {
		next.Reason = CredentialRecovered
	} else if p.state.AuthorizationRevision != lease.AuthorizationRevision {
		next.Reason = ScopeChanged
	}
	// The encrypted CAS record is authoritative across restart. The existing
	// enrollment is a compatibility projection, published only with this record.
	p.relay.mu.Lock()
	defer p.relay.mu.Unlock()
	if e := SaveEnrollment(p.relay.enrollmentPath, lease.Enrollment); e != nil {
		f.err = e
		return
	}
	if e := p.persist(next); e != nil {
		f.err = e
		return
	}
	p.relay.enrollment = lease.Enrollment
	p.state = next
	f.lease = lease
	p.publishLocked()
}
func (p *managedCredentialProvider) Invalidate(binding CredentialBinding, expected CredentialGeneration, reason CredentialInvalidationReason) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if binding != p.binding {
		return errors.New("credential binding changed")
	}
	switch reason {
	case AuthenticationRequired, AccessRejected, RotationRequired:
	default:
		return errors.New("invalid credential invalidation reason")
	}
	if p.closed {
		return context.Canceled
	}
	if expected != p.state.Generation || p.state.Reason == CredentialRevoked || p.state.Invalidated {
		return nil
	}
	next := p.state
	next.Invalidated = true
	if e := p.persist(next); e != nil {
		return e
	}
	p.state = next
	return nil
}
func (p *managedCredentialProvider) eventLocked() CredentialEvent {
	event := CredentialEvent{Binding: p.binding, CredentialGeneration: p.state.Generation, AuthorizationRevision: p.state.AuthorizationRevision, StateVersion: p.state.Version, Reason: p.state.Reason}
	if p.state.Lease != nil {
		lease := copyCredentialLease(*p.state.Lease)
		event.Lease = &lease
	}
	return event
}
func (p *managedCredentialProvider) publishLocked() {
	event := p.eventLocked()
	for ch := range p.subscribers {
		select {
		case ch <- event:
		default:
			select {
			case <-ch:
			default:
			}
			ch <- event
		}
	}
}
func (p *managedCredentialProvider) Subscribe(ctx context.Context, binding CredentialBinding) <-chan CredentialEvent {
	ch := make(chan CredentialEvent, 1)
	p.mu.Lock()
	if p.closed || binding != p.binding {
		close(ch)
		p.mu.Unlock()
		return ch
	}
	p.subscribers[ch] = struct{}{}
	if p.state.Reason != "" {
		ch <- p.eventLocked()
	}
	p.mu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
		case <-p.root.Done():
		}
		p.mu.Lock()
		if _, ok := p.subscribers[ch]; ok {
			delete(p.subscribers, ch)
			close(ch)
		}
		p.mu.Unlock()
	}()
	return ch
}
func (p *managedCredentialProvider) Close() error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.cancel()
	}
	p.mu.Unlock()
	return nil
}
func copyCredentialLease(v CredentialLease) CredentialLease {
	raw, e := json.Marshal(v)
	if e != nil {
		panic(fmt.Sprintf("invalid internal credential lease: %v", e))
	}
	var out CredentialLease
	_ = json.Unmarshal(raw, &out)
	return out
}
