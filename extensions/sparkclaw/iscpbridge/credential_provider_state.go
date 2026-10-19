package iscpbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
)

// CredentialRecovery must return only a verified target-local lease. It owns the
// durable control intent and leaves its exact result pending until the provider
// installation has succeeded. The provider never calls it with a socket lock.
type CredentialRecovery func(context.Context, CredentialBinding, CredentialGeneration) (CredentialLease, error)
type credentialState struct {
	Binding                    CredentialBinding
	Lease                      *CredentialLease
	Generation                 CredentialGeneration
	AuthorizationRevision      string
	Version                    uint64
	Reason                     CredentialEventReason
	Invalidated                bool
	TerminalAuthorityPublicKey string
	TerminalAuthorityRevision  string
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
	installed   func(context.Context, CredentialLease) error
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
	return r.ConfigureCredentialProviderWithInstallation(binding, recovery, nil)
}

// The installation callback runs after durable CAS and outside every provider
// mutex/file lock. A lost ACK retries this callback against the retained lease.
func (r *RelayClient) ConfigureCredentialProviderWithInstallation(binding CredentialBinding, recovery CredentialRecovery, installed func(context.Context, CredentialLease) error) error {
	if err := CheckLegacyCredentialPending(r.enrollmentPath); err != nil {
		return err
	}
	if !filepath.IsAbs(r.enrollmentPath) || recovery == nil || binding.TLSCertificateSHA256 != c.Base64URL(c.SHA256([]byte(r.enrollment.TLSCertificatePEM))) || binding.DomainID != r.device.Identity.DomainID || binding.DeviceID != r.device.Identity.DeviceID || binding.ResourceBindingID == "" || binding.TargetServiceID == "" || binding.RelayPublicKey == "" || binding.IssuerPublicKey == "" || binding.TLSCertificateSHA256 == "" {
		return errors.New("credential provider needs original verified binding and pins")
	}
	key, e := c.NewProvider().HKDF(r.device.Private.BytesForDevStore(), nil, []byte("iscp/credential-state/v2\x00"+r.device.Identity.PublicKey.KID), 32)
	if e != nil {
		return e
	}
	root, cancel := context.WithCancel(context.Background())
	p := &managedCredentialProvider{relay: r, binding: binding, recovery: recovery, installed: installed, root: root, cancel: cancel, key: key, path: r.enrollmentPath + ".credentials.v2", subscribers: map[chan CredentialEvent]struct{}{}, state: credentialState{Binding: binding}}
	unlock, e := lockCredentialFile(root, p.path+".lock")
	if e != nil {
		cancel()
		return e
	}
	e = p.load()
	unlock()
	if e != nil {
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
		if p.state.Version != 0 {
			return errors.New("durable credential history disappeared")
		}
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
	if state.Version < p.state.Version {
		return errors.New("durable credential state version regressed")
	}
	previous := p.state
	p.state = state
	if state.Lease != nil {
		p.relay.mu.Lock()
		p.relay.enrollment = state.Lease.Enrollment
		p.relay.mu.Unlock()
	}
	if state.Version > previous.Version {
		event := p.eventLocked()
		if previous.AuthorizationRevision != "" && previous.AuthorizationRevision != state.AuthorizationRevision && event.Reason != CredentialRevoked {
			event.Reason = ScopeChanged
		}
		p.publishEventLocked(event)
	}
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
	if e = writeSecretFile(p.path, []byte(c.Base64URL(append(nonce, ct...)))); e != nil {
		return e
	}
	return syncCredentialDirectory(filepath.Dir(p.path))
}
func (p *managedCredentialProvider) EnsureAccess(ctx context.Context, binding CredentialBinding) (CredentialLease, error) {
	if err := CheckLegacyCredentialPending(p.relay.enrollmentPath); err != nil {
		return CredentialLease{}, err
	}
retry:
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return CredentialLease{}, context.Canceled
	}
	if binding != p.binding {
		p.mu.Unlock()
		return CredentialLease{}, errors.New("credential binding changed")
	}
	unlock, err := lockCredentialFile(ctx, p.path+".lock")
	if err != nil {
		p.mu.Unlock()
		return CredentialLease{}, err
	}
	err = p.load()
	unlock()
	if err != nil {
		p.mu.Unlock()
		return CredentialLease{}, err
	}
	if p.state.Reason == CredentialRevoked {
		p.mu.Unlock()
		return CredentialLease{}, ErrAuthorizationRevoked
	}
	if p.state.Lease != nil && !p.state.Invalidated && time.Now().Add(10*time.Second).Before(p.state.Lease.ExpiresAt) {
		lease := copyCredentialLease(*p.state.Lease)
		p.mu.Unlock()
		if p.installed != nil {
			if err := p.installed(ctx, lease); err != nil {
				if persistErr := p.observeTerminal(err); persistErr != nil {
					return CredentialLease{}, persistErr
				}
				return CredentialLease{}, err
			}
		}
		current, err := p.leaseCurrent(ctx, lease)
		if err != nil {
			return CredentialLease{}, err
		}
		if current {
			return lease, nil
		}
		goto retry
	}
	f := p.flight
	if f == nil {
		f = &credentialFlight{done: make(chan struct{})}
		p.flight = f
		expected := p.state.Generation
		version := p.state.Version
		go p.recover(f, expected, version)
	}
	p.mu.Unlock()
	select {
	case <-ctx.Done():
		return CredentialLease{}, ctx.Err()
	case <-f.done:
		if f.err != nil {
			return CredentialLease{}, f.err
		}
		// Installation/ACK runs outside the provider lock. During that window
		// a cached reader may reject this generation, or another process may
		// replace it. A waiter must recheck durable state before returning the
		// completed flight, otherwise it can return the just-rejected token.
		current, err := p.leaseCurrent(ctx, f.lease)
		if err != nil {
			return CredentialLease{}, err
		}
		if current {
			return copyCredentialLease(f.lease), nil
		}
		goto retry
	}
}

// leaseCurrent is the linearization check after any installation callback. That
// callback performs network I/O without provider/file locks, so both cached and
// flight paths must reload the durable authority before returning credentials.
func (p *managedCredentialProvider) leaseCurrent(ctx context.Context, lease CredentialLease) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	unlock, err := lockCredentialFile(ctx, p.path+".lock")
	if err != nil {
		return false, err
	}
	defer unlock()
	if err = p.load(); err != nil {
		return false, err
	}
	return !p.closed && !p.state.Invalidated && p.state.Lease != nil && p.state.Version == lease.StateVersion && time.Now().Before(p.state.Lease.ExpiresAt), nil
}
func (p *managedCredentialProvider) recover(f *credentialFlight, expected CredentialGeneration, version uint64) {
	ctx, cancel := context.WithTimeout(p.root, 30*time.Second)
	defer cancel()
	lease, err := p.recovery(ctx, p.binding, expected)
	p.mu.Lock()
	defer func() {
		p.mu.Unlock()
		if f.err == nil && p.installed != nil {
			f.err = p.installed(ctx, copyCredentialLease(f.lease))
			if f.err != nil {
				if persistErr := p.observeTerminal(f.err); persistErr != nil {
					f.err = persistErr
				}
			}
		}
		p.mu.Lock()
		p.flight = nil
		close(f.done)
		p.mu.Unlock()
	}()
	if p.closed {
		f.err = context.Canceled
		return
	}
	unlock, lockErr := lockCredentialFile(ctx, p.path+".lock")
	if lockErr != nil {
		f.err = lockErr
		return
	}
	defer unlock()
	if e := p.load(); e != nil {
		f.err = e
		return
	}
	if expected != p.state.Generation || version != p.state.Version {
		if p.state.Lease != nil && !p.state.Invalidated && time.Now().Before(p.state.Lease.ExpiresAt) {
			f.lease = copyCredentialLease(*p.state.Lease)
			p.relay.mu.Lock()
			p.relay.enrollment = f.lease.Enrollment
			p.relay.mu.Unlock()
			p.publishLocked()
			return
		}
		f.err = errors.New("credential recovery lost durable CAS")
		return
	}

	if err != nil {
		if persistErr := p.recordTerminalLocked(err); persistErr != nil {
			err = persistErr
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
	ctx, cancel := context.WithTimeout(p.root, 5*time.Second)
	defer cancel()
	unlock, e := lockCredentialFile(ctx, p.path+".lock")
	if e != nil {
		return e
	}
	defer unlock()
	if e = p.load(); e != nil {
		return e
	}
	if expected != p.state.Generation || p.state.Reason == CredentialRevoked || p.state.Invalidated {
		return nil
	}
	next := p.state
	next.Invalidated = true
	next.Version++
	if next.Lease != nil {
		lease := copyCredentialLease(*next.Lease)
		lease.StateVersion = next.Version
		next.Lease = &lease
	}
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
func (p *managedCredentialProvider) publishLocked() { p.publishEventLocked(p.eventLocked()) }
func (p *managedCredentialProvider) publishEventLocked(event CredentialEvent) {
	for ch := range p.subscribers {
		select {
		case ch <- event:
		default:
			next := event
			select {
			case pending := <-ch:
				if pending.Reason == CredentialRevoked {
					next.Reason = CredentialRevoked
					next.Lease = nil
				} else if pending.Reason == IdentityChanged && next.Reason != CredentialRevoked {
					next.Reason = IdentityChanged
				} else if pending.Reason == ScopeChanged && next.Reason != CredentialRevoked && next.Reason != IdentityChanged {
					next.Reason = ScopeChanged
				}
			default:
			}
			ch <- next
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
