package iscpworkbench

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
)

var ErrStreamAuthorityExpired = errors.New("application stream authority unavailable")
var errStreamAuthority = ErrStreamAuthorityExpired

// Owned by Endpoint.mu, scoped to one authenticated session. No snapshot is
// persisted or shared with ordinary business authorization.
type streamAuthority struct {
	invalidated                       bool
	policy                            iscpauth.Policy
	deadline, nextRefresh             time.Time
	grantDeadline, capabilityDeadline time.Time
	grantExpiry, capabilityExpiry     time.Time
	generation                        uint64
	checking                          chan struct{}
	err                               error
	watching                          bool
}

func (e *Endpoint) streamAuthorityValidLocked(s *activeSession, generation uint64) bool {
	a := s.streamAuthority
	if e.closed || e.authorizationRevoked || e.session != s || s.ctx.Err() != nil || a == nil || (generation != 0 && a.generation != generation) || a.policy.State != iscpauth.Active {
		return false
	}
	c := s.capabilities
	if c == nil || c.StreamSchemaVersion != 1 || !slices.Contains(c.Operations, OperationExecutionProgressStream) {
		return false
	}
	m := e.grantMaterial()
	if a.policy.Revision != m.grant.RevocationEpoch || c.AuthorizationRevision != m.grant.RevocationEpoch || verifyGrant(e.config, m, time.Now().UTC()) != nil {
		return false
	}
	// Absolute expiries are converted once to monotonic deadlines. Verified
	// renewal with unchanged permissions can extend them without reopening.
	now := time.Now()
	if !a.grantExpiry.Equal(m.grant.ExpiresAt) {
		a.grantExpiry = m.grant.ExpiresAt
		a.grantDeadline = now.Add(m.grant.ExpiresAt.Sub(now))
	}
	if !a.capabilityExpiry.Equal(c.ExpiresAt) {
		a.capabilityExpiry = c.ExpiresAt
		a.capabilityDeadline = now.Add(c.ExpiresAt.Sub(now))
	}
	return now.Before(a.deadline) && now.Before(a.grantDeadline) && now.Before(a.capabilityDeadline)
}

func (e *Endpoint) ensureStreamAuthority(ctx context.Context, s *activeSession) (uint64, error) {
	e.mu.Lock()
	if e.session != s || e.closed || e.authorizationRevoked {
		e.mu.Unlock()
		return 0, errStreamAuthority
	}
	if s.streamAuthority == nil {
		s.streamAuthority = &streamAuthority{generation: 1}
	}
	a := s.streamAuthority
	if e.streamAuthorityValidLocked(s, 0) {
		g := a.generation
		e.mu.Unlock()
		return g, nil
	}
	if a.checking == nil {
		e.startStreamRefreshLocked(s)
	}
	checking := a.checking
	e.mu.Unlock()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-s.ctx.Done():
		return 0, errStreamAuthority
	case <-checking:
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.streamAuthorityValidLocked(s, 0) {
		return 0, errStreamAuthority
	}
	return a.generation, nil
}

func (e *Endpoint) startStreamRefreshLocked(s *activeSession) {
	a := s.streamAuthority
	if a.checking != nil || e.closed || e.session != s {
		return
	}
	done := make(chan struct{})
	a.checking = done
	started := time.Now()
	e.workers.Add(1)
	go func() {
		defer e.workers.Done()
		ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		defer cancel()
		p, err := e.queryStreamAuthority(ctx)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		defer close(done)
		if e.session != s || e.closed || e.authorizationRevoked || a.checking != done {
			return
		}
		a.checking = nil
		if errors.Is(err, iscpbridge.ErrAuthorizationRevoked) || err == nil && p.State == iscpauth.Revoked {
			e.authorizationRevoked = true
			e.resetLocked()
			go e.setState("authorization_revoked")
			if e.cancel != nil {
				e.cancel()
			}
			return
		}
		if err == nil && p.State == iscpauth.Expired {
			a.deadline = time.Time{}
			a.invalidated = true
			a.generation++
			e.stopStreamsLocked(s, errStreamAuthority)
		}
		a.err = err
		a.nextRefresh = time.Now().Add(5 * time.Second)
		if err != nil || p.State != iscpauth.Active || p.Revision != e.grantMaterial().grant.RevocationEpoch || !time.Now().Before(started.Add(10*time.Second)) {
			return
		}
		if a.policy.State == iscpauth.Active && (a.policy.Revision != p.Revision || a.policy.Version != p.Version || !slices.Equal(a.policy.Scopes, p.Scopes)) {
			a.generation++
			e.stopStreamsLocked(s, errStreamAuthority)
		}
		if a.policy.State == iscpauth.Active && !a.invalidated && !e.streamAuthorityValidLocked(s, 0) {
			a.generation++
			e.stopStreamsLocked(s, errStreamAuthority)
		}
		a.invalidated = false
		a.policy = p
		a.policy.Scopes = slices.Clone(p.Scopes)
		a.deadline = started.Add(5 * time.Minute)
		if !p.ExpiresAt.IsZero() {
			cutoff := started.Add(p.ExpiresAt.Sub(started))
			if cutoff.Before(a.deadline) {
				a.deadline = cutoff
			}
		}
		a.nextRefresh = started.Add(time.Minute)
		if early := a.deadline.Add(-10 * time.Second); early.Before(a.nextRefresh) {
			a.nextRefresh = early
		}
		if !a.watching {
			a.watching = true
			e.workers.Add(1)
			go e.watchStreamAuthority(s)
		}
	}()
}

func (e *Endpoint) watchStreamAuthority(s *activeSession) {
	defer e.workers.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			e.mu.Lock()
			if e.session != s || e.closed {
				e.mu.Unlock()
				return
			}
			a := s.streamAuthority
			if !e.streamAuthorityValidLocked(s, 0) {
				if !a.invalidated {
					a.generation++
					a.invalidated = true
				}
				e.stopStreamsLocked(s, errStreamAuthority)
			}
			if a.checking == nil && !time.Now().Before(a.nextRefresh) {
				e.startStreamRefreshLocked(s)
			}
			e.mu.Unlock()
		}
	}
}

// Unlike ordinary policy checks, a stream refresh publishes its outcome only
// after checking the original session, preventing late queries from changing a
// replacement session's authority.
func (e *Endpoint) queryStreamAuthority(ctx context.Context) (iscpauth.Policy, error) {
	if e.authorityPolicy != nil {
		return e.authorityPolicy(ctx)
	}
	if err := verifyGrant(e.config, e.grantMaterial(), time.Now().UTC()); err != nil {
		return iscpauth.Policy{}, err
	}
	if e.lifecycle != nil {
		return e.lifecycle.AuthorizationPolicy(ctx)
	}
	return iscpauth.Policy{Version: 1, Lifetime: iscpauth.Bounded, Revision: e.grantMaterial().grant.RevocationEpoch, State: iscpauth.Active}, nil
}

// StreamAuthorityRemaining returns a local monotonic publication bound for the
// private helper pipe. It does not refresh authority or disclose credentials.
func (e *Endpoint) StreamAuthorityRemaining(id string) (time.Duration, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.session
	if s == nil {
		return 0, errStreamAuthority
	}
	p := s.streams[id]
	if p == nil || p.ctx.Err() != nil || !e.streamAuthorityValidLocked(s, p.generation) {
		return 0, errStreamAuthority
	}
	a := s.streamAuthority
	d := min(time.Until(a.deadline), time.Until(a.grantDeadline), time.Until(a.capabilityDeadline))
	if d < time.Millisecond {
		return 0, errStreamAuthority
	}
	return d, nil
}
