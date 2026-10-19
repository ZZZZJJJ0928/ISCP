package iscpworkbench

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

func streamAuthorityUnitEndpoint(t *testing.T, query func(context.Context) (iscpauth.Policy, error)) (*Endpoint, *activeSession) {
	t.Helper()
	e, s := responseUnitEndpoint(t, query)
	s.capabilities = &TransportCapabilities{Profile: ProfileV2, StreamSchemaVersion: 1, AuthorizationRevision: 1, ExpiresAt: time.Now().Add(time.Hour), Operations: []string{OperationExecutionProgressStream}}
	s.streamAuthority = &streamAuthority{policy: activeResponsePolicy(), generation: 1, deadline: time.Now().Add(time.Minute), nextRefresh: time.Now().Add(time.Hour), watching: true}
	// These unit tests drive expiry/refresh explicitly, while real session
	// teardown still owns all asynchronous queries through Endpoint.workers.
	return e, s
}

func beginTestStreamRefresh(t *testing.T, e *Endpoint, s *activeSession) <-chan struct{} {
	t.Helper()
	e.mu.Lock()
	e.startStreamRefreshLocked(s)
	done := s.streamAuthority.checking
	e.mu.Unlock()
	if done == nil {
		t.Fatal("refresh did not start")
	}
	return done
}

func awaitStreamRefresh(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("refresh did not finish")
	}
}

func TestStreamValidSnapshotDoesNotWaitForStalledBackgroundRefresh(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var calls atomic.Int32
	e, s := streamAuthorityUnitEndpoint(t, func(ctx context.Context) (iscpauth.Policy, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
			return activeResponsePolicy(), nil
		case <-ctx.Done():
			return iscpauth.Policy{}, ctx.Err()
		}
	})
	done := beginTestStreamRefresh(t, e, s)
	awaitResponseSignal(t, entered)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	for i := 0; i < 20; i++ {
		generation, err := e.ensureStreamAuthority(ctx, s)
		if err != nil || generation != 1 || e.streamLocalCheck(s, generation) != nil {
			t.Fatalf("valid cached batch waited for query: generation=%d err=%v", generation, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh work was not shared: %d", calls.Load())
	}
	unblock()
	awaitStreamRefresh(t, done)
	if e.streamLocalCheck(s, 1) != nil {
		t.Fatal("same-version refresh invalidated current subscription")
	}
}

func TestStreamTransientRefreshFailurePreservesOnlyUnexpiredSnapshot(t *testing.T) {
	e, s := streamAuthorityUnitEndpoint(t, func(context.Context) (iscpauth.Policy, error) {
		return iscpauth.Policy{}, errors.New("issuer temporarily unavailable")
	})
	e.mu.Lock()
	original := s.streamAuthority.deadline
	e.mu.Unlock()
	awaitStreamRefresh(t, beginTestStreamRefresh(t, e, s))
	if e.streamLocalCheck(s, 1) != nil {
		t.Fatal("transient refresh failure discarded a valid snapshot")
	}
	e.mu.Lock()
	if !s.streamAuthority.deadline.Equal(original) {
		t.Error("failed refresh extended authority")
	}
	s.streamAuthority.deadline = time.Now().Add(-time.Second)
	e.mu.Unlock()
	if e.streamLocalCheck(s, 1) == nil {
		t.Fatal("expired cached authority survived failed refresh")
	}
}

func TestStreamRefreshAfterExpiryCannotReviveOldGeneration(t *testing.T) {
	e, s := streamAuthorityUnitEndpoint(t, func(context.Context) (iscpauth.Policy, error) {
		return activeResponsePolicy(), nil
	})
	e.mu.Lock()
	s.streamAuthority.deadline = time.Now().Add(-time.Second)
	e.mu.Unlock()
	if e.streamLocalCheck(s, 1) == nil {
		t.Fatal("expired snapshot remained valid")
	}
	generation, err := e.ensureStreamAuthority(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	if generation == 1 || e.streamLocalCheck(s, 1) == nil {
		t.Fatal("successful refresh revived the expired subscription generation")
	}
	if e.streamLocalCheck(s, generation) != nil {
		t.Fatal("new observation did not acquire refreshed authority")
	}
}

func TestStreamLateRefreshCannotReviveRevokedOrReplacedSession(t *testing.T) {
	for _, mode := range []string{"known-revocation", "session-replacement", "expired-result"} {
		t.Run(mode, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			policy := activeResponsePolicy()
			if mode == "expired-result" {
				policy.ExpiresAt = time.Now().Add(-time.Second)
			}
			e, s := streamAuthorityUnitEndpoint(t, func(context.Context) (iscpauth.Policy, error) {
				close(entered)
				<-release // Deliberately late provider ignores cancellation.
				return policy, nil
			})
			e.mu.Lock()
			original := s.streamAuthority.deadline
			e.mu.Unlock()
			done := beginTestStreamRefresh(t, e, s)
			awaitResponseSignal(t, entered)
			switch mode {
			case "known-revocation":
				e.observeAuthorizationError(iscpbridge.ErrAuthorizationRevoked)
			case "session-replacement":
				e.mu.Lock()
				e.session = newSession(t.Context(), newUUID(), session.LocalHello{})
				e.mu.Unlock()
			}
			unblock()
			awaitStreamRefresh(t, done)
			if e.streamLocalCheck(s, 1) == nil {
				t.Fatal("late response established invalid authority")
			}
			if mode != "expired-result" {
				e.mu.Lock()
				changed := !s.streamAuthority.deadline.Equal(original)
				e.mu.Unlock()
				if changed {
					t.Fatal("late result mutated revoked/replaced authority")
				}
			}
		})
	}
}

func TestStreamScopeChangeFencesOldGenerationButSameRevisionRenewalDoesNot(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-rights-renewal", true: "scope-reduced"}[changed], func(t *testing.T) {
			policy := activeResponsePolicy()
			if changed {
				policy.Scopes = []string{"workbench.text"}
			}
			e, s := streamAuthorityUnitEndpoint(t, func(context.Context) (iscpauth.Policy, error) { return policy, nil })
			awaitStreamRefresh(t, beginTestStreamRefresh(t, e, s))
			e.mu.Lock()
			generation := s.streamAuthority.generation
			e.mu.Unlock()
			if changed {
				if generation == 1 || e.streamLocalCheck(s, 1) == nil {
					t.Fatal("permission change reused original subscription authority")
				}
			} else if generation != 1 || e.streamLocalCheck(s, 1) != nil {
				t.Fatal("same rights renewal restarted a valid subscription")
			}
		})
	}
}

func TestStreamVerifiedGrantAndCapabilityRenewalKeepsSubscriptionGeneration(t *testing.T) {
	var queries atomic.Int32
	e, s := streamAuthorityUnitEndpoint(t, func(context.Context) (iscpauth.Policy, error) {
		queries.Add(1)
		return activeResponsePolicy(), nil
	})
	provider := iscpcrypto.NewProvider()
	issuer, err := identity.NewDevice(provider, "renewal-authority", "issuer", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	e.grantMu.Lock()
	grant := e.material.grant
	grant.ExpiresAt = time.Now().Add(30 * time.Second)
	grant, err = trust.SignGrant(provider, issuer, grant)
	if err == nil {
		e.material.issuer, e.material.grant = issuer.Identity, grant
	}
	e.grantMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	s.capabilities.ExpiresAt = time.Now().Add(30 * time.Second)
	e.mu.Unlock()
	if e.streamLocalCheck(s, 1) != nil {
		t.Fatal("initial signed authority failed")
	}
	e.mu.Lock()
	beforeGrant, beforeCapability := s.streamAuthority.grantDeadline, s.streamAuthority.capabilityDeadline
	e.mu.Unlock()
	grant.GrantID = newUUID()
	grant.ExpiresAt = time.Now().Add(time.Hour)
	grant, err = trust.SignGrant(provider, issuer, grant)
	if err != nil {
		t.Fatal(err)
	}
	e.grantMu.Lock()
	e.material.grant = grant
	e.grantMu.Unlock()
	e.mu.Lock()
	s.capabilities.ExpiresAt = time.Now().Add(time.Hour)
	e.mu.Unlock()
	generation, err := e.ensureStreamAuthority(t.Context(), s)
	if err != nil || generation != 1 || queries.Load() != 0 {
		t.Fatalf("same-rights renewal reopened/rechecked stream: generation=%d queries=%d err=%v", generation, queries.Load(), err)
	}
	e.mu.Lock()
	extended := s.streamAuthority.grantDeadline.After(beforeGrant) && s.streamAuthority.capabilityDeadline.After(beforeCapability)
	e.mu.Unlock()
	if !extended {
		t.Fatal("verified renewal did not extend local authority deadlines")
	}
}

func TestStreamAuthoritySnapshotTTLStartsAtQueryInitiation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	e, s := streamAuthorityUnitEndpoint(t, func(ctx context.Context) (iscpauth.Policy, error) {
		close(entered)
		select {
		case <-release:
			return activeResponsePolicy(), nil
		case <-ctx.Done():
			return iscpauth.Policy{}, ctx.Err()
		}
	})
	before := time.Now()
	done := beginTestStreamRefresh(t, e, s)
	awaitResponseSignal(t, entered)
	afterStart := time.Now()
	time.Sleep(30 * time.Millisecond)
	unblock()
	awaitStreamRefresh(t, done)
	e.mu.Lock()
	deadline := s.streamAuthority.deadline
	e.mu.Unlock()
	if deadline.Before(before.Add(5*time.Minute)) || deadline.After(afterStart.Add(5*time.Minute)) {
		t.Fatal("query latency extended authorization lifetime")
	}
}

func TestStreamExplicitInactivePolicyInvalidatesCachedAuthorityImmediately(t *testing.T) {
	for _, state := range []string{iscpauth.Revoked, iscpauth.Expired} {
		t.Run(state, func(t *testing.T) {
			var checks atomic.Int32
			e, s := streamAuthorityUnitEndpoint(t, func(context.Context) (iscpauth.Policy, error) {
				p := activeResponsePolicy()
				if checks.Add(1) == 1 {
					p.State = state
					if state == iscpauth.Expired {
						p.Lifetime, p.ExpiresAt = iscpauth.Bounded, time.Now().Add(-time.Second)
					}
				}
				return p, nil
			})
			p := recoveryPending(t.Context())
			senderCtx, stop := context.WithCancel(t.Context())
			defer stop()
			e.mu.Lock()
			s.streams[newUUID()] = p
			s.streamSenders[newUUID()] = &streamSender{ctx: senderCtx, cancel: stop}
			e.mu.Unlock()
			awaitStreamRefresh(t, beginTestStreamRefresh(t, e, s))
			if e.streamLocalCheck(s, 1) == nil {
				t.Fatal("explicit inactive policy left cached text authority active")
			}
			select {
			case <-p.errors:
			default:
				t.Fatal("inactive policy did not close receiving observation")
			}
			if senderCtx.Err() == nil {
				t.Fatal("inactive policy did not stop sender")
			}
			generation, err := e.ensureStreamAuthority(t.Context(), s)
			if state == iscpauth.Revoked {
				if err == nil || checks.Load() != 1 {
					t.Fatalf("known revocation rechecked or revived: queries=%d err=%v", checks.Load(), err)
				}
			} else if err != nil || generation == 1 || e.streamLocalCheck(s, 1) == nil {
				t.Fatalf("restored expired authority failed generation fencing: generation=%d err=%v", generation, err)
			}
		})
	}
}

func TestStreamLateRevocationFromReplacedSessionCannotRevokeCurrentSession(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	e, s := streamAuthorityUnitEndpoint(t, func(context.Context) (iscpauth.Policy, error) {
		close(entered)
		<-release
		return iscpauth.Policy{}, iscpbridge.ErrAuthorizationRevoked
	})
	done := beginTestStreamRefresh(t, e, s)
	awaitResponseSignal(t, entered)
	e.mu.Lock()
	replacement := newSession(t.Context(), newUUID(), session.LocalHello{})
	e.session = replacement
	e.mu.Unlock()
	unblock()
	awaitStreamRefresh(t, done)
	e.mu.Lock()
	revoked, current := e.authorizationRevoked, e.session
	e.mu.Unlock()
	if revoked || current != replacement || replacement.ctx.Err() != nil {
		t.Fatal("old-session query revoked a replacement identity/session")
	}
}

func TestStreamGrantRevisionChangeRejectsOldSnapshotAndLateQuery(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var queries atomic.Int32
	e, s := streamAuthorityUnitEndpoint(t, func(ctx context.Context) (iscpauth.Policy, error) {
		p := activeResponsePolicy()
		if queries.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return iscpauth.Policy{}, ctx.Err()
			}
		} else {
			p.Revision = 2
		}
		return p, nil
	})
	provider := iscpcrypto.NewProvider()
	issuer, err := identity.NewDevice(provider, "revision-authority", "issuer", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	e.grantMu.Lock()
	grant, err := trust.SignGrant(provider, issuer, e.material.grant)
	if err == nil {
		e.material.issuer, e.material.grant = issuer.Identity, grant
	}
	e.grantMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if e.streamLocalCheck(s, 1) != nil {
		t.Fatal("initial authority failed")
	}
	done := beginTestStreamRefresh(t, e, s)
	awaitResponseSignal(t, entered)
	grant.RevocationEpoch = 2
	grant, err = trust.SignGrant(provider, issuer, grant)
	if err != nil {
		t.Fatal(err)
	}
	e.grantMu.Lock()
	e.material.grant = grant
	e.grantMu.Unlock()
	e.mu.Lock()
	s.capabilities.AuthorizationRevision = 2
	e.mu.Unlock()
	if e.streamLocalCheck(s, 1) == nil {
		t.Error("revision-one snapshot authorized revised Grant/capability")
	}
	unblock()
	awaitStreamRefresh(t, done)
	if e.streamLocalCheck(s, 0) == nil {
		t.Fatal("late revision-one query reestablished authority after revision changed")
	}
	generation, err := e.ensureStreamAuthority(t.Context(), s)
	if err != nil || generation == 1 || e.streamLocalCheck(s, 1) == nil {
		t.Fatalf("current revision recovery failed fencing: generation=%d err=%v", generation, err)
	}
}
