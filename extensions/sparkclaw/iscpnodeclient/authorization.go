package iscpnodeclient

import (
	"context"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

// An authorizationFlight exists only while a fresh check is in progress. There
// is no completed-result cache or TTL. It belongs to exactly one Client and one
// immutable authority generation; every later nonoverlapping call checks again.
type authorizationFlight struct {
	generation uint64
	done       chan struct{}
	cancel     context.CancelFunc
	waiters    uint64
	finished   bool
	policy     iscpauth.Policy
	err        error
}

// AuthorizationPolicy coalesces overlapping checks without serializing each
// business caller behind a separate issuer network roundtrip. Each waiter keeps
// its own cancellation/deadline. The shared pure read is bounded by the existing
// 30-second network budget and is canceled when its last waiter leaves.
func (cl *Client) AuthorizationPolicy(ctx context.Context) (iscpauth.Policy, error) {
	for {
		if err := ctx.Err(); err != nil {
			return iscpauth.Policy{}, err
		}
		cl.authorityMu.Lock()
		if cl.authorityChanged == nil {
			cl.authorityChanged = make(chan struct{})
		}
		changed := cl.authorityChanged
		if cl.authorityMutations != 0 {
			cl.authorityMu.Unlock()
			select {
			case <-ctx.Done():
				return iscpauth.Policy{}, ctx.Err()
			case <-changed:
				continue
			}
		}
		flight := cl.authorityFlight
		var checkCtx context.Context
		if flight == nil {
			var cancel context.CancelFunc
			checkCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
			flight = &authorizationFlight{generation: cl.authorityGeneration, done: make(chan struct{}), cancel: cancel}
			cl.authorityFlight = flight
		}
		flight.waiters++
		cl.authorityMu.Unlock()
		if checkCtx != nil {
			go cl.runAuthorizationFlight(checkCtx, flight)
		}
		select {
		case <-ctx.Done():
		case <-changed:
		case <-flight.done:
		}
		cl.authorityMu.Lock()
		policy, err, retry := cl.consumeAuthorizationFlightLocked(ctx, flight)
		cl.authorityMu.Unlock()
		if retry {
			continue
		}
		return policy, err
	}
}

// Caller holds authorityMu. This is the waiter's return linearization point.
// Mutations and freshly observed signed revocations fence all older cohorts,
// including already published results whose waiters have not been scheduled.
func (cl *Client) consumeAuthorizationFlightLocked(ctx context.Context, flight *authorizationFlight) (iscpauth.Policy, error, bool) {
	flight.waiters--
	if flight.waiters == 0 && !flight.finished {
		flight.cancel()
		if cl.authorityFlight == flight {
			cl.authorityFlight = nil
		}
	}
	if err := ctx.Err(); err != nil {
		return iscpauth.Policy{}, err, false
	}
	if !flight.finished || flight.generation != cl.authorityGeneration || cl.authorityMutations != 0 {
		return iscpauth.Policy{}, nil, true
	}
	policy := flight.policy
	policy.Scopes = append([]string(nil), policy.Scopes...)
	return policy, flight.err, false
}

func (cl *Client) runAuthorizationFlight(ctx context.Context, flight *authorizationFlight) {
	defer flight.cancel()
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.authorityMu.Lock()
	current := flight == cl.authorityFlight && flight.generation == cl.authorityGeneration && cl.authorityMutations == 0 && flight.waiters != 0
	cl.authorityMu.Unlock()
	var policy iscpauth.Policy
	err := iscpnodeissuer.ErrConflict
	if current {
		// Config/identity are private copies and every Grant/installation
		// mutation is fenced. Bind the read explicitly to the full current
		// identity, Grant, revision, scopes and deployment/Owner/Client.
		binding := cl.authorityBindingDigest()
		policy, err = cl.authorizationPolicyLocked(ctx)
		if binding != cl.authorityBindingDigest() {
			policy, err = iscpauth.Policy{}, iscpnodeissuer.ErrConflict
		}
	}
	cl.authorityMu.Lock()
	if cl.authorityFlight == flight {
		cl.authorityFlight = nil // Unlink before publishing; no later caller can reuse it.
	}
	flight.policy, flight.err, flight.finished = policy, err, true
	close(flight.done)
	cl.authorityMu.Unlock()
}

// beginAuthorityMutation must precede cl.mu acquisition. An in-progress check
// is only a pure read, so it may be canceled; durable renewal/recovery/deletion
// requests retain their existing serialized exact-operation handling. Readers
// cannot publish old active authority across any queued or completed mutation.
func (cl *Client) beginAuthorityMutation() func() {
	cl.authorityMu.Lock()
	cl.authorityMutations++
	cl.authorityGeneration++
	if cl.authorityFlight != nil {
		cl.authorityFlight.cancel()
		cl.authorityFlight = nil
	}
	cl.signalAuthorityChangeLocked()
	cl.authorityMu.Unlock()
	return func() {
		cl.authorityMu.Lock()
		cl.authorityMutations--
		cl.authorityGeneration++
		cl.signalAuthorityChangeLocked()
		cl.authorityMu.Unlock()
	}
}

func (cl *Client) signalAuthorityChangeLocked() {
	if cl.authorityChanged != nil {
		close(cl.authorityChanged)
	}
	cl.authorityChanged = make(chan struct{})
}

// Caller holds cl.mu and has already verified the sealed, signed revoked
// result's identity/scope/revision. A known revoke is terminal, but unlike a
// transient network denial it also advances the fence for published active reads.
func (cl *Client) observeSignedRevocationLocked() {
	if cl.revoked {
		return
	}
	cl.revoked = true
	cl.authorityMu.Lock()
	cl.authorityRevoked = true
	cl.authorityGeneration++
	if cl.authorityFlight != nil {
		cl.authorityFlight.cancel()
		cl.authorityFlight = nil
	}
	cl.signalAuthorityChangeLocked()
	cl.authorityMu.Unlock()
}

// Caller holds cl.mu. The digest is a read-only mirror used solely to identify
// a possible byte-identical AcceptGrant no-op without waiting to cancel a read.
// It is never evidence of current authorization; every Policy still checks fresh.
func (cl *Client) rememberPreviousGrantLocked(g trust.Grant) {
	cl.previous = cloneGrant(g)
	cl.authorityMu.Lock()
	cl.authorityGrantDigest = iscpnodeissuer.Digest(cl.previous)
	cl.authorityMu.Unlock()
}

// Caller holds cl.mu.
func (cl *Client) authorityBindingDigest() string {
	return iscpnodeissuer.Digest(struct {
		Config       StoredConfig
		Identity     identity.DeviceIdentity
		Grant        trust.Grant
		Installation string
	}{cl.cfg, cl.device.Identity, cl.previous, cl.installationID})
}

func cloneGrant(g trust.Grant) trust.Grant {
	g.Permissions = append([]string(nil), g.Permissions...)
	g.RelayConstraints = append([]string(nil), g.RelayConstraints...)
	return g
}
