package iscpbridge

import (
	"context"
	"errors"
	"strconv"
	"time"

	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
)

// CredentialAuthorityTermination is produced only after the owning control
// client verifies a correlated terminal response using this pinned authority.
// Its revision belongs to that authority, not necessarily to the Relay lease.
type CredentialAuthorityTermination struct {
	AuthorityPublicKey    string
	AuthorizationRevision string
	Cause                 error
}

func (e *CredentialAuthorityTermination) Error() string {
	return "credential authority ended: " + e.Cause.Error()
}
func (e *CredentialAuthorityTermination) Unwrap() error { return e.Cause }

func (p *managedCredentialProvider) recordTerminalLocked(err error) error {
	var typed *control.Error
	if !errors.As(err, &typed) || (typed.Code != "authorization_revoked" && typed.Code != "authorization_ended") || typed.AuthorizationRevision == nil {
		return nil
	}
	key, revision := p.binding.RelayPublicKey, string(*typed.AuthorizationRevision)
	var source *CredentialAuthorityTermination
	if errors.As(err, &source) {
		if source.AuthorityPublicKey != p.binding.IssuerPublicKey && source.AuthorityPublicKey != p.binding.RelayPublicKey {
			return nil
		}
		key, revision = source.AuthorityPublicKey, source.AuthorizationRevision
	} else if typed.Audience != p.binding.TargetServiceID {
		return nil
	}
	nextRevision, parseErr := strconv.ParseUint(revision, 10, 64)
	if parseErr != nil || nextRevision == 0 {
		return nil
	}
	oldRevision := uint64(0)
	if key == p.binding.RelayPublicKey {
		oldRevision, _ = strconv.ParseUint(p.state.AuthorizationRevision, 10, 64)
	}
	if p.state.TerminalAuthorityPublicKey == key {
		terminal, _ := strconv.ParseUint(p.state.TerminalAuthorityRevision, 10, 64)
		if terminal > oldRevision {
			oldRevision = terminal
		}
	}
	if nextRevision < oldRevision || p.state.Reason == CredentialRevoked {
		return nil
	}
	next := p.state
	next.Lease = nil
	next.Version++
	next.Reason = CredentialRevoked
	next.TerminalAuthorityPublicKey = key
	next.TerminalAuthorityRevision = revision
	if key == p.binding.RelayPublicKey {
		next.AuthorizationRevision = revision
	}
	if err := p.persist(next); err != nil {
		return err
	}
	p.state = next
	p.publishLocked()
	return nil
}
func (p *managedCredentialProvider) observeTerminal(err error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
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
	return p.recordTerminalLocked(err)
}
