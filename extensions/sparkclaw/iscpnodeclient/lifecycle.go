package iscpnodeclient

import (
	"context"
	"errors"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type pendingLifecycle struct {
	Request iscpnodeissuer.LifecycleRequest `json:"request"`
	Private []byte                          `json:"private"`
	Result  *iscpnodeissuer.LifecycleResult `json:"result,omitempty"`
}

func (cl *Client) lifecycle(ctx context.Context, kind, operation string, revision uint64, persist bool) (iscpnodeissuer.LifecycleResult, error) {
	var zero iscpnodeissuer.LifecycleResult
	var p pendingLifecycle
	name := "lifecycle.pending"
	if kind == "delete" || kind == "delete-receipt" {
		name = "deletion.pending"
	}
	e := cl.read(name, &p)
	if !persist || errors.Is(e, os.ErrNotExist) {
		req, priv, e := iscpnodeissuer.NewLifecycleRequest(kind, operation, cl.cfg.InvitationID, revision, cl.previous.GrantID, cl.device, cl.cfg.IssuerIdentity.DeviceID, time.Now().UTC())
		if e != nil {
			return zero, e
		}
		if kind == "recover" {
			proof, e := cl.device.CreateProof(c.NewProvider(), cl.cfg.RelayID, operation+"\x00"+req.WrapPublicKey, c.Base64URL(c.RandomBytes(24)), time.Now().UTC())
			if e != nil {
				return zero, e
			}
			req.RelayProof = &proof
			req.Proof, e = cl.device.CreateProof(c.NewProvider(), cl.cfg.IssuerIdentity.DeviceID, iscpnodeissuer.LifecycleChallenge(req), c.Base64URL(c.RandomBytes(24)), time.Now().UTC())
			if e != nil {
				return zero, e
			}
		}
		p = pendingLifecycle{Request: req, Private: priv}
		if persist {
			if e = cl.write(name, p); e != nil {
				return zero, e
			}
		}
	} else if e != nil {
		return zero, e
	}
	if p.Request.Kind != kind && !(kind == "delete-receipt" && p.Request.Kind == "delete") {
		return zero, iscpnodeissuer.ErrConflict
	}
	if p.Request.OperationID != operation && kind != "renew" && kind != "recover" {
		return zero, iscpnodeissuer.ErrConflict
	}
	if p.Request.Revision != revision {
		return zero, iscpnodeissuer.ErrConflict
	}
	if p.Result == nil {
		var wire iscpnodeissuer.LifecycleResponse
		step := "renew"
		if p.Request.Kind == "recover" {
			step = "recover"
		}
		if e = cl.exchange(ctx, p.Request.OperationID, step, p.Request, &wire); e != nil {

			return zero, e
		}
		out, e := iscpnodeissuer.OpenLifecycle(p.Request, wire, p.Private)
		if e != nil {
			return zero, e
		}
		if out.Version != 1 || out.OperationID != p.Request.OperationID || out.InvitationID != cl.cfg.InvitationID || iscpnodeissuer.Digest(out.Identity) != iscpnodeissuer.Digest(cl.device.Identity) || iscpnodeissuer.Digest(out.Scopes) != iscpnodeissuer.Digest(cl.cfg.Scopes) || iscpnodeissuer.VerifyObject("sparkclaw.iscp.lifecycle-result.v1", out, cl.cfg.IssuerIdentity, out.Signature) != nil {
			return zero, iscpnodeissuer.ErrDenied
		}
		if out.State != "active" && out.State != "revoked" {
			return zero, iscpnodeissuer.ErrDenied
		}
		if out.State == "revoked" && out.Revision <= cl.cfg.Revision {
			return zero, iscpnodeissuer.ErrDenied
		}
		if out.State == "active" && out.Revision != cl.cfg.Revision {
			return zero, iscpnodeissuer.ErrDenied
		}
		if out.Grant != nil && cl.verifyGrantAt(*out.Grant, out.Grant.NotBefore) != nil {
			return zero, iscpnodeissuer.ErrDenied
		}
		if out.RelayReceipt != nil {
			credentials, e := iscpnodeissuer.OpenRegistrationReceipt(*out.RelayReceipt, p.Private, cl.device.Identity)
			if e != nil {
				return zero, e
			}
			out.RelayCredentials = &credentials
		}
		p.Result = &out
		if persist {
			if e = cl.write(name, p); e != nil {
				return zero, e
			}
		}
	}
	if p.Result.State == "revoked" {
		cl.observeSignedRevocationLocked()
		if kind != "delete" && kind != "delete-receipt" {
			return zero, iscpbridge.ErrAuthorizationRevoked
		}
	}
	if persist && name == "lifecycle.pending" {
		cl.pending = &p
	}
	return *p.Result, nil
}
func (cl *Client) UsesStandingAuthorization() bool { return true }
func (cl *Client) HasPendingRenewal() bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.cfg.ControlV2 {
		state, err := (clientControlStore{cl}).Load(context.Background())
		return err == nil && state.Pending != nil
	}
	var p pendingLifecycle
	return cl.read("lifecycle.pending", &p) == nil
}
func (cl *Client) Current(ctx context.Context) (trust.Grant, error) {
	cl.mu.Lock()
	previous := cloneGrant(cl.previous)
	cl.mu.Unlock()
	if !time.Now().Before(previous.ExpiresAt) {
		return cl.Renew(ctx, previous)
	}
	return previous, nil
}
func (cl *Client) Renew(ctx context.Context, previous trust.Grant) (trust.Grant, error) {
	end := cl.beginAuthorityMutation()
	defer end()
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.revoked {
		return trust.Grant{}, iscpbridge.ErrAuthorizationRevoked
	}
	if previous.SubjectDeviceID != cl.device.Identity.DeviceID || previous.Audience != cl.cfg.ResponderIdentity.DeviceID || previous.ConfirmationThumbprint != cl.device.Identity.PublicKey.KID {
		return trust.Grant{}, iscpnodeissuer.ErrDenied
	}
	cl.rememberPreviousGrantLocked(previous)
	if cl.cfg.ControlV2 {
		out, err := cl.controlLifecycleLocked(ctx, "renew")
		if err != nil {
			return trust.Grant{}, err
		}
		cl.completed = out.Grant
		return *out.Grant, nil
	}
	out, e := cl.lifecycle(ctx, "renew", "renew-"+c.Base64URL(c.RandomBytes(24)), cl.cfg.Revision, true)
	if e != nil {
		return trust.Grant{}, e
	}
	if out.Grant == nil {
		return trust.Grant{}, iscpnodeissuer.ErrDenied
	}
	if !time.Now().Before(out.Grant.ExpiresAt) {
		var pending pendingLifecycle
		if e := cl.read("lifecycle.pending", &pending); e != nil {
			return trust.Grant{}, e
		}
		if e := cl.ackApplied(pending); e != nil {
			return trust.Grant{}, e
		}
		if e := os.Remove(filepath.Join(cl.directory, "lifecycle.pending")); e != nil {
			return trust.Grant{}, e
		}
		cl.pending = nil
		return trust.Grant{}, iscpbridge.ErrGrantRenewalResultExpired
	}
	if e = cl.verifyGrant(*out.Grant); e != nil {
		return trust.Grant{}, e
	}
	cl.completed = out.Grant
	return *out.Grant, nil
}
func (cl *Client) AcceptGrant(g trust.Grant) error {
	g = cloneGrant(g)
	digest := iscpnodeissuer.Digest(g)
	cl.authorityMu.Lock()
	revoked := cl.authorityRevoked
	unchanged := cl.authorityGrantDigest == digest
	cl.authorityMu.Unlock()
	if revoked {
		return iscpbridge.ErrAuthorizationRevoked
	}
	if e := cl.verifyGrant(g); e != nil {
		return e
	}
	if unchanged {
		// Current's ordinary poll supplies the identical accepted Grant.
		// Wait for any serialized check/mutation, then revalidate both the
		// exact current Grant and its expiry without canceling a pure check.
		cl.mu.Lock()
		revoked = cl.revoked
		if !revoked && iscpnodeissuer.Digest(cl.previous) == digest {
			e := cl.verifyGrant(g)
			cl.mu.Unlock()
			return e
		}
		cl.mu.Unlock()
		if revoked {
			return iscpbridge.ErrAuthorizationRevoked
		}
	}
	end := cl.beginAuthorityMutation()
	defer end()
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.revoked {
		return iscpbridge.ErrAuthorizationRevoked
	}
	if e := cl.verifyGrant(g); e != nil {
		return e
	}
	cl.rememberPreviousGrantLocked(g)
	return nil
}
func (cl *Client) CommitRenewal() error {
	end := cl.beginAuthorityMutation()
	defer end()
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.cfg.ControlV2 {
		return cl.commitControlRenewalLocked()
	}
	var p pendingLifecycle
	if e := cl.read("lifecycle.pending", &p); errors.Is(e, os.ErrNotExist) {
		return nil
	} else if e != nil {
		return e
	}
	if p.Result == nil || p.Result.Grant == nil || cl.previous.GrantID != p.Result.Grant.GrantID {
		return iscpnodeissuer.ErrConflict
	}
	if e := cl.ackApplied(p); e != nil {
		return e
	}
	if e := os.Remove(filepath.Join(cl.directory, "lifecycle.pending")); e != nil {
		return e
	}
	cl.pending = nil
	cl.completed = nil
	return nil
}

// authorizationPolicyLocked performs one fresh, signed check. Its caller holds
// cl.mu; overlapping readers are coordinated separately by AuthorizationPolicy.
func (cl *Client) authorizationPolicyLocked(ctx context.Context) (iscpauth.Policy, error) {
	if cl.revoked {
		return iscpauth.Policy{}, iscpbridge.ErrAuthorizationRevoked
	}
	out, e := cl.lifecycle(ctx, "check", "check-"+c.Base64URL(c.RandomBytes(24)), cl.cfg.Revision, false)
	if e != nil {
		return iscpauth.Policy{}, e
	}
	if out.State != "active" {
		return iscpauth.Policy{}, iscpbridge.ErrAuthorizationRevoked
	}
	return iscpauth.Policy{Version: 2, Lifetime: iscpauth.UntilRevoked, Revision: out.Revision, State: iscpauth.Active, Scopes: out.Scopes}, nil
}
func (cl *Client) CheckAuthorization(ctx context.Context) error {
	_, e := cl.AuthorizationPolicy(ctx)
	return e
}
func (cl *Client) DeleteAuthorization(ctx context.Context, operation string, revision uint64) (iscpauth.DeletionReceipt, error) {
	end := cl.beginAuthorityMutation()
	defer end()
	cl.mu.Lock()
	defer cl.mu.Unlock()
	out, e := cl.lifecycle(ctx, "delete", operation, revision, true)
	if e != nil {
		return iscpauth.DeletionReceipt{}, e
	}
	if out.Deletion == nil || out.Deletion.OperationID != operation || out.Deletion.ExpectedRevision != revision || out.Deletion.AuthorizationRevision != revision+1 || out.Deletion.State != "revoked" {
		return iscpauth.DeletionReceipt{}, iscpnodeissuer.ErrDenied
	}
	return *out.Deletion, nil
}
func (cl *Client) AuthorizationDeletionReceipt(ctx context.Context, operation string, revision uint64) (iscpauth.DeletionReceipt, error) {
	return cl.DeleteAuthorization(ctx, operation, revision)
}

// RecoverTransport returns credentials only after a fresh device proof and an
// atomic Relay recovery receipt. Caller saves credentials/Grant before committing.
func (cl *Client) RecoverTransport(ctx context.Context) (iscpnodeissuer.LifecycleResult, error) {
	end := cl.beginAuthorityMutation()
	defer end()
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.cfg.ControlV2 {
		return cl.controlLifecycleLocked(ctx, "recover")
	}
	return cl.lifecycle(ctx, "recover", "recover-"+c.Base64URL(c.RandomBytes(24)), cl.cfg.Revision, true)
}

func (cl *Client) PendingLifecycleKind() (string, error) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.cfg.ControlV2 {
		state, err := (clientControlStore{cl}).Load(context.Background())
		if err != nil {
			return "", err
		}
		if state.Pending == nil {
			return "", nil
		}
		return strings.TrimPrefix(state.Pending.Intent.Kind, "credential."), nil
	}
	var p pendingLifecycle
	e := cl.read("lifecycle.pending", &p)
	if errors.Is(e, os.ErrNotExist) {
		return "", nil
	}
	if e != nil {
		return "", e
	}
	return p.Request.Kind, nil
}
func (cl *Client) ResolvePendingLifecycle(ctx context.Context) (iscpnodeissuer.LifecycleResult, error) {
	end := cl.beginAuthorityMutation()
	defer end()
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.cfg.ControlV2 {
		state, err := (clientControlStore{cl}).Load(ctx)
		if err != nil {
			return iscpnodeissuer.LifecycleResult{}, err
		}
		if state.Pending == nil {
			return iscpnodeissuer.LifecycleResult{}, iscpnodeissuer.ErrConflict
		}
		return cl.controlLifecycleLocked(ctx, strings.TrimPrefix(state.Pending.Intent.Kind, "credential."))
	}
	var p pendingLifecycle
	if e := cl.read("lifecycle.pending", &p); e != nil {
		return iscpnodeissuer.LifecycleResult{}, e
	}
	out, e := cl.lifecycle(ctx, p.Request.Kind, p.Request.OperationID, p.Request.Revision, true)
	if e != nil {
		return out, e
	}
	if out.Grant != nil && !time.Now().Before(out.Grant.ExpiresAt) {
		if e = cl.ackApplied(p); e != nil {
			return iscpnodeissuer.LifecycleResult{}, e
		}
		if e = os.Remove(filepath.Join(cl.directory, "lifecycle.pending")); e != nil {
			return iscpnodeissuer.LifecycleResult{}, e
		}
		cl.pending = nil
		return iscpnodeissuer.LifecycleResult{}, iscpbridge.ErrGrantRenewalResultExpired
	}
	return out, nil
}

func (cl *Client) ackApplied(p pendingLifecycle) error {
	req := iscpnodeissuer.AppliedRequest{Version: 1, OperationID: p.Request.OperationID, GrantID: p.Result.Grant.GrantID, Identity: cl.device.Identity}
	proof, e := cl.device.CreateProof(c.NewProvider(), cl.cfg.IssuerIdentity.DeviceID, iscpnodeissuer.AppliedChallenge(req), c.Base64URL(c.RandomBytes(24)), time.Now().UTC())
	if e != nil {
		return e
	}
	req.Proof = proof
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var ack iscpnodeissuer.AppliedReceipt
	if e = cl.exchange(ctx, p.Request.OperationID, "applied", req, &ack); e != nil {
		return e
	}
	if ack.Version != 1 || ack.OperationID != p.Request.OperationID || ack.GrantID != p.Result.Grant.GrantID || ack.State != "applied" || iscpnodeissuer.Digest(ack.Identity) != iscpnodeissuer.Digest(cl.device.Identity) || iscpnodeissuer.VerifyObject("sparkclaw.iscp.applied-receipt.v1", ack, cl.cfg.IssuerIdentity, ack.Signature) != nil {
		return iscpnodeissuer.ErrDenied
	}

	return nil
}
