package iscpnodeclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	bridge "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

const controlJournalName = "operations.v2"

type clientControlStore struct{ client *Client }

func (s clientControlStore) Load(ctx context.Context) (control.ClientJournal, error) {
	unlock, err := bridge.LockPrivateCheckpoint(ctx, filepath.Join(s.client.directory, controlJournalName+".lock"))
	if err != nil {
		return control.ClientJournal{}, err
	}
	defer unlock()
	var state control.ClientJournal
	err = s.client.read(controlJournalName, &state)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return state, err
}
func (s clientControlStore) CompareAndSwap(ctx context.Context, expected uint64, next control.ClientJournal) error {
	unlock, err := bridge.LockPrivateCheckpoint(ctx, filepath.Join(s.client.directory, controlJournalName+".lock"))
	if err != nil {
		return err
	}
	defer unlock()
	var state control.ClientJournal
	err = s.client.read(controlJournalName, &state)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if state.Version != expected || next.Version != expected+1 {
		return control.ErrJournalCAS
	}
	return s.client.write(controlJournalName, next)
}
func (cl *Client) UsesControlV2() bool { return cl.cfg.ControlV2 }
func (cl *Client) controlCoordinator() (*control.Coordinator, error) {
	if !cl.cfg.ControlV2 {
		return nil, control.ErrInvalid
	}
	transport, err := control.NewClient(cl.cfg.Origin, cl.cfg.IssuerIdentity.DeviceID, cl.device, cl.cfg.IssuerIdentity, cl.http)
	if err != nil {
		return nil, err
	}
	scopes := append([]string(nil), cl.cfg.Scopes...)
	sort.Strings(scopes)
	return &control.Coordinator{Client: transport, Store: clientControlStore{cl}, Namespace: control.CredentialNamespace, Subject: control.Subject{DomainID: cl.device.Identity.DomainID, DeviceID: cl.device.Identity.DeviceID, BindingID: cl.cfg.Binding.ClientID}, Target: control.Target{ServiceID: cl.cfg.IssuerIdentity.DeviceID, ResourceID: cl.cfg.Binding.ClientID}, Revision: control.Number(cl.cfg.Revision), ResourceVersion: control.Number(cl.cfg.Revision), Scopes: scopes, VerifyResult: cl.verifyControlResult}, nil
}
func (cl *Client) verifyControlResult(intent control.Intent, result control.Result) error {
	if result.Payload.State == "failed" && result.Payload.Body.Code == "generation_conflict" && result.Payload.Body.Grant == nil && result.Payload.Body.RelayResult == nil {
		return nil
	}
	grant := result.Payload.Body.Grant
	if result.Payload.State != "succeeded" || grant == nil || cl.verifyGrantAt(*grant, grant.NotBefore) != nil {
		return control.ErrAuthentication
	}
	if intent.Kind == "credential.renew" {
		if result.Payload.Body.RelayResult != nil {
			return control.ErrAuthentication
		}
		return nil
	}
	// The verified outer issuer signature commits the complete child result.
	// The issuer checks its exact durable child key/digest; the consumer verifies
	// Relay signer/subject/target independently, without inventing a service actor
	// pin absent from enrollment. A self-authored terminal cannot be delegated.
	child := result.Payload.Body.RelayResult
	if intent.Kind != "credential.recover" || child == nil || child.Verify(cl.cfg.RelaySignerIdentity) != nil || child.Payload.State != "succeeded" || child.Payload.Key.Namespace != control.RelayNamespace || child.Payload.Key.DomainID != cl.device.Identity.DomainID || child.Payload.Key.DeviceID == cl.device.Identity.DeviceID {
		return control.ErrAuthentication
	}
	credentials := child.Payload.Body.RelayCredentials
	if credentials == nil || credentials.TargetServiceID != cl.cfg.RelayID || credentials.BindingID != cl.cfg.Binding.ClientID || credentials.CredentialGeneration != child.Payload.CredentialGeneration || credentials.AuthorizationRevision == "0" {
		return control.ErrAuthentication
	}
	for _, token := range []control.Credential{credentials.Access, credentials.Refresh} {
		if token.DomainID != cl.device.Identity.DomainID || token.DeviceID != cl.device.Identity.DeviceID || token.Token == "" {
			return control.ErrAuthentication
		}
	}
	return nil
}
func (cl *Client) controlResultLocked(ctx context.Context, kind string) (control.Result, error) {
	coordinator, err := cl.controlCoordinator()
	if err != nil {
		return control.Result{}, err
	}
	return coordinator.Result(ctx, kind)
}
func (cl *Client) controlLifecycleLocked(ctx context.Context, kind string) (node.LifecycleResult, error) {
	result, err := cl.controlResultLocked(ctx, "credential."+kind)
	if err != nil {
		return node.LifecycleResult{}, err
	}
	out := node.LifecycleResult{Version: 2, OperationID: result.Payload.Key.OperationID, InvitationID: cl.cfg.InvitationID, Identity: cl.device.Identity, Revision: cl.cfg.Revision, State: "active", Scopes: append([]string(nil), cl.cfg.Scopes...), Grant: result.Payload.Body.Grant}
	if child := result.Payload.Body.RelayResult; child != nil {
		tokens := child.Payload.Body.RelayCredentials
		out.RelayCredentials = &node.RelayCredentials{Access: bridge.RelayCredential{DomainID: tokens.Access.DomainID, DeviceID: tokens.Access.DeviceID, Token: tokens.Access.Token, ExpiresAt: tokens.Access.ExpiresAt}, Refresh: bridge.RelayCredential{DomainID: tokens.Refresh.DomainID, DeviceID: tokens.Refresh.DeviceID, Token: tokens.Refresh.Token, ExpiresAt: tokens.Refresh.ExpiresAt}}
	}
	return out, nil
}

// RecoverCredentialLease is the real provider callback. Both target signatures
// and independent target generations are verified before returning the lease.
// The encrypted pending result remains until CredentialLeaseInstalled is called.
func (cl *Client) RecoverCredentialLease(ctx context.Context, binding bridge.CredentialBinding, expected bridge.CredentialGeneration, bundle bridge.EnrollmentBundle) (bridge.CredentialLease, error) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if binding.DomainID != cl.device.Identity.DomainID || binding.DeviceID != cl.device.Identity.DeviceID || binding.ResourceBindingID != cl.cfg.Binding.ClientID || binding.TargetServiceID != cl.cfg.RelayID || binding.IssuerPublicKey != cl.cfg.IssuerIdentity.PublicKey.Public || binding.RelayPublicKey != cl.cfg.RelaySignerIdentity.PublicKey.Public || binding.TLSCertificateSHA256 != c.Base64URL(c.SHA256([]byte(cl.cfg.TLSCertificatePEM))) {
		return bridge.CredentialLease{}, control.ErrAuthentication
	}
	result, err := cl.controlResultLocked(ctx, "credential.recover")
	if err != nil {
		return bridge.CredentialLease{}, err
	}
	child := result.Payload.Body.RelayResult
	tokens := child.Payload.Body.RelayCredentials
	old, _ := control.Counter(expected).Uint64()
	next, err := tokens.CredentialGeneration.Uint64()
	if err != nil || next < old {
		return bridge.CredentialLease{}, control.ErrAuthentication
	}
	bundle.Access = bridge.RelayCredential{DomainID: tokens.Access.DomainID, DeviceID: tokens.Access.DeviceID, Token: tokens.Access.Token, ExpiresAt: tokens.Access.ExpiresAt}
	bundle.Refresh = bridge.RelayCredential{DomainID: tokens.Refresh.DomainID, DeviceID: tokens.Refresh.DeviceID, Token: tokens.Refresh.Token, ExpiresAt: tokens.Refresh.ExpiresAt}
	bundle.IssuedAt = child.Payload.CompletedAt
	bundle.ExpiresAt = bundle.Refresh.ExpiresAt
	expiry := result.UsableUntil()
	return bridge.CredentialLease{Binding: binding, Enrollment: bundle, CredentialGeneration: bridge.CredentialGeneration(tokens.CredentialGeneration), AuthorizationRevision: string(tokens.AuthorizationRevision), ExpiresAt: expiry}, nil
}

// PendingControlGrant lets the lifecycle persist the verified original Grant
// before the provider durably installs the transport lease.
func (cl *Client) PendingControlGrant(ctx context.Context) (node.LifecycleResult, error) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	state, err := (clientControlStore{cl}).Load(ctx)
	if err != nil {
		return node.LifecycleResult{}, err
	}
	if state.Pending == nil || state.Pending.Result == nil {
		return node.LifecycleResult{}, control.ErrUnknown
	}
	result := state.Pending.Result
	if err = cl.verifyControlResult(state.Pending.Intent, *result); err != nil {
		return node.LifecycleResult{}, err
	}
	return node.LifecycleResult{Version: 2, OperationID: result.Payload.Key.OperationID, Grant: result.Payload.Body.Grant}, nil
}

// PersistControlGrant fences local Grant installation against another process
// advancing the durable control journal. The callback may only write local
// files; it must not perform network I/O or call back into this client.
func (cl *Client) PersistControlGrant(ctx context.Context, lease bridge.CredentialLease, save func(trust.Grant) error) (trust.Grant, error) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	unlock, err := bridge.LockPrivateCheckpoint(ctx, filepath.Join(cl.directory, controlJournalName+".lock"))
	if err != nil {
		return trust.Grant{}, err
	}
	defer unlock()
	var state control.ClientJournal
	if err = cl.read(controlJournalName, &state); err != nil {
		return trust.Grant{}, err
	}
	if state.Pending == nil || state.Pending.Result == nil {
		return trust.Grant{}, control.ErrJournalCAS
	}
	result := state.Pending.Result
	if err = cl.verifyControlResult(state.Pending.Intent, *result); err != nil {
		return trust.Grant{}, err
	}
	child := result.Payload.Body.RelayResult
	if child == nil || child.Payload.Body.RelayCredentials == nil || result.Payload.Body.Grant == nil {
		return trust.Grant{}, control.ErrInvalid
	}
	tokens := child.Payload.Body.RelayCredentials
	if string(tokens.CredentialGeneration) != string(lease.CredentialGeneration) || tokens.Access.Token != lease.Enrollment.Access.Token || tokens.Refresh.Token != lease.Enrollment.Refresh.Token {
		return trust.Grant{}, control.ErrJournalCAS
	}
	grant := cloneGrant(*result.Payload.Body.Grant)
	if err = save(grant); err != nil {
		return trust.Grant{}, err
	}
	return grant, nil
}

func (cl *Client) CredentialLeaseInstalled(ctx context.Context, lease bridge.CredentialLease) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	state, err := (clientControlStore{cl}).Load(ctx)
	if err != nil {
		return err
	}
	if state.Pending == nil {
		return nil
	}
	if state.Pending.Intent.Kind == "credential.renew" {
		return nil
	}
	result := state.Pending.Result
	if result == nil || result.Payload.Body.RelayResult == nil {
		return control.ErrInvalid
	}
	if err = cl.verifyControlResult(state.Pending.Intent, *result); err != nil {
		return err
	}
	child := result.Payload.Body.RelayResult
	tokens := child.Payload.Body.RelayCredentials
	if string(tokens.CredentialGeneration) != string(lease.CredentialGeneration) || tokens.Access.Token != lease.Enrollment.Access.Token || tokens.Refresh.Token != lease.Enrollment.Refresh.Token || cl.previous.GrantID != result.Payload.Body.Grant.GrantID {
		return control.ErrInvalid
	}
	coordinator, err := cl.controlCoordinator()
	if err != nil {
		return err
	}
	return coordinator.Installed(ctx, result.ResultDigest)
}
func (cl *Client) commitControlRenewalLocked() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	state, err := (clientControlStore{cl}).Load(ctx)
	if err != nil {
		return err
	}
	if state.Pending == nil {
		return nil
	}
	p := state.Pending
	if p.Result == nil || p.Result.Payload.Body.Grant == nil || p.Result.Payload.Body.Grant.GrantID != cl.previous.GrantID {
		return node.ErrConflict
	}
	// Recovery installation is acknowledged only by the durable provider callback.
	if p.Intent.Kind == "credential.recover" {
		return node.ErrConflict
	}
	coordinator, err := cl.controlCoordinator()
	if err != nil {
		return err
	}
	return coordinator.Installed(ctx, p.Result.ResultDigest)
}
