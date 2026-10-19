package iscpbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"os"
	"path/filepath"
	"time"
)

type serviceControlStore struct {
	path string
	key  []byte
}

func (s serviceControlStore) load() (control.ClientJournal, error) {
	var state control.ClientJournal
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return state, control.ErrInvalid
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return state, err
	}
	blob, err := base64.RawURLEncoding.Strict().DecodeString(string(raw))
	if err != nil || len(blob) < 28 {
		return state, control.ErrInvalid
	}
	plain, err := c.NewProvider().Open(s.key, blob[:12], blob[12:], []byte(s.path))
	if err != nil {
		return state, err
	}
	err = json.Unmarshal(plain, &state)
	return state, err
}
func (s serviceControlStore) Load(ctx context.Context) (control.ClientJournal, error) {
	unlock, err := lockCredentialFile(ctx, s.path+".lock")
	if err != nil {
		return control.ClientJournal{}, err
	}
	defer unlock()
	return s.load()
}
func (s serviceControlStore) CompareAndSwap(ctx context.Context, expected uint64, next control.ClientJournal) error {
	unlock, err := lockCredentialFile(ctx, s.path+".lock")
	if err != nil {
		return err
	}
	defer unlock()
	old, err := s.load()
	if err != nil {
		return err
	}
	if old.Version != expected || next.Version != expected+1 {
		return control.ErrJournalCAS
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	nonce := c.RandomBytes(12)
	cipher, err := c.NewProvider().Seal(s.key, nonce, raw, []byte(s.path))
	if err != nil {
		return err
	}
	if err = writeSecretFile(s.path, []byte(c.Base64URL(append(nonce, cipher...)))); err != nil {
		return err
	}
	return syncCredentialDirectory(filepath.Dir(s.path))
}

// ConfigureServiceCredentialProvider uses the pre-enrolled service's current
// durable ownership, never an invitation or WSS forwarder. Authority snapshots
// are authenticated service-only reads and do not themselves grant permission.
func (r *RelayClient) ConfigureServiceCredentialProvider(issuer identity.DeviceIdentity) error {
	bundle := r.Enrollment()
	if bundle.Mode != BundleModeWorkbenchNodeManaged || bundle.RelaySignerIdentity == nil {
		return control.ErrInvalid
	}
	key, err := c.NewProvider().HKDF(r.device.Private.BytesForDevStore(), nil, []byte("iscp/service-control-journal/v2\x00"+r.device.Identity.PublicKey.KID), 32)
	if err != nil {
		return err
	}
	store := serviceControlStore{path: r.enrollmentPath + ".service.operations.v2", key: key}
	transport, err := control.NewClient(bundle.RelayBaseURL, bundle.RelayID, r.device, *bundle.RelaySignerIdentity, r.client)
	if err != nil {
		return err
	}
	binding := CredentialBinding{DomainID: r.device.Identity.DomainID, DeviceID: r.device.Identity.DeviceID, ResourceBindingID: r.device.Identity.DeviceID, TargetServiceID: bundle.RelayID, IssuerPublicKey: issuer.PublicKey.Public, RelayPublicKey: bundle.RelaySignerIdentity.PublicKey.Public, TLSCertificateSHA256: c.Base64URL(c.SHA256([]byte(bundle.TLSCertificatePEM)))}
	subject := control.Subject{DomainID: binding.DomainID, DeviceID: binding.DeviceID, BindingID: binding.ResourceBindingID}
	target := control.Target{ServiceID: binding.TargetServiceID, ResourceID: binding.ResourceBindingID}
	verify := func(intent control.Intent, result control.Result) error {
		if result.Payload.State == "failed" && result.Payload.Body.Code == "generation_conflict" && result.Payload.Body.RelayCredentials == nil {
			return nil
		}
		tokens := result.Payload.Body.RelayCredentials
		if result.Payload.State != "succeeded" || tokens == nil || result.Payload.Key.DeviceID != binding.DeviceID || tokens.TargetServiceID != target.ServiceID || tokens.BindingID != subject.BindingID || tokens.CredentialGeneration != result.Payload.CredentialGeneration || tokens.AuthorizationRevision != intent.TaskAuthorization.AuthorizationRevision {
			return control.ErrAuthentication
		}
		for _, token := range []control.Credential{tokens.Access, tokens.Refresh} {
			if token.DomainID != subject.DomainID || token.DeviceID != subject.DeviceID || token.Token == "" {
				return control.ErrAuthentication
			}
		}
		return nil
	}
	coordinator := func(ctx context.Context) (*control.Coordinator, error) {
		state, err := store.Load(ctx)
		if err != nil {
			return nil, err
		}
		var revision, resource control.Counter
		var scopes []string
		if state.Pending != nil {
			revision = state.Pending.Intent.TaskAuthorization.AuthorizationRevision
			resource = state.Pending.Intent.Preconditions.ResourceVersion
			scopes = state.Pending.Intent.Payload.RequestedScopes
		} else {
			// Obtain a fresh operation-correlated authority response first. A
			// revoked service gets the signed typed terminal error here; an
			// unsigned snapshot HTTP failure must never be interpreted as revoke.
			probe := control.Request{Action: "lookup", Key: control.Key{DomainID: subject.DomainID, DeviceID: subject.DeviceID, Namespace: control.RelayNamespace, OperationID: "authority-" + control.RandomID()}, SemanticDigest: control.RandomID()}
			status, err := transport.Attempt(ctx, probe, "")
			if err != nil {
				return nil, err
			}
			if status.Status == nil || status.Status.State != "absent" || !status.Status.HistoryComplete {
				return nil, control.ErrUnknown
			}
			snapshot, err := transport.Authority(ctx, subject, target)
			if err != nil {
				return nil, err
			}
			revision = snapshot.AuthorizationRevision
			resource = snapshot.ResourceVersion
			scopes = snapshot.Scopes
		}
		return &control.Coordinator{Client: transport, Store: store, Namespace: control.RelayNamespace, Subject: subject, Target: target, Revision: revision, ResourceVersion: resource, Scopes: scopes, VerifyResult: verify}, nil
	}
	return r.ConfigureCredentialProviderWithInstallation(binding, func(ctx context.Context, _ CredentialBinding, _ CredentialGeneration) (CredentialLease, error) {
		op, err := coordinator(ctx)
		if err != nil {
			return CredentialLease{}, err
		}
		result, err := op.Result(ctx, "relay.recover")
		if err != nil {
			return CredentialLease{}, err
		}
		tokens := result.Payload.Body.RelayCredentials
		next := r.Enrollment()
		next.Access = RelayCredential{DomainID: tokens.Access.DomainID, DeviceID: tokens.Access.DeviceID, Token: tokens.Access.Token, ExpiresAt: tokens.Access.ExpiresAt}
		next.Refresh = RelayCredential{DomainID: tokens.Refresh.DomainID, DeviceID: tokens.Refresh.DeviceID, Token: tokens.Refresh.Token, ExpiresAt: tokens.Refresh.ExpiresAt}
		next.IssuedAt = result.Payload.CompletedAt
		next.ExpiresAt = next.Refresh.ExpiresAt
		return CredentialLease{Binding: binding, Enrollment: next, CredentialGeneration: CredentialGeneration(tokens.CredentialGeneration), AuthorizationRevision: string(tokens.AuthorizationRevision), ExpiresAt: result.UsableUntil()}, nil
	}, func(ctx context.Context, lease CredentialLease) error {
		state, err := store.Load(ctx)
		if err != nil {
			return err
		}
		if state.Pending == nil {
			return nil
		}
		p := state.Pending
		if p.Result == nil || p.Result.Payload.Body.RelayCredentials == nil {
			return control.ErrUnknown
		}
		tokens := p.Result.Payload.Body.RelayCredentials
		if string(tokens.CredentialGeneration) != string(lease.CredentialGeneration) || tokens.Access.Token != lease.Enrollment.Access.Token || tokens.Refresh.Token != lease.Enrollment.Refresh.Token {
			return control.ErrJournalCAS
		}
		op, err := coordinator(ctx)
		if err != nil {
			return err
		}
		return op.Installed(ctx, p.Result.ResultDigest)
	})
}
func RecoverNodeServiceRuntime(ctx context.Context, path string, bundle EnrollmentBundle, device identity.Device, issuer identity.DeviceIdentity) (EnrollmentBundle, error) {
	relay, err := NewRelayCredentialClient(ProfileProduction, path, bundle, device, 30*time.Second)
	if err != nil {
		return EnrollmentBundle{}, err
	}
	if err = relay.ConfigureServiceCredentialProvider(issuer); err != nil {
		return EnrollmentBundle{}, err
	}
	defer relay.CredentialProvider().Close()
	lease, err := relay.CredentialProvider().EnsureAccess(ctx, relay.CredentialBinding())
	return lease.Enrollment, err
}
