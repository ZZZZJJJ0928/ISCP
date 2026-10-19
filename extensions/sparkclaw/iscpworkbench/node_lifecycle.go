package iscpworkbench

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeclient"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

type grantLifecycle interface {
	Current(context.Context) (trust.Grant, error)
	Renew(context.Context, trust.Grant) (trust.Grant, error)
	HasPendingRenewal() bool
	CommitRenewal() error
	AcceptGrant(trust.Grant) error
	CheckAuthorization(context.Context) error
	AuthorizationPolicy(context.Context) (iscpauth.Policy, error)
	DeleteAuthorization(context.Context, string, uint64) (iscpauth.DeletionReceipt, error)
	AuthorizationDeletionReceipt(context.Context, string, uint64) (iscpauth.DeletionReceipt, error)
	UsesStandingAuthorization() bool
}

func newNodeLifecycle(cfg Config, m material) (*iscpnodeclient.Client, error) {
	if cfg.Role != RoleInitiator || cfg.IssuerControlFile == "" || cfg.Binding == nil {
		return nil, errors.New("node-managed lifecycle requires its original subject and binding")
	}
	var stored iscpnodeclient.StoredConfig
	if err := readJSONFile(cfg.IssuerControlFile, &stored, true); err != nil {
		return nil, errors.New("load node issuer control identity")
	}
	if stored.Origin != m.enrollment.RelayBaseURL || stored.TLSCertificatePEM != m.enrollment.TLSCertificatePEM || stored.RelayID != m.enrollment.RelayID || stored.Binding.DeploymentID != cfg.Binding.DeploymentID || stored.Binding.OwnerID != cfg.Binding.OwnerID || stored.Binding.ClientID != cfg.Binding.ClientID || stored.Revision != m.grant.RevocationEpoch || stored.IssuerIdentity.DeviceID != m.issuer.DeviceID || stored.IssuerIdentity.PublicKey.Public != m.issuer.PublicKey.Public || stored.RelaySignerIdentity.PublicKey.Public != m.enrollment.RelaySignerIdentity.PublicKey.Public || stored.ResponderIdentity.DeviceID != m.peer.DeviceID || stored.ResponderIdentity.PublicKey.Public != m.peer.PublicKey.Public {
		return nil, errors.New("node lifecycle pins or original binding differ")
	}
	return iscpnodeclient.NewStored(stored, m.device, filepath.Join(cfg.IdentityDirectory, "node-control"), m.grant)
}

func recoverNodeRuntime(ctx context.Context, path string, cfg Config, m material) (Config, error) {
	if cfg.Role == RoleResponder {
		pending := cfg.EnrollmentFile + ".service-recovery.pending"
		updated, err := iscpbridge.RecoverNodeServiceCredentials(ctx, m.enrollment, m.device, pending)
		if err != nil {
			return Config{}, err
		}
		if err = iscpbridge.SaveEnrollment(cfg.EnrollmentFile, updated); err != nil {
			return Config{}, err
		}
		if err = iscpbridge.CommitNodeServiceRecovery(pending); err != nil {
			return Config{}, err
		}
		return LoadConfig(path)
	}
	client, err := newNodeLifecycle(cfg, m)
	if err != nil {
		return Config{}, err
	}
	if client.UsesControlV2() {
		relay, err := iscpbridge.NewRelayCredentialClient(cfg.EffectiveRelayProfile(), cfg.EnrollmentFile, m.enrollment, m.device, 30*time.Second)
		if err != nil {
			return Config{}, err
		}
		endpoint := &Endpoint{config: cfg, material: m, lifecycle: client, relay: relay}
		if err = configureNodeCredentialProvider(endpoint, relay); err != nil {
			return Config{}, err
		}
		provider := relay.CredentialProvider()
		defer provider.Close()
		if _, err = provider.EnsureAccess(ctx, relay.CredentialBinding()); err != nil {
			return Config{}, err
		}
		return LoadConfig(path)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	m, err = reconcileNodePending(ctx, cfg, m, client, nil)
	if err != nil && !errors.Is(err, iscpbridge.ErrGrantRenewalResultExpired) {
		return Config{}, err
	}
	if time.Now().Before(m.enrollment.Access.ExpiresAt) && time.Now().Before(m.enrollment.Refresh.ExpiresAt) && time.Now().Before(m.enrollment.ExpiresAt) && time.Now().Before(m.grant.ExpiresAt) {
		return LoadConfig(path)
	}
	result, err := client.RecoverTransport(ctx)
	if err != nil {
		return Config{}, err
	}
	if result.RelayCredentials == nil {
		return Config{}, errors.New("node recovery lacks sealed transport credentials")
	}
	if _, err = applyNodeLifecycle(ctx, cfg, m, client, result, nil); err != nil {
		return Config{}, err
	}
	return LoadConfig(path)
}
func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// applyNodeLifecycle commits the original signed result before acknowledging its
// durable operation. A lost ACK retains the pending response; replay cannot issue
// another Grant or overwrite a newer revocation.
func applyNodeLifecycle(ctx context.Context, cfg Config, m material, client *iscpnodeclient.Client, result iscpnodeissuer.LifecycleResult, relay *iscpbridge.RelayClient) (material, error) {
	if result.Grant == nil {
		return m, errors.New("node lifecycle result lacks business Grant")
	}
	next := m
	next.grant = *result.Grant
	if err := verifyGrant(cfg, next, time.Now().UTC()); err != nil {
		return m, err
	}
	if err := saveCurrentGrant(cfg.GrantFile, next.grant); err != nil {
		return m, err
	}
	m = next
	if result.RelayCredentials != nil {
		bundle := m.enrollment
		if relay != nil {
			bundle = relay.Enrollment()
		}
		discovery, err := iscpbridge.DiscoverNodeRelay(ctx, bundle)
		if err != nil {
			return m, err
		}
		updated := bundle
		updated.Access = result.RelayCredentials.Access
		updated.Refresh = result.RelayCredentials.Refresh
		updated.IssuedAt = time.Now().UTC()
		updated.ExpiresAt = minTime(discovery.ExpiresAt, updated.Refresh.ExpiresAt)
		if err = updated.ValidateCredentials(time.Now().UTC()); err != nil {
			return m, err
		}
		if relay != nil {
			err = relay.UpdateEnrollment(func(b *iscpbridge.EnrollmentBundle) { *b = updated })
		} else {
			err = iscpbridge.SaveEnrollment(cfg.EnrollmentFile, updated)
		}
		if err != nil {
			return m, err
		}
		m.enrollment = updated
	}
	if err := client.AcceptGrant(m.grant); err != nil {
		return m, err
	}
	return m, client.CommitRenewal()
}
func reconcileNodePending(ctx context.Context, cfg Config, m material, client *iscpnodeclient.Client, relay *iscpbridge.RelayClient) (material, error) {
	kind, err := client.PendingLifecycleKind()
	if err != nil {
		return m, err
	}
	if kind == "" {
		return m, nil
	}
	if kind != "renew" && kind != "recover" {
		return m, errors.New("unknown pending node lifecycle kind")
	}
	result, err := client.ResolvePendingLifecycle(ctx)
	if err != nil {
		return m, err
	}
	return applyNodeLifecycle(ctx, cfg, m, client, result, relay)
}

// recoverLiveNodeTransport is serialized with Grant renewal. Transport expiry
// during a long outage reuses the original device/standing authorization and
// TEST1 control path, without consuming an invitation or retrying business work.
func (e *Endpoint) recoverLiveNodeTransport(ctx context.Context) error {
	client, ok := e.lifecycle.(*iscpnodeclient.Client)
	if !ok {
		return nil
	}
	relay, ok := e.relay.(*iscpbridge.RelayClient)
	if !ok {
		return nil
	}
	if client.UsesControlV2() {
		if provider := relay.CredentialProvider(); provider != nil {
			_, err := provider.EnsureAccess(ctx, relay.CredentialBinding())
			return err
		}
		return control.ErrUnknown
	}
	bundle := relay.Enrollment()
	if time.Now().Before(bundle.Refresh.ExpiresAt) && time.Now().Before(bundle.ExpiresAt) {
		return nil
	}
	e.renewalMu.Lock()
	defer e.renewalMu.Unlock()
	m, err := reconcileNodePending(ctx, e.config, e.grantMaterial(), client, relay)
	if err != nil && !errors.Is(err, iscpbridge.ErrGrantRenewalResultExpired) {
		return err
	}
	bundle = relay.Enrollment()
	if !time.Now().Before(bundle.Refresh.ExpiresAt) || !time.Now().Before(bundle.ExpiresAt) {
		result, recoveryErr := client.RecoverTransport(ctx)
		if recoveryErr != nil {
			return recoveryErr
		}
		m, err = applyNodeLifecycle(ctx, e.config, m, client, result, relay)
	}
	e.grantMu.Lock()
	e.material.grant = m.grant
	e.grantMu.Unlock()
	e.observeAuthorizationError(err)
	return err
}

// RecoverNodeEnrollment completes a previously signed historical enrollment
// before activation. It uses the same durable lifecycle coordinator as runtime
// recovery; the original signed EnrollmentResult is never rewritten or relabeled.
func RecoverNodeEnrollment(ctx context.Context, path string) (Config, error) {
	cfg, err := LoadControlConfig(path)
	if err != nil {
		return Config{}, err
	}
	if cfg.Mode != "node-managed" || cfg.Role != RoleInitiator {
		return Config{}, errors.New("node enrollment recovery requires its original initiator")
	}
	m, err := loadMaterialMode(cfg, true)
	if err != nil {
		return Config{}, err
	}
	return recoverNodeRuntime(ctx, path, cfg, m)
}

// configureNodeCredentialProvider connects the shared lease interface directly
// to the independent HTTPS coordinator. No socket is needed to recover.
func configureNodeCredentialProvider(e *Endpoint, relay *iscpbridge.RelayClient) error {
	client, ok := e.lifecycle.(*iscpnodeclient.Client)
	if !ok || !client.UsesControlV2() {
		return nil
	}
	stored := client.StoredConfig()
	binding := iscpbridge.CredentialBinding{DomainID: e.material.device.Identity.DomainID, DeviceID: e.material.device.Identity.DeviceID, ResourceBindingID: stored.Binding.ClientID, TargetServiceID: stored.RelayID, IssuerPublicKey: stored.IssuerIdentity.PublicKey.Public, RelayPublicKey: stored.RelaySignerIdentity.PublicKey.Public, TLSCertificateSHA256: c.Base64URL(c.SHA256([]byte(stored.TLSCertificatePEM)))}
	return relay.ConfigureCredentialProviderWithInstallation(binding, func(ctx context.Context, b iscpbridge.CredentialBinding, g iscpbridge.CredentialGeneration) (iscpbridge.CredentialLease, error) {
		e.renewalMu.Lock()
		defer e.renewalMu.Unlock()
		if kind, err := client.PendingLifecycleKind(); err != nil {
			return iscpbridge.CredentialLease{}, err
		} else if kind == "renew" {
			pending, err := client.ResolvePendingLifecycle(ctx)
			if err != nil {
				return iscpbridge.CredentialLease{}, err
			}
			if pending.Grant == nil {
				return iscpbridge.CredentialLease{}, control.ErrUnknown
			}
			if err = saveCurrentGrant(e.config.GrantFile, *pending.Grant); err != nil {
				return iscpbridge.CredentialLease{}, err
			}
			if err = client.AcceptGrant(*pending.Grant); err != nil {
				return iscpbridge.CredentialLease{}, err
			}
			if err = client.CommitRenewal(); err != nil {
				return iscpbridge.CredentialLease{}, err
			}
			e.grantMu.Lock()
			e.material.grant = *pending.Grant
			e.grantMu.Unlock()
		}
		lease, err := client.RecoverCredentialLease(ctx, b, g, relay.Enrollment())
		if err != nil {
			return iscpbridge.CredentialLease{}, err
		}
		pending, err := client.PendingControlGrant(ctx)
		if err != nil || pending.Grant == nil {
			return iscpbridge.CredentialLease{}, control.ErrUnknown
		}
		next := e.grantMaterial()
		next.grant = *pending.Grant
		if err = verifyGrant(e.config, next, time.Now().UTC()); err != nil {
			return iscpbridge.CredentialLease{}, err
		}
		if err = saveCurrentGrant(e.config.GrantFile, next.grant); err != nil {
			return iscpbridge.CredentialLease{}, err
		}
		if err = client.AcceptGrant(next.grant); err != nil {
			return iscpbridge.CredentialLease{}, err
		}
		e.grantMu.Lock()
		e.material.grant = next.grant
		e.grantMu.Unlock()
		return lease, nil
	}, client.CredentialLeaseInstalled)
}
