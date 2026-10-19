package iscpworkbench

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

type Binding struct {
	DeploymentID string `json:"deployment_id"`
	OwnerID      string `json:"owner_id"`
	ClientID     string `json:"client_id"`
}

type Config struct {
	ExpectedInstallationID string              `json:"expected_installation_id,omitempty"`
	ApplicationProfiles    []string            `json:"application_profiles,omitempty"`
	QualifiedCapabilities  []string            `json:"qualified_capabilities,omitempty"`
	SchemaVersion          int                 `json:"schema_version"`
	Mode                   string              `json:"mode"`
	Role                   string              `json:"role"`
	RelayProfile           string              `json:"relay_profile,omitempty"`
	IdentityDirectory      string              `json:"identity_directory"`
	IdentityKeyBackend     string              `json:"identity_key_backend"`
	IdentityKeyringService string              `json:"identity_keyring_service,omitempty"`
	EnrollmentFile         string              `json:"enrollment_file"`
	PeerIdentityFile       string              `json:"peer_identity_file"`
	IssuerIdentityFile     string              `json:"issuer_identity_file"`
	InvitationIdentityFile string              `json:"invitation_identity_file,omitempty"`
	NodeIssuerSocket       string              `json:"node_issuer_socket,omitempty"`
	NodeIssuerTokenFile    string              `json:"node_issuer_token_file,omitempty"`
	PeerRegistryFile       string              `json:"peer_registry_file,omitempty"`
	IssuerControlFile      string              `json:"issuer_control_file,omitempty"`
	GrantFile              string              `json:"grant_file"`
	Permission             string              `json:"permission,omitempty"`
	Binding                *Binding            `json:"binding,omitempty"`
	GrantRenewal           *GrantRenewalConfig `json:"grant_renewal,omitempty"`
}

// GrantRenewalConfig points to the separately pinned local issuer. Relay
// credentials and the issuer's management credential are never used here.
type GrantRenewalConfig struct {
	URL                   string `json:"url"`
	AuthorizationLifetime string `json:"authorization_lifetime,omitempty"`
	PendingFile           string `json:"pending_file"`
	PollIntervalSeconds   int    `json:"poll_interval_seconds,omitempty"`
}

// PublicIdentity is derived from the validated enrollment and pinned peer,
// allowing Electron to bind its public connection descriptor to this helper.
// It contains no access tokens, grants or signing keys.
type PublicIdentity struct {
	DomainID               string `json:"domain_id"`
	InitiatorDeviceID      string `json:"initiator_device_id"`
	ResponderDeviceID      string `json:"responder_device_id"`
	ResponderKeyThumbprint string `json:"responder_key_thumbprint"`
	RelayURL               string `json:"relay_url"`
	RelayProfile           string `json:"relay_profile"`
}

func (c Config) PublicIdentity() (PublicIdentity, error) {
	m, err := loadMaterial(c)
	if err != nil {
		return PublicIdentity{}, err
	}
	initiator, responder := m.device.Identity, m.peer
	if c.Role == RoleResponder {
		initiator, responder = m.peer, m.device.Identity
	}
	return PublicIdentity{DomainID: m.enrollment.DomainID, InitiatorDeviceID: initiator.DeviceID, ResponderDeviceID: responder.DeviceID, ResponderKeyThumbprint: responder.PublicKey.KID, RelayURL: m.enrollment.RelayBaseURL, RelayProfile: c.EffectiveRelayProfile()}, nil
}

func (c Config) EffectiveRelayProfile() string {
	if c.RelayProfile == "" {
		return iscpbridge.ProfileProduction
	}
	return c.RelayProfile
}

func LoadConfig(path string) (Config, error) { return loadConfig(path, false) }

// LoadControlConfig validates pinned identity and historical Grant continuity
// without requiring live Relay credentials for deletion receipt recovery.
func LoadControlConfig(path string) (Config, error) { return loadConfig(path, true) }
func loadConfig(path string, controlOnly bool) (Config, error) {
	var cfg Config
	if err := readJSONFile(path, &cfg, true); err != nil {
		return cfg, fmt.Errorf("load workbench configuration: %w", err)
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return cfg, errors.New("resolve workbench configuration directory")
	}
	paths := []*string{&cfg.IdentityDirectory, &cfg.EnrollmentFile, &cfg.PeerIdentityFile, &cfg.IssuerIdentityFile, &cfg.GrantFile, &cfg.InvitationIdentityFile, &cfg.PeerRegistryFile, &cfg.IssuerControlFile, &cfg.NodeIssuerSocket, &cfg.NodeIssuerTokenFile}
	for _, field := range paths {
		if *field != "" && !filepath.IsAbs(*field) {
			*field = filepath.Join(base, *field)
		}
	}
	if cfg.GrantRenewal != nil && !filepath.IsAbs(cfg.GrantRenewal.PendingFile) {
		cfg.GrantRenewal.PendingFile = filepath.Join(base, cfg.GrantRenewal.PendingFile)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	if _, err := loadMaterialMode(cfg, controlOnly); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if len(c.ApplicationProfiles) > 2 {
		return errors.New("too many application profiles")
	}
	seen := map[string]bool{}
	for _, p := range c.ApplicationProfiles {
		if (p != Profile && p != ProfileV2) || seen[p] {
			return errors.New("invalid application profile")
		}
		seen[p] = true
	}
	if c.supportsV2() && !seen[Profile] {
		return errors.New("v2 requires the v1 negotiation carrier")
	}
	for _, name := range c.QualifiedCapabilities {
		if _, ok := LookupOperation(name); !ok {
			return errors.New("unknown qualified operation")
		}
	}

	nodeManaged := c.SchemaVersion == 2 && c.Mode == "node-managed"
	if !nodeManaged && (c.SchemaVersion != 1 || c.Mode != "local-test") {
		return errors.New("workbench requires explicit schema 1 local-test configuration")
	}
	if c.Role != RoleInitiator && c.Role != RoleResponder {
		return errors.New("workbench role must be initiator or responder")
	}
	if c.EffectiveRelayProfile() != iscpbridge.ProfileProduction && c.EffectiveRelayProfile() != iscpbridge.ProfileLocalLab {
		return errors.New("unsupported workbench Relay profile")
	}
	if c.IdentityKeyBackend != iscpbridge.IdentityKeyBackendFile && c.IdentityKeyBackend != iscpbridge.IdentityKeyBackendKeyring {
		return errors.New("workbench identity key backend must be file or keyring")
	}
	paths := []string{c.IdentityDirectory, c.EnrollmentFile, c.IssuerIdentityFile}
	if nodeManaged && c.Role == RoleResponder {
		paths = append(paths, c.InvitationIdentityFile, c.PeerRegistryFile)
	} else {
		paths = append(paths, c.PeerIdentityFile, c.GrantFile)
	}
	if nodeManaged {
		if c.EffectiveRelayProfile() != iscpbridge.ProfileProduction || c.Binding == nil && c.Role == RoleInitiator || c.GrantRenewal != nil {
			return errors.New("node-managed runtime requires production trust and node lifecycle")
		}
		paths = append(paths, c.InvitationIdentityFile)
		if c.Role == RoleInitiator {
			paths = append(paths, c.IssuerControlFile)
			if !uuidPattern.MatchString(c.ExpectedInstallationID) {
				return errors.New("node-managed initiator requires its original installation UUID")
			}
		}
	}
	for _, path := range paths {
		if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
			return errors.New("workbench identity and authorization paths must be absolute")
		}
	}
	if c.NodeIssuerSocket != "" && (!nodeManaged || c.Role != RoleResponder || !filepath.IsAbs(c.NodeIssuerSocket)) {
		return errors.New("node issuer socket requires node-managed responder and an absolute Unix path")
	}
	if c.NodeIssuerTokenFile != "" && (c.NodeIssuerSocket == "" || !nodeManaged || c.Role != RoleResponder || !filepath.IsAbs(c.NodeIssuerTokenFile)) {
		return errors.New("node issuer management token requires a node-managed responder and absolute private paths")
	}
	if c.Permission != "" && c.Permission != Permission {
		return errors.New("unsupported workbench permission")
	}
	if c.GrantRenewal != nil {
		if c.GrantRenewal.AuthorizationLifetime != "" && c.GrantRenewal.AuthorizationLifetime != iscpauth.UntilRevoked {
			return errors.New("unsupported Grant authorization lifetime")
		}
		if err := iscpbridge.ValidateGrantLifecycleURL(c.GrantRenewal.URL); err != nil {
			return err
		}
		if c.GrantRenewal.PendingFile == "" || !filepath.IsAbs(c.GrantRenewal.PendingFile) || c.GrantRenewal.PendingFile == c.GrantFile || c.GrantRenewal.PendingFile == c.EnrollmentFile {
			return errors.New("grant renewal requires an independent absolute private pending file")
		}
		if c.GrantRenewal.PollIntervalSeconds < 0 || c.GrantRenewal.PollIntervalSeconds > 300 {
			return errors.New("grant renewal polling interval must be between 1 and 300 seconds")
		}
	}
	if c.Binding != nil {
		for _, id := range []string{c.Binding.DeploymentID, c.Binding.OwnerID, c.Binding.ClientID} {
			if strings.TrimSpace(id) == "" || len(id) > 200 {
				return errors.New("workbench binding must identify deployment, owner and client")
			}
		}
	}
	return nil
}

type material struct {
	device     identity.Device
	enrollment iscpbridge.EnrollmentBundle
	peer       identity.DeviceIdentity
	issuer     identity.DeviceIdentity
	grant      trust.Grant
}

func loadMaterial(cfg Config) (material, error) { return loadMaterialMode(cfg, false) }
func loadMaterialMode(cfg Config, controlOnly bool) (material, error) {
	var m material
	if err := cfg.Validate(); err != nil {
		return m, err
	}
	info, err := os.Stat(cfg.IdentityDirectory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return m, errors.New("workbench identity directory must be private (0700)")
	}
	var boundedIdentity identity.DeviceIdentity
	if err := readJSONFile(filepath.Join(cfg.IdentityDirectory, iscpbridge.IdentityFileName), &boundedIdentity, false); err != nil {
		return m, errors.New("workbench device identity must be a bounded regular file")
	}
	if cfg.IdentityKeyBackend == iscpbridge.IdentityKeyBackendFile {
		info, err := os.Lstat(filepath.Join(cfg.IdentityDirectory, iscpbridge.IdentityKeyFileName))
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 || info.Mode().Perm()&0o077 != 0 {
			return m, errors.New("workbench private identity key file is invalid")
		}
	}
	m.device, err = iscpbridge.LoadDeviceWithKeyBackend(filepath.Join(cfg.IdentityDirectory, iscpbridge.IdentityFileName), filepath.Join(cfg.IdentityDirectory, iscpbridge.IdentityKeyFileName), cfg.IdentityKeyBackend, cfg.IdentityKeyringService)
	if err != nil {
		return m, errors.New("load workbench device identity")
	}
	if err := readJSONFile(cfg.EnrollmentFile, &m.enrollment, true); err != nil {
		return m, errors.New("load workbench Relay enrollment")
	}
	if cfg.SchemaVersion == 2 && cfg.Role == RoleResponder && cfg.PeerIdentityFile == "" {
		return loadResponderMaterial(cfg, m, controlOnly)
	}
	if err := readJSONFile(cfg.PeerIdentityFile, &m.peer, false); err != nil {
		return m, errors.New("load pinned workbench peer")
	}
	if err := readJSONFile(cfg.IssuerIdentityFile, &m.issuer, false); err != nil {
		return m, errors.New("load pinned local grant issuer")
	}
	if err := readJSONFile(cfg.GrantFile, &m.grant, true); err != nil {
		return m, errors.New("load local workbench grant")
	}
	if !controlOnly {
		if err := validateEnrollment(m.enrollment, m.device.Identity, cfg.EffectiveRelayProfile(), time.Now().UTC()); err != nil {
			return m, err
		}
	} else if (cfg.GrantRenewal == nil && cfg.Mode != "node-managed") || m.enrollment.Type != iscpbridge.EnrollmentBundleType || m.enrollment.DomainID != m.device.Identity.DomainID || m.enrollment.DeviceID != m.device.Identity.DeviceID || m.enrollment.RelayID == "" {
		return m, errors.New("invalid authorization control enrollment binding")
	}
	if m.peer.DomainID != m.device.Identity.DomainID || m.peer.DeviceID == m.device.Identity.DeviceID || m.peer.DeviceID == "" {
		return m, errors.New("workbench peer identity binding is invalid")
	}
	for _, id := range []identity.DeviceIdentity{m.device.Identity, m.peer, m.issuer} {
		if id.Type != identity.TypeDeviceIdentity || id.DomainID == "" || id.DeviceID == "" || id.PublicKey.KTY != "Ed25519" || id.PublicKey.Use != "identity-signature" || id.PublicKey.KID == "" {
			return m, errors.New("workbench pinned identity key is invalid")
		}
		pub, err := iscpcrypto.DecodeBase64URL(id.PublicKey.Public)
		if err != nil || len(pub) != 32 || id.PublicKey.KID != iscpcrypto.Thumbprint("Ed25519", pub) {
			return m, errors.New("workbench pinned public key is invalid")
		}
	}
	// Cloud root key IDs are operator names (for example cloud-trust-prod-1),
	// unlike enrolled device IDs. Pin their exact KID and public bytes without
	// substituting a device thumbprint convention for the cloud key namespace.
	if cfg.Mode == "node-managed" {
		if err := validateNodeAuthorities(cfg, m); err != nil {
			return m, err
		}
	} else if cfg.EffectiveRelayProfile() == iscpbridge.ProfileLocalLab {
		if m.enrollment.RelaySignerIdentity == nil {
			return m, errors.New("missing pinned local Relay signer")
		}
		if err := iscpbridge.ValidateLocalRelaySigner(*m.enrollment.RelaySignerIdentity); err != nil {
			return m, err
		}
		if m.issuer.PublicKey.Public == m.enrollment.RelaySignerIdentity.PublicKey.Public {
			return m, errors.New("local session issuer must be separate from the Relay signer")
		}
	} else {
		cloud := m.enrollment.TrustRootIdentity
		cloudPublic, err := iscpcrypto.DecodeBase64URL(cloud.PublicKey.Public)
		if cloud.Type != identity.TypeDeviceIdentity || cloud.DomainID == "" || cloud.DeviceID == "" || cloud.PublicKey.KTY != "Ed25519" || cloud.PublicKey.KID == "" || len(cloud.PublicKey.KID) > 200 || err != nil || len(cloudPublic) != 32 {
			return m, errors.New("pinned cloud Trust Root key is invalid")
		}
		if m.issuer.PublicKey.Public == m.enrollment.TrustRootIdentity.PublicKey.Public {
			return m, errors.New("local test grant issuer must be separate from the cloud Trust Root")
		}
	}
	verificationTime := time.Now().UTC()
	if (cfg.GrantRenewal != nil || cfg.Mode == "node-managed") && !verificationTime.Before(m.grant.ExpiresAt) {
		// A signed expired seed can recover through the explicitly configured
		// lifecycle. Runtime admission still verifies against the actual time.
		verificationTime = m.grant.ExpiresAt.Add(-time.Nanosecond)
	}
	if err := verifyGrant(cfg, m, verificationTime); err != nil {
		return m, err
	}
	if cfg.Mode == "node-managed" && cfg.Role == RoleInitiator {
		if _, err := newNodeLifecycle(cfg, m); err != nil {
			return m, err
		}
	}
	return m, nil
}

func validateEnrollment(b iscpbridge.EnrollmentBundle, local identity.DeviceIdentity, profile string, now time.Time) error {
	if b.Type != iscpbridge.EnrollmentBundleType || b.DomainID != local.DomainID || b.DeviceID != local.DeviceID || b.RelayID == "" {
		return errors.New("workbench enrollment does not match device")
	}
	if err := b.ValidateCredentials(now); err != nil {
		return err
	}
	if profile == iscpbridge.ProfileLocalLab {
		if b.Mode != iscpbridge.BundleModeWorkbenchLocalLab {
			return errors.New("local-lab workbench requires local reference enrollment")
		}
	} else if b.Mode == iscpbridge.BundleModeWorkbenchLocalLab {
		return errors.New("production workbench rejects local reference enrollment")
	}
	if b.Mode == iscpbridge.BundleModeWorkbenchNodeManaged && profile != iscpbridge.ProfileProduction {
		return errors.New("node-managed enrollment requires production Relay")
	}
	if b.IssuedAt.IsZero() || !b.IssuedAt.Before(b.ExpiresAt) || !now.Before(b.ExpiresAt) {
		return errors.New("workbench enrollment is incomplete or expired")
	}
	for _, credential := range []iscpbridge.RelayCredential{b.Access, b.Refresh} {
		if credential.DomainID != b.DomainID || credential.DeviceID != b.DeviceID || strings.TrimSpace(credential.Token) == "" || credential.ExpiresAt.IsZero() {
			return errors.New("workbench Relay credential binding is invalid")
		}
	}
	if !now.Before(b.Refresh.ExpiresAt) {
		return errors.New("workbench Relay refresh credential expired")
	}
	return iscpbridge.ValidateWorkbenchRelayURLs(profile, b.RelayBaseURL, b.RelayWebSocketURL)
}

func verifyGrant(cfg Config, m material, now time.Time) error {
	subject, audience := m.device.Identity, m.peer
	if cfg.Role == RoleResponder {
		subject, audience = m.peer, m.device.Identity
	}
	thumbprint, err := identity.Thumbprint(subject)
	if err != nil {
		return errors.New("workbench subject thumbprint is invalid")
	}
	g := m.grant
	if g.GrantID == "" || g.Issuer != m.issuer.DeviceID || g.Signature.Alg != "Ed25519" || g.Signature.KID != m.issuer.PublicKey.KID || !g.NotBefore.Before(g.ExpiresAt) || len(g.Permissions) != 1 || g.Permissions[0] != Permission || len(g.RelayConstraints) != 1 || g.RelayConstraints[0] != m.enrollment.RelayID {
		return errors.New("local workbench grant issuer, permission or Relay binding is invalid")
	}
	if err := trust.VerifyGrant(iscpcrypto.NewProvider(), g, m.issuer, trust.VerifyOptions{Audience: audience.DeviceID, SubjectDeviceID: subject.DeviceID, ConfirmationThumbprint: thumbprint, Permission: Permission, RelayID: m.enrollment.RelayID, Now: now}); err != nil {
		return errors.New("local workbench grant verification failed")
	}
	return nil
}

func readJSONFile(path string, value any, private bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("configuration file is unavailable")
	}
	if !info.Mode().IsRegular() || info.Size() > 512<<10 || (private && info.Mode().Perm()&0o077 != 0) {
		return errors.New("configuration file must be a bounded regular file with private permissions")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return errors.New("read configuration file")
	}
	if err := strictDecode(raw, value); err != nil {
		return errors.New("decode configuration file")
	}
	return nil
}
