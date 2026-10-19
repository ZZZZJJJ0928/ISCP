package iscpbridge

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	keyring "github.com/zalando/go-keyring"
)

const (
	EnrollmentRequestType = "sparkclaw.bridge.enrollment_request.v1"
	EnrollmentBundleType  = "sparkclaw.bridge.enrollment.v1"
	IdentityFileName      = "device.identity.json"
	IdentityKeyFileName   = "device.identity.key"

	IdentityKeyBackendKeyring     = "keyring"
	IdentityKeyBackendFile        = "file"
	DefaultIdentityKeyringService = "SparkClaw ISCP Bridge"
)

type EnrollmentRequest struct {
	Type             string                  `json:"type"`
	DeviceType       string                  `json:"device_type"`
	DeviceRole       string                  `json:"device_role"`
	ProductKind      string                  `json:"product_kind"`
	RuntimeKind      string                  `json:"runtime_kind"`
	HardwareClass    string                  `json:"hardware_class"`
	ProtocolVersions []string                `json:"protocol_versions"`
	Identity         identity.DeviceIdentity `json:"identity"`
	DeviceProof      *identity.DeviceProof   `json:"device_proof,omitempty"`
	CreatedAt        time.Time               `json:"created_at"`
}

type EnrollmentProofOptions struct {
	Audience  string
	Challenge string
	Nonce     string
}

type RelayCredential struct {
	DomainID  string    `json:"domain_id"`
	DeviceID  string    `json:"device_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type PeerAuthorization struct {
	Identity                identity.DeviceIdentity `json:"identity"`
	InboundGrant            trust.Grant             `json:"inbound_grant"`
	OutboundGrant           trust.Grant             `json:"outbound_grant"`
	InboundRevocationEpoch  uint64                  `json:"inbound_revocation_epoch"`
	OutboundRevocationEpoch uint64                  `json:"outbound_revocation_epoch"`
}

// BundleModeManaged marks a bundle produced by Cloud managed provisioning
// (ISCP v0.2 pairing ticket v3): the Bridge holds the single outbound Trust
// Grant (subject = bridge, audience = phone) and the phone peer is a
// responder without a grant of its own. The empty mode is the legacy
// externally-issued dual-grant contract.
const BundleModeManaged = "managed"

// BundleModeWorkbenchLocalLab represents real credentials issued by the
// isolated reference Relay. Its public signer is separate from session grants.
const BundleModeWorkbenchLocalLab = "workbench-local-lab"

// BundleModeWorkbenchNodeManaged uses explicitly pinned self-hosted authorities.
// It does not reuse Cloud enrollment or local-test trust semantics.
const BundleModeWorkbenchNodeManaged = "workbench-node-managed"

type EnrollmentBundle struct {
	TLSCertificatePEM        string                   `json:"tls_certificate_pem,omitempty"`
	InvitationSignerIdentity *identity.DeviceIdentity `json:"invitation_signer_identity,omitempty"`
	Type                     string                   `json:"type"`
	Mode                     string                   `json:"mode,omitempty"`
	DomainID                 string                   `json:"domain_id"`
	DeviceID                 string                   `json:"device_id"`
	RelayID                  string                   `json:"relay_id"`
	RelayBaseURL             string                   `json:"relay_base_url"`
	RelayWebSocketURL        string                   `json:"relay_websocket_url"`
	TrustRootIdentity        identity.DeviceIdentity  `json:"trust_root_identity"`
	RelaySignerIdentity      *identity.DeviceIdentity `json:"relay_signer_identity,omitempty"`
	Access                   RelayCredential          `json:"access"`
	Refresh                  RelayCredential          `json:"refresh"`
	Peers                    []PeerAuthorization      `json:"peers"`
	IssuedAt                 time.Time                `json:"issued_at"`
	ExpiresAt                time.Time                `json:"expires_at"`
}

type DeviceFiles struct {
	Directory    string
	IdentityFile string
	KeyFile      string
}

func GenerateEnrollmentRequestWithKeyBackend(directory, domainID, deviceID, hardwareClass, keyBackend, keyringService string, now time.Time) (EnrollmentRequest, DeviceFiles, error) {
	return GenerateEnrollmentRequestWithProof(directory, domainID, deviceID, hardwareClass, keyBackend, keyringService, EnrollmentProofOptions{}, now)
}

func GenerateEnrollmentRequestWithProof(directory, domainID, deviceID, hardwareClass, keyBackend, keyringService string, proofOptions EnrollmentProofOptions, now time.Time) (EnrollmentRequest, DeviceFiles, error) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return EnrollmentRequest{}, DeviceFiles{}, errors.New("identity directory is required")
	}
	domainID = strings.TrimSpace(domainID)
	deviceID = strings.TrimSpace(deviceID)
	if domainID == "" || deviceID == "" {
		return EnrollmentRequest{}, DeviceFiles{}, errors.New("domain ID and device ID are required")
	}
	if strings.TrimSpace(hardwareClass) == "" {
		hardwareClass = "gb10"
	}
	proofOptions.Audience = strings.TrimSpace(proofOptions.Audience)
	proofOptions.Challenge = strings.TrimSpace(proofOptions.Challenge)
	proofOptions.Nonce = strings.TrimSpace(proofOptions.Nonce)
	proofRequested := proofOptions.Audience != "" || proofOptions.Challenge != "" || proofOptions.Nonce != ""
	if proofRequested && (proofOptions.Audience == "" || proofOptions.Challenge == "") {
		return EnrollmentRequest{}, DeviceFiles{}, errors.New("proof audience and challenge must be provided together")
	}
	if len(proofOptions.Audience) > 200 || len(proofOptions.Challenge) > 1024 || len(proofOptions.Nonce) > 200 {
		return EnrollmentRequest{}, DeviceFiles{}, errors.New("proof audience, challenge, or nonce is too long")
	}
	if proofRequested && proofOptions.Nonce == "" {
		nonce := make([]byte, 24)
		if _, err := rand.Read(nonce); err != nil {
			return EnrollmentRequest{}, DeviceFiles{}, fmt.Errorf("generate enrollment proof nonce: %w", err)
		}
		proofOptions.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return EnrollmentRequest{}, DeviceFiles{}, fmt.Errorf("create identity directory: %w", err)
	}
	files := DeviceFiles{
		Directory:    directory,
		IdentityFile: filepath.Join(directory, IdentityFileName),
		KeyFile:      filepath.Join(directory, IdentityKeyFileName),
	}
	keyBackend = strings.ToLower(strings.TrimSpace(keyBackend))
	if keyBackend != IdentityKeyBackendFile && keyBackend != IdentityKeyBackendKeyring {
		return EnrollmentRequest{}, DeviceFiles{}, errors.New("identity key backend must be keyring or file")
	}
	if _, err := os.Stat(files.IdentityFile); err == nil {
		return EnrollmentRequest{}, DeviceFiles{}, errors.New("device identity already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return EnrollmentRequest{}, DeviceFiles{}, fmt.Errorf("inspect device identity: %w", err)
	}
	provider := iscpcrypto.NewProvider()
	device, err := identity.NewDevice(provider, domainID, deviceID, now)
	if err != nil {
		return EnrollmentRequest{}, DeviceFiles{}, fmt.Errorf("generate ISCP identity: %w", err)
	}
	device.Identity.Metadata = map[string]string{
		"device_type":    "compute_node",
		"device_role":    "owner_runtime",
		"product_kind":   "sparkclaw",
		"runtime_kind":   "sparkclaw",
		"hardware_class": hardwareClass,
	}
	identityRaw, err := json.MarshalIndent(device.Identity, "", "  ")
	if err != nil {
		return EnrollmentRequest{}, DeviceFiles{}, fmt.Errorf("encode ISCP identity: %w", err)
	}
	privateKey := base64.RawURLEncoding.EncodeToString(device.Private.BytesForDevStore())
	if err := saveIdentityKey(keyBackend, keyringService, device.Identity, files.KeyFile, privateKey); err != nil {
		return EnrollmentRequest{}, DeviceFiles{}, err
	}
	if err := os.WriteFile(files.IdentityFile, append(identityRaw, '\n'), 0o644); err != nil {
		_ = deleteIdentityKey(keyBackend, keyringService, device.Identity, files.KeyFile)
		return EnrollmentRequest{}, DeviceFiles{}, fmt.Errorf("write device identity: %w", err)
	}
	request := EnrollmentRequest{
		Type:             EnrollmentRequestType,
		DeviceType:       "compute_node",
		DeviceRole:       "owner_runtime",
		ProductKind:      "sparkclaw",
		RuntimeKind:      "sparkclaw",
		HardwareClass:    hardwareClass,
		ProtocolVersions: []string{ProtocolVersion, BridgeVersion},
		Identity:         device.Identity,
		CreatedAt:        now.UTC(),
	}
	if proofRequested {
		proof, err := device.CreateProof(provider, proofOptions.Audience, proofOptions.Challenge, proofOptions.Nonce, now)
		if err != nil {
			_ = os.Remove(files.IdentityFile)
			_ = deleteIdentityKey(keyBackend, keyringService, device.Identity, files.KeyFile)
			return EnrollmentRequest{}, DeviceFiles{}, fmt.Errorf("create enrollment device proof: %w", err)
		}
		request.DeviceProof = &proof
	}
	return request, files, nil
}

func LoadDeviceWithKeyBackend(identityFile, keyFile, keyBackend, keyringService string) (identity.Device, error) {
	identityRaw, err := os.ReadFile(identityFile)
	if err != nil {
		return identity.Device{}, fmt.Errorf("read device identity: %w", err)
	}
	var publicIdentity identity.DeviceIdentity
	if err := json.Unmarshal(identityRaw, &publicIdentity); err != nil {
		return identity.Device{}, errors.New("decode device identity")
	}
	encodedKey, err := loadIdentityKey(keyBackend, keyringService, publicIdentity, keyFile)
	if err != nil {
		return identity.Device{}, err
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encodedKey))
	if err != nil {
		return identity.Device{}, errors.New("decode device identity key")
	}
	privateKey, err := iscpcrypto.Ed25519PrivateKeyFromBytes(keyBytes)
	if err != nil {
		return identity.Device{}, errors.New("load device identity key")
	}
	publicBytes, err := iscpcrypto.DecodeBase64URL(publicIdentity.PublicKey.Public)
	if err != nil {
		return identity.Device{}, errors.New("decode device public key")
	}
	if !iscpcrypto.EqualMAC(privateKey.Public().Bytes(), publicBytes) {
		return identity.Device{}, errors.New("device identity key does not match public identity")
	}
	return identity.Device{Identity: publicIdentity, Private: privateKey}, nil
}

func saveIdentityKey(backend, service string, deviceIdentity identity.DeviceIdentity, keyFile, encoded string) error {
	switch backend {
	case IdentityKeyBackendKeyring:
		if strings.TrimSpace(service) == "" {
			service = DefaultIdentityKeyringService
		}
		if err := keyring.Set(service, identityKeyAccount(deviceIdentity), encoded); err != nil {
			return fmt.Errorf("store device identity in system keyring: %w", err)
		}
		return nil
	case IdentityKeyBackendFile:
		return writeSecretFile(keyFile, []byte(encoded+"\n"))
	default:
		return errors.New("unsupported identity key backend")
	}
}

func loadIdentityKey(backend, service string, deviceIdentity identity.DeviceIdentity, keyFile string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case IdentityKeyBackendKeyring:
		if strings.TrimSpace(service) == "" {
			service = DefaultIdentityKeyringService
		}
		encoded, err := keyring.Get(service, identityKeyAccount(deviceIdentity))
		if err != nil {
			return "", fmt.Errorf("load device identity from system keyring: %w", err)
		}
		return encoded, nil
	case IdentityKeyBackendFile:
		if err := requirePrivateFile(keyFile); err != nil {
			return "", err
		}
		raw, err := os.ReadFile(keyFile)
		if err != nil {
			return "", fmt.Errorf("read device identity key: %w", err)
		}
		return strings.TrimSpace(string(raw)), nil
	default:
		return "", errors.New("unsupported identity key backend")
	}
}

func deleteIdentityKey(backend, service string, deviceIdentity identity.DeviceIdentity, keyFile string) error {
	if backend == IdentityKeyBackendKeyring {
		if strings.TrimSpace(service) == "" {
			service = DefaultIdentityKeyringService
		}
		return keyring.Delete(service, identityKeyAccount(deviceIdentity))
	}
	return os.Remove(keyFile)
}

func identityKeyAccount(deviceIdentity identity.DeviceIdentity) string {
	return deviceIdentity.DomainID + "/" + deviceIdentity.DeviceID
}

func LoadEnrollment(path string, now time.Time) (EnrollmentBundle, error) {
	if err := requirePrivateFile(path); err != nil {
		return EnrollmentBundle{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return EnrollmentBundle{}, fmt.Errorf("read enrollment bundle: %w", err)
	}
	var bundle EnrollmentBundle
	if err := strictUnmarshal(raw, &bundle); err != nil {
		return EnrollmentBundle{}, errors.New("decode enrollment bundle")
	}
	if err := bundle.Validate(now); err != nil {
		return EnrollmentBundle{}, err
	}
	return bundle, nil
}

func SaveEnrollment(path string, bundle EnrollmentBundle) error {
	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return errors.New("encode enrollment bundle")
	}
	return writeSecretFile(path, append(raw, '\n'))
}

func (b EnrollmentBundle) Validate(now time.Time) error {
	if b.Type != EnrollmentBundleType {
		return errors.New("unsupported enrollment bundle type")
	}
	if strings.TrimSpace(b.DomainID) == "" || strings.TrimSpace(b.DeviceID) == "" || strings.TrimSpace(b.RelayID) == "" {
		return errors.New("enrollment identity and Relay fields are required")
	}
	if b.Access.DomainID != b.DomainID || b.Access.DeviceID != b.DeviceID || strings.TrimSpace(b.Access.Token) == "" {
		return errors.New("access credential is not bound to the enrolled device")
	}
	if b.Refresh.DomainID != b.DomainID || b.Refresh.DeviceID != b.DeviceID || strings.TrimSpace(b.Refresh.Token) == "" {
		return errors.New("refresh credential is not bound to the enrolled device")
	}
	if b.Access.ExpiresAt.IsZero() || b.Refresh.ExpiresAt.IsZero() || !now.Before(b.Refresh.ExpiresAt) {
		return errors.New("enrollment Relay credentials are expired or incomplete")
	}
	// A managed multi-tenant Trust Root (Infinimesh Cloud) signs for many
	// device domains from its own platform domain, so the domain-equality
	// check applies only to the legacy single-domain contract.
	if strings.TrimSpace(b.TrustRootIdentity.DeviceID) == "" {
		return errors.New("Trust Root identity is required")
	}
	if b.Mode != BundleModeManaged && b.TrustRootIdentity.DomainID != b.DomainID {
		return errors.New("Trust Root identity is outside the enrolled Domain")
	}
	if b.IssuedAt.IsZero() || b.ExpiresAt.IsZero() || !b.IssuedAt.Before(b.ExpiresAt) {
		return errors.New("enrollment validity window is invalid")
	}
	if !now.Before(b.ExpiresAt) {
		return errors.New("enrollment bundle has expired; re-enrollment is required")
	}
	if len(b.Peers) == 0 {
		return errors.New("enrollment bundle has no authorized peers")
	}
	seen := map[string]struct{}{}
	for _, peer := range b.Peers {
		if peer.Identity.DomainID != b.DomainID || strings.TrimSpace(peer.Identity.DeviceID) == "" {
			return errors.New("peer identity is outside the enrolled Domain")
		}
		if _, ok := seen[peer.Identity.DeviceID]; ok {
			return errors.New("enrollment bundle contains duplicate peers")
		}
		seen[peer.Identity.DeviceID] = struct{}{}
		if b.Mode != BundleModeManaged {
			if peer.InboundGrant.SubjectDeviceID != peer.Identity.DeviceID || peer.InboundGrant.Audience != b.DeviceID {
				return errors.New("peer inbound grant binding is invalid")
			}
		}
		if peer.OutboundGrant.SubjectDeviceID != b.DeviceID || peer.OutboundGrant.Audience != peer.Identity.DeviceID {
			return errors.New("peer outbound grant binding is invalid")
		}
	}
	return nil
}

// ValidateCredentials checks cloud enrollment independently of the legacy
// Bridge's grant direction. An enrolled device can use a separate application
// issuer while retaining its cloud Trust Root and rotated access credentials.
func (b EnrollmentBundle) ValidateCredentials(now time.Time) error {
	if b.Type != EnrollmentBundleType || strings.TrimSpace(b.DomainID) == "" || strings.TrimSpace(b.DeviceID) == "" || strings.TrimSpace(b.RelayID) == "" {
		return errors.New("enrollment identity and Relay fields are required")
	}
	for _, credential := range []RelayCredential{b.Access, b.Refresh} {
		if credential.DomainID != b.DomainID || credential.DeviceID != b.DeviceID || strings.TrimSpace(credential.Token) == "" || credential.ExpiresAt.IsZero() {
			return errors.New("Relay credential is not bound to the enrolled device")
		}
	}
	if !now.Before(b.Refresh.ExpiresAt) {
		return errors.New("enrollment Relay refresh credential expired")
	}
	if b.Mode == BundleModeWorkbenchNodeManaged {
		if err := ValidateNodeRelayURLs(b.RelayBaseURL, b.RelayWebSocketURL); err != nil {
			return err
		}
		if b.InvitationSignerIdentity == nil || b.RelaySignerIdentity == nil || b.InvitationSignerIdentity.DomainID != b.DomainID || b.RelaySignerIdentity.DomainID != b.DomainID || b.TLSCertificatePEM == "" {
			return errors.New("node-managed enrollment requires independent invitation/Relay pins and TLS trust")
		}
		if ValidateLocalRelaySigner(*b.InvitationSignerIdentity) != nil || ValidateLocalRelaySigner(*b.RelaySignerIdentity) != nil || b.InvitationSignerIdentity.PublicKey.Public == b.RelaySignerIdentity.PublicKey.Public {
			return errors.New("node-managed enrollment authority pins are invalid")
		}
	} else if b.Mode == BundleModeWorkbenchLocalLab {
		if b.RelaySignerIdentity == nil || b.RelaySignerIdentity.DomainID != b.DomainID || b.RelaySignerIdentity.DeviceID == "" {
			return errors.New("local Relay signer pin is required")
		}
	} else if b.TrustRootIdentity.DeviceID == "" || b.TrustRootIdentity.DomainID == "" {
		return errors.New("cloud Trust Root identity is required")
	}
	if b.IssuedAt.IsZero() || b.ExpiresAt.IsZero() || !b.IssuedAt.Before(b.ExpiresAt) || !now.Before(b.ExpiresAt) {
		return errors.New("cloud enrollment is incomplete or expired")
	}
	return nil
}

func (b EnrollmentBundle) Peer(deviceID string) (PeerAuthorization, bool) {
	for _, peer := range b.Peers {
		if peer.Identity.DeviceID == deviceID {
			return peer, true
		}
	}
	return PeerAuthorization{}, false
}

func requirePrivateFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect private file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("private path must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("private file permissions must not allow group or other access")
	}
	return nil
}

func writeSecretFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create private directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".sparkclaw-iscp-*")
	if err != nil {
		return fmt.Errorf("create private temporary file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("protect private temporary file: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write private temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync private temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close private temporary file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace private file: %w", err)
	}
	return nil
}
