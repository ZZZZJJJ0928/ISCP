// Package iscplocalissuer issues fixed-direction, short-lived grants for a
// privately configured local integration. It never registers Relay devices.
package iscplocalissuer

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

const Permission = "sparkclaw.workbench.v1"

type Config struct {
	SchemaVersion        int    `json:"schema_version"`
	Mode                 string `json:"mode"`
	Directory            string `json:"directory"`
	SubjectIdentityFile  string `json:"subject_identity_file"`
	AudienceIdentityFile string `json:"audience_identity_file"`
	RelayID              string `json:"relay_id"`
}

type Issuer struct {
	mu        sync.Mutex
	device    identity.Device
	subject   identity.DeviceIdentity
	audience  identity.DeviceIdentity
	relayID   string
	token     string
	auditFile string
	directory string
	Now       func() time.Time
}

// Initialize creates a new private root. Existing directories are never reused
// or overwritten; recovering a run uses its existing config and signing key.
func Initialize(directory, subjectFile, audienceFile, relayID string) (Config, error) {
	var cfg Config
	if !filepath.IsAbs(directory) || strings.TrimSpace(relayID) == "" {
		return cfg, errors.New("absolute new directory and Relay ID required")
	}
	subject, err := readIdentity(subjectFile)
	if err != nil {
		return cfg, err
	}
	audience, err := readIdentity(audienceFile)
	if err != nil {
		return cfg, err
	}
	if err = validatePair(subject, audience); err != nil {
		return cfg, err
	}
	if err = os.Mkdir(directory, 0o700); err != nil {
		return cfg, errors.New("issuer directory must be new")
	}
	provider := iscpcrypto.NewProvider()
	device, err := identity.NewDevice(provider, subject.DomainID, "local-issuer-"+iscpcrypto.Base64URL(iscpcrypto.RandomBytes(12)), time.Now().UTC())
	if err != nil {
		return cfg, err
	}
	device.Identity.Metadata = map[string]string{"purpose": "sparkclaw-local-iscp-test"}
	cfg = Config{1, "local-test", directory, subjectFile, audienceFile, relayID}
	public, _ := json.MarshalIndent(device.Identity, "", "  ")
	config, _ := json.MarshalIndent(cfg, "", "  ")
	for name, raw := range map[string][]byte{
		"issuer.identity.json": public,
		"issuer.key":           []byte(base64.RawURLEncoding.EncodeToString(device.Private.BytesForDevStore())),
		"management.token":     []byte(iscpcrypto.Base64URL(iscpcrypto.RandomBytes(32))),
		"issuer.json":          config,
	} {
		if err = os.WriteFile(filepath.Join(directory, name), raw, 0o600); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

func Load(configPath string) (*Issuer, error) {
	raw, err := readPrivate(configPath)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err = decode(raw, &cfg); err != nil || cfg.SchemaVersion != 1 || cfg.Mode != "local-test" || !filepath.IsAbs(cfg.Directory) || strings.TrimSpace(cfg.RelayID) == "" {
		return nil, errors.New("invalid local issuer config")
	}
	info, err := os.Lstat(cfg.Directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("issuer directory is not private")
	}
	public, err := readIdentity(filepath.Join(cfg.Directory, "issuer.identity.json"))
	if err != nil {
		return nil, err
	}
	keyRaw, err := readPrivate(filepath.Join(cfg.Directory, "issuer.key"))
	if err != nil {
		return nil, err
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(string(keyRaw))
	if err != nil {
		return nil, errors.New("invalid issuer key")
	}
	key, err := iscpcrypto.Ed25519PrivateKeyFromBytes(keyBytes)
	if err != nil {
		return nil, errors.New("invalid issuer key")
	}
	if iscpcrypto.Base64URL(key.Public().Bytes()) != public.PublicKey.Public {
		return nil, errors.New("issuer key identity mismatch")
	}
	subject, err := readIdentity(cfg.SubjectIdentityFile)
	if err != nil {
		return nil, err
	}
	audience, err := readIdentity(cfg.AudienceIdentityFile)
	if err != nil {
		return nil, err
	}
	if err = validatePair(subject, audience); err != nil || public.DomainID != subject.DomainID {
		return nil, errors.New("issuer peer identity mismatch")
	}
	token, err := readPrivate(filepath.Join(cfg.Directory, "management.token"))
	if err != nil || len(token) < 32 {
		return nil, errors.New("invalid management credential")
	}
	i := &Issuer{device: identity.Device{Identity: public, Private: key}, subject: subject, audience: audience, relayID: cfg.RelayID, token: string(token), auditFile: filepath.Join(cfg.Directory, "issuance.jsonl"), directory: cfg.Directory, Now: time.Now}
	if _, err = i.readRenewalState(); err != nil {
		return nil, err
	}
	return i, nil
}

func (i *Issuer) Sign(ttl time.Duration) (trust.Grant, error) {
	if ttl < time.Second || ttl > 30*time.Minute || ttl%time.Second != 0 {
		return trust.Grant{}, errors.New("grant TTL must be between 1 second and 30 minutes")
	}
	var grant trust.Grant
	err := i.withRenewalState(func(state *renewalState) (bool, error) {
		if state.Authorization != nil && int(ttl/time.Second) != state.TTLSeconds {
			return false, errors.New("authorized grant TTL cannot change")
		}
		var err error
		now := i.Now().UTC()
		issuedTTL := ttl
		if state.Authorization != nil {
			if err := authorizationError(state, now); err != nil {
				return false, err
			}
			issuedTTL = authorizationBoundedTTL(ttl, state.Authorization.ExpiresAt, now)
			if issuedTTL < time.Second {
				return false, errors.New("authorization has less than one second remaining")
			}
		}
		epoch := uint64(1)
		if state.CurrentGrant != nil {
			epoch = state.CurrentGrant.RevocationEpoch
		}
		grant, err = i.signGrantAt(issuedTTL, now, epoch)
		if err != nil {
			return false, err
		}
		state.CurrentGrant = &grant
		state.TTLSeconds = int(ttl / time.Second)
		return true, nil
	})
	return grant, err
}

// signGrantAt is called under the cross-process state lock. Only public grant
// provenance reaches the issuance journal.
func (i *Issuer) signGrantAt(ttl time.Duration, now time.Time, epoch uint64) (trust.Grant, error) {
	provider := iscpcrypto.NewProvider()
	thumbprint, err := identity.Thumbprint(i.subject)
	if err != nil {
		return trust.Grant{}, err
	}
	grant, err := trust.SignGrant(provider, i.device, trust.Grant{
		GrantID:         "local-grant-" + iscpcrypto.Base64URL(iscpcrypto.RandomBytes(16)),
		SubjectDeviceID: i.subject.DeviceID, Audience: i.audience.DeviceID,
		ConfirmationThumbprint: thumbprint, Permissions: []string{Permission},
		RelayConstraints: []string{i.relayID}, NotBefore: now, ExpiresAt: now.Add(ttl), RevocationEpoch: epoch,
	})
	if err != nil {
		return trust.Grant{}, err
	}
	if info, err := os.Lstat(i.auditFile); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > maxRenewalStateBytes) {
		return trust.Grant{}, errors.New("issuance journal is not private")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return trust.Grant{}, errors.New("issuance journal unavailable")
	}
	fd, err := syscall.Open(i.auditFile, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_APPEND|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return trust.Grant{}, errors.New("issuance journal unavailable")
	}
	journal := os.NewFile(uintptr(fd), "issuance journal")
	defer journal.Close()
	if info, err := journal.Stat(); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > maxRenewalStateBytes {
		return trust.Grant{}, errors.New("issuance journal is not private")
	}
	if err = json.NewEncoder(journal).Encode(map[string]any{"grant_id": grant.GrantID, "subject_device_id": grant.SubjectDeviceID, "audience": grant.Audience, "expires_at": grant.ExpiresAt, "issuer_kid": i.device.Identity.PublicKey.KID}); err != nil {
		return trust.Grant{}, errors.New("issuance journal unavailable")
	}
	if err = journal.Sync(); err != nil {
		return trust.Grant{}, errors.New("issuance journal unavailable")
	}
	return grant, nil
}

// Handler accepts only a TTL; peer identities, permissions and Relay cannot be
// chosen by a caller. Only the local runner possesses the management credential.
func (i *Issuer) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if i.handleRenewal(w, r) {
			return
		}
		if r.Method != "POST" || r.URL.Path != "/v1/grants" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		authorization := r.Header.Get("Authorization")
		provided := strings.TrimPrefix(authorization, "Bearer ")
		if !strings.HasPrefix(authorization, "Bearer ") || len(provided) != len(i.token) || subtle.ConstantTimeCompare([]byte(provided), []byte(i.token)) != 1 {
			http.Error(w, "management authorization required", 401)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
		if err != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		var input struct {
			TTLSeconds int `json:"ttl_seconds"`
		}
		if err = decode(raw, &input); err != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		if input.TTLSeconds == 0 {
			input.TTLSeconds = 1800
		}
		grant, err := i.Sign(time.Duration(input.TTLSeconds) * time.Second)
		if err != nil {
			http.Error(w, "invalid grant TTL", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(grant)
	})
}

func readPrivate(path string) ([]byte, error) {
	return readPrivateBounded(path, 65536)
}
func readIdentity(path string) (identity.DeviceIdentity, error) {
	var value identity.DeviceIdentity
	raw, err := readBoundedFile(path, 65536, false)
	if err != nil || len(raw) > 65536 {
		return value, errors.New("peer identity file unavailable")
	}
	if err = decode(raw, &value); err != nil {
		return value, errors.New("invalid peer identity")
	}
	public, decodeErr := iscpcrypto.DecodeBase64URL(value.PublicKey.Public)
	_, keyErr := iscpcrypto.Ed25519PublicKeyFromBytes(public)
	thumbprint, thumbErr := identity.Thumbprint(value)
	if value.Type != identity.TypeDeviceIdentity || value.DomainID == "" || value.DeviceID == "" || value.PublicKey.KTY != "Ed25519" || value.PublicKey.Use != "identity-signature" || value.PublicKey.KID != thumbprint || decodeErr != nil || keyErr != nil || thumbErr != nil {
		return value, errors.New("invalid peer identity")
	}
	return value, nil
}
func validatePair(subject, audience identity.DeviceIdentity) error {
	if subject.DomainID != audience.DomainID || subject.DeviceID == audience.DeviceID {
		return errors.New("test peers must be distinct devices in one enrolled Domain")
	}
	return nil
}
func decode(raw []byte, value any) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if !json.Valid(raw) {
		return errors.New("invalid JSON")
	}
	return nil
}
