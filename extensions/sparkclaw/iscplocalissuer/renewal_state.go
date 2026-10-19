package iscplocalissuer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

const (
	RenewalStateFile      = "renewal-state.json"
	maxRenewalStateBytes  = 64 << 20
	maxIdempotencyRecords = 32768
	maxNonceRecords       = 4096
)

type renewalScope struct {
	DomainID    string `json:"domain_id"`
	Subject     string `json:"subject_device_id"`
	Audience    string `json:"audience_device_id"`
	SubjectKey  string `json:"subject_key"`
	AudienceKey string `json:"audience_key"`
	RelayID     string `json:"relay_id"`
	Permission  string `json:"permission"`
}

type renewalAuthorization struct {
	AuthorizedAt time.Time                 `json:"authorized_at"`
	ExpiresAt    time.Time                 `json:"expires_at"`
	Revoked      bool                      `json:"revoked"`
	Lifetime     string                    `json:"lifetime,omitempty"`
	Revision     uint64                    `json:"revision,omitempty"`
	Scopes       []string                  `json:"scopes,omitempty"`
	Deletion     *iscpauth.DeletionReceipt `json:"deletion,omitempty"`
}

type idempotencyRecord struct {
	BodySHA256 string `json:"body_sha256"`
	Status     int    `json:"status"`
	// Bytes, rather than RawMessage, preserve the exact successful wire response.
	Response []byte `json:"response"`
	// Current is a read-only local adapter: its retries need only cover proof
	// freshness. Bounded-policy renewal responses live until consent ends;
	// permanent-policy receipts expire seven days after their Grant.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type renewalState struct {
	SchemaVersion   int                                 `json:"schema_version"`
	Scope           renewalScope                        `json:"scope"`
	CurrentGrant    *trust.Grant                        `json:"current_grant,omitempty"`
	TTLSeconds      int                                 `json:"ttl_seconds"`
	Authorization   *renewalAuthorization               `json:"authorization,omitempty"`
	Idempotency     map[string]idempotencyRecord        `json:"idempotency"`
	Nonces          map[string]time.Time                `json:"nonces"`
	DeletionHistory map[string]iscpauth.DeletionReceipt `json:"deletion_history,omitempty"`
	Reauthorization *reauthorizationReceipt             `json:"reauthorization,omitempty"`
}

func (i *Issuer) scope() renewalScope {
	return renewalScope{i.subject.DomainID, i.subject.DeviceID, i.audience.DeviceID, i.subject.PublicKey.KID, i.audience.PublicKey.KID, i.relayID, Permission}
}

func (i *Issuer) readRenewalState() (*renewalState, error) {
	raw, err := readPrivateBounded(filepath.Join(i.directory, RenewalStateFile), maxRenewalStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return &renewalState{SchemaVersion: 1, Scope: i.scope(), Idempotency: map[string]idempotencyRecord{}, Nonces: map[string]time.Time{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var state renewalState
	if decode(raw, &state) != nil || (state.SchemaVersion != 1 && state.SchemaVersion != 2) || state.Scope != i.scope() || len(state.Idempotency) > maxIdempotencyRecords || len(state.Nonces) > maxNonceRecords {
		return nil, errors.New("invalid renewal state")
	}
	if state.CurrentGrant != nil {
		ttl, err := i.validateGrant(*state.CurrentGrant)
		if err != nil || state.TTLSeconds < ttl || state.TTLSeconds > 1800 || (state.Authorization == nil && ttl != state.TTLSeconds) {
			return nil, errors.New("invalid current grant")
		}
	} else if state.TTLSeconds != 0 || state.Authorization != nil {
		return nil, errors.New("renewal state has no current grant")
	}
	if auth := state.Authorization; auth != nil {
		duration := auth.ExpiresAt.Sub(auth.AuthorizedAt)
		if state.SchemaVersion == 2 {
			if iscpauth.ValidateScopes(auth.Scopes) != nil || auth.AuthorizedAt.IsZero() || auth.Lifetime != iscpauth.UntilRevoked || !auth.ExpiresAt.IsZero() || auth.Revision == 0 || state.CurrentGrant.RevocationEpoch > auth.Revision || (!auth.Revoked && state.CurrentGrant.RevocationEpoch != auth.Revision) {
				return nil, errors.New("invalid permanent authorization")
			}
			if d := auth.Deletion; d != nil && (!auth.Revoked || !validIdempotencyKey(d.OperationID) || d.ExpectedRevision == 0 || d.ExpectedRevision == ^uint64(0) || d.AuthorizationRevision != d.ExpectedRevision+1 || d.AuthorizationRevision != auth.Revision || d.State != iscpauth.Revoked || d.DeletedAt.IsZero()) {
				return nil, errors.New("invalid authorization deletion receipt")
			}
		} else if auth.AuthorizedAt.IsZero() || duration < 24*time.Hour || duration > 365*24*time.Hour || auth.Lifetime != "" || auth.Revision != 0 || len(auth.Scopes) != 0 {
			return nil, errors.New("invalid renewal authorization")
		}
	} else if state.SchemaVersion == 2 {
		return nil, errors.New("permanent authorization missing")
	}
	for key, record := range state.Idempotency {
		if len(key) != 64 || len(record.BodySHA256) != 64 || len(record.Response) > 8192 || !json.Valid(record.Response) || (record.Status != 200 && record.Status != 201) {
			return nil, errors.New("invalid idempotency record")
		}
	}
	for key, expires := range state.Nonces {
		if len(key) != 64 || expires.IsZero() {
			return nil, errors.New("invalid nonce record")
		}
	}
	if len(state.DeletionHistory) > 4096 {
		return nil, errors.New("authorization history exceeds limit")
	}
	for key, receipt := range state.DeletionHistory {
		if key != receipt.OperationID || !validIdempotencyKey(key) || receipt.ExpectedRevision == 0 || receipt.ExpectedRevision == ^uint64(0) || receipt.AuthorizationRevision != receipt.ExpectedRevision+1 || receipt.State != iscpauth.Revoked || receipt.DeletedAt.IsZero() {
			return nil, errors.New("invalid authorization history")
		}
	}
	if receipt := state.Reauthorization; receipt != nil {
		if state.SchemaVersion != 2 || !validIdempotencyKey(receipt.OperationID) || receipt.ExpectedRevision == 0 || receipt.ExpectedRevision == ^uint64(0) || receipt.Grant.RevocationEpoch != receipt.ExpectedRevision+1 || receipt.Grant.RevocationEpoch > state.Authorization.Revision || len(receipt.ScopesDigest) != 64 {
			return nil, errors.New("invalid reauthorization receipt")
		}
		if _, err := i.validateGrant(receipt.Grant); err != nil {
			return nil, err
		}
	}
	if state.Idempotency == nil {
		state.Idempotency = map[string]idempotencyRecord{}
	}
	if state.Nonces == nil {
		state.Nonces = map[string]time.Time{}
	}
	return &state, nil
}

// The private file lock serializes the CLI and running server as well as
// concurrent requests. Each operation reloads authorization to observe revocation.
func (i *Issuer) withRenewalState(fn func(*renewalState) (bool, error)) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	fd, err := syscall.Open(filepath.Join(i.directory, ".renewal.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("renewal lock unavailable")
	}
	file := os.NewFile(uintptr(fd), "renewal lock")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("renewal lock is not private")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return errors.New("renewal lock unavailable")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	state, err := i.readRenewalState()
	if err != nil {
		return err
	}
	dirty, businessErr := fn(state)
	if dirty {
		if err := i.writeRenewalState(state); err != nil {
			return err
		}
	}
	return businessErr
}

func (i *Issuer) writeRenewalState(state *renewalState) error {
	raw, err := json.Marshal(state)
	if err != nil || len(raw) > maxRenewalStateBytes {
		return errors.New("renewal state exceeds limit")
	}
	file, err := os.CreateTemp(i.directory, ".renewal-state-*")
	if err != nil {
		return errors.New("renewal state unavailable")
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.New("renewal state unavailable")
	}
	if err = os.Rename(name, filepath.Join(i.directory, RenewalStateFile)); err != nil {
		return errors.New("renewal state unavailable")
	}
	dir, err := os.Open(i.directory)
	if err != nil {
		return errors.New("renewal state unavailable")
	}
	defer dir.Close()
	return dir.Sync()
}

func readPrivateBounded(path string, limit int64) ([]byte, error) {
	return readBoundedFile(path, limit, true)
}

func readBoundedFile(path string, limit int64, private bool) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "private issuer file")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || (private && info.Mode().Perm() != 0o600) || info.Size() > limit {
		return nil, errors.New("private issuer file is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("private issuer file exceeds limit")
	}
	return raw, nil
}

func hashString(value string) string { return hashBytes([]byte(value)) }
func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func (i *Issuer) validateGrant(grant trust.Grant) (int, error) {
	ttl := grant.ExpiresAt.Sub(grant.NotBefore)
	if ttl < time.Second || ttl > 30*time.Minute || ttl%time.Second != 0 || grant.GrantID == "" || grant.Issuer != i.device.Identity.DeviceID || grant.Signature.Alg != "Ed25519" || grant.Signature.KID != i.device.Identity.PublicKey.KID || grant.RevocationEpoch == 0 || len(grant.Permissions) != 1 || grant.Permissions[0] != Permission || len(grant.RelayConstraints) != 1 || grant.RelayConstraints[0] != i.relayID {
		return 0, errors.New("grant scope or TTL is invalid")
	}
	thumbprint, err := identity.Thumbprint(i.subject)
	if err != nil {
		return 0, err
	}
	// Historical verification preserves recoverability after the short Grant
	// expires. Authorization is separately checked against the real current time.
	err = trust.VerifyGrant(iscpcrypto.NewProvider(), grant, i.device.Identity, trust.VerifyOptions{Audience: i.audience.DeviceID, SubjectDeviceID: i.subject.DeviceID, ConfirmationThumbprint: thumbprint, Permission: Permission, RelayID: i.relayID, CurrentRevocationEpoch: grant.RevocationEpoch, Now: grant.NotBefore})
	return int(ttl / time.Second), err
}

// AuthorizeRenewal records explicit operator consent for the existing direction.
// The absolute deadline is never extended by a device request.
func (i *Issuer) AuthorizeRenewal(grantFile string, authorizationHours int) error {
	if authorizationHours < 24 || authorizationHours > 365*24 {
		return errors.New("authorization hours must be between 24 and 8760")
	}
	raw, err := readPrivateBounded(grantFile, 65536)
	if err != nil {
		return errors.New("authorization grant file unavailable")
	}
	var grant trust.Grant
	if err = decode(raw, &grant); err != nil {
		return errors.New("invalid authorization grant")
	}
	ttl, err := i.validateGrant(grant)
	if err != nil {
		return err
	}
	return i.withRenewalState(func(state *renewalState) (bool, error) {
		if state.SchemaVersion == 2 {
			return false, errors.New("permanent authorization cannot be replaced by a bounded policy")
		}
		if state.CurrentGrant != nil {
			current, _ := json.Marshal(state.CurrentGrant)
			supplied, _ := json.Marshal(grant)
			if string(current) != string(supplied) {
				return false, errors.New("authorization grant is not the current grant")
			}
		}
		now := i.Now().UTC()
		if state.Authorization != nil && !now.Before(state.Authorization.ExpiresAt) {
			state.Idempotency = map[string]idempotencyRecord{}
		}
		policyTTL := ttl
		if state.Authorization != nil {
			policyTTL = state.TTLSeconds
		}
		state.CurrentGrant, state.TTLSeconds = &grant, policyTTL
		state.Authorization = &renewalAuthorization{AuthorizedAt: now, ExpiresAt: now.Add(time.Duration(authorizationHours) * time.Hour)}
		return true, nil
	})
}

func (i *Issuer) RevokeRenewal() error {
	return i.withRenewalState(func(state *renewalState) (bool, error) {
		if state.Authorization == nil {
			return false, errors.New("renewal authorization not found")
		}
		if state.Authorization.Revoked {
			return false, nil
		}
		if state.SchemaVersion == 2 {
			if state.Authorization.Revision == ^uint64(0) {
				return false, errors.New("authorization revision exhausted")
			}
			state.Authorization.Revision++
		}
		state.Authorization.Revoked = true
		return true, nil
	})
}
