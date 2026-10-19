package iscplocalissuer

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

const (
	AutoRenewPath           = "/v2/relay/devices/auto-renew-grant"
	CurrentGrantPath        = "/v1/grants/current"
	RenewalCapabilityPath   = "/v1/renewal-capability"
	proofFreshness          = 5 * time.Minute
	trustRootDescriptorType = "iscp.trust_root.descriptor.v2"
)

type RenewalRequest struct {
	Identity      identity.DeviceIdentity `json:"identity"`
	IdentityProof identity.DeviceProof    `json:"identity_proof"`
}

type DeviceRecord struct {
	DomainID string `json:"domain_id"`
	DeviceID string `json:"device_id"`
	Status   string `json:"status"`
	GrantID  string `json:"grant_id"`
}

type GrantResponse struct {
	Data  DeviceRecord `json:"data"`
	Grant trust.Grant  `json:"grant"`
}

type protocolError struct {
	status     int
	reason     string
	retryAfter int
}

func (e *protocolError) Error() string        { return e.reason }
func failure(status int, reason string) error { return &protocolError{status: status, reason: reason} }

func authorizationError(state *renewalState, now time.Time) error {
	if state.Authorization == nil {
		return failure(404, "renewal_authorization_not_found")
	}
	if state.Authorization.Revoked {
		return failure(403, "renewal_authorization_revoked")
	}
	if !state.Authorization.ExpiresAt.IsZero() && !now.Before(state.Authorization.ExpiresAt) {
		return failure(410, "renewal_authorization_expired")
	}
	return nil
}

func writeProtocolError(w http.ResponseWriter, err error) {
	var e *protocolError
	if !errors.As(err, &e) {
		e = &protocolError{status: 503, reason: "issuer_state_unavailable"}
	}
	if e.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(e.retryAfter))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.status)
	_ = json.NewEncoder(w).Encode(map[string]string{"type": "iscp.error.v2", "reason": e.reason})
}

func (i *Issuer) handleRenewal(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case iscpauth.DeletePath, iscpauth.DeleteReceiptPath:
		i.authorizationDelete(w, r)
		return true
	case iscpauth.StatusPath:
		i.authorizationStatus(w, r)
		return true
	case RenewalCapabilityPath:
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			writeProtocolError(w, failure(405, "method_not_allowed"))
			return true
		}
		signed, err := i.readCapability()
		if err != nil {
			writeProtocolError(w, err)
		} else {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signed)
		}
		return true
	case AutoRenewPath, CurrentGrantPath:
		if r.Method != http.MethodPost || r.URL.RawQuery != "" {
			writeProtocolError(w, failure(405, "method_not_allowed"))
			return true
		}
		key := r.Header.Get("Idempotency-Key")
		if !validIdempotencyKey(key) {
			writeProtocolError(w, failure(400, "idempotency_key_required"))
			return true
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
		if err != nil {
			writeProtocolError(w, failure(400, "invalid_request"))
			return true
		}
		status, response, err := i.deviceGrant(r.URL.Path, key, raw)
		if err != nil {
			writeProtocolError(w, err)
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(response)
		}
		return true
	default:
		return false
	}
}

// Atomic state replacement gives GET a consistent snapshot without creating a
// lock file or pruning records. Capability discovery has no persisted effects.
func (i *Issuer) readCapability() (descriptor.SignedDescriptor, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	state, err := i.readRenewalState()
	if err != nil {
		return descriptor.SignedDescriptor{}, err
	}
	now := i.Now().UTC()
	if err = authorizationError(state, now); err != nil && !(state.SchemaVersion == 2 && state.Authorization != nil) {
		return descriptor.SignedDescriptor{}, err
	}
	return i.capability(state, now)
}

func validIdempotencyKey(key string) bool {
	if key == "" || len(key) > 200 || strings.TrimSpace(key) != key {
		return false
	}
	for _, ch := range key {
		if ch < 33 || ch > 126 {
			return false
		}
	}
	return true
}

func (i *Issuer) capability(state *renewalState, now time.Time) (descriptor.SignedDescriptor, error) {
	return descriptor.Sign(iscpcrypto.NewProvider(), i.device, trustRootDescriptorType, i.capabilityBody(state, now), now)
}

func (i *Issuer) capabilityBody(state *renewalState, now time.Time) descriptor.TrustRootDescriptor {
	expires := now.Add(5 * time.Minute)
	if !state.Authorization.ExpiresAt.IsZero() && state.Authorization.ExpiresAt.Before(expires) {
		expires = state.Authorization.ExpiresAt
	}
	key := i.device.Identity.PublicKey
	body := descriptor.TrustRootDescriptor{Type: trustRootDescriptorType, TrustRootID: i.device.Identity.DeviceID, DomainID: i.device.Identity.DomainID,
		Keys: []descriptor.PublicKey{{KTY: key.KTY, Use: "descriptor-signature", KID: key.KID, Public: key.Public}}, IssuedAt: now, ExpiresAt: expires,
		Metadata: map[string]string{"purpose": "sparkclaw-local-grant-renewal", "grant_renewal": "true", "issuer_device_id": i.device.Identity.DeviceID, "relay_id": i.relayID, "subject_device_id": i.subject.DeviceID, "audience_device_id": i.audience.DeviceID, "permission": Permission}}
	state.policy(now).AddTo(body.Metadata)
	return body
}

func (i *Issuer) deviceGrant(path, key string, raw []byte) (int, []byte, error) {
	var status int
	var response []byte
	err := i.withRenewalState(func(state *renewalState) (bool, error) {
		now := i.Now().UTC()
		if err := authorizationError(state, now); err != nil {
			return false, err
		}
		dirty := false
		for cachedKey, cached := range state.Idempotency {
			if !cached.ExpiresAt.IsZero() && !now.Before(cached.ExpiresAt) {
				delete(state.Idempotency, cachedKey)
				dirty = true
			}
		}
		cacheKey, bodyHash := hashString(path+"\x00"+key), hashBytes(raw)
		if previous, exists := state.Idempotency[cacheKey]; exists {
			if previous.BodySHA256 != bodyHash {
				return dirty, failure(409, "renewal_identity_conflict")
			}
			// This payload was verified before its successful response was persisted.
			// An unknown-outcome retry must survive proof expiry and server restart.
			var cached GrantResponse
			if decode(previous.Response, &cached) != nil {
				return dirty, errors.New("invalid cached response")
			}
			if _, err := i.validateGrant(cached.Grant); err != nil {
				return dirty, err
			}
			status, response = previous.Status, previous.Response
			return dirty, nil
		}
		if len(state.Idempotency) >= maxIdempotencyRecords {
			return dirty, &protocolError{429, "issuer_capacity_exceeded", 60}
		}
		var input RenewalRequest
		if decode(raw, &input) != nil {
			return dirty, failure(400, "invalid_request")
		}
		if err := i.verifyDeviceProof(path, key, input, now); err != nil {
			return dirty, err
		}
		for nonce, expires := range state.Nonces {
			if now.After(expires) {
				delete(state.Nonces, nonce)
			}
		}
		nonceKey := hashString(input.Identity.DeviceID + "\x00" + input.IdentityProof.Nonce)
		if _, exists := state.Nonces[nonceKey]; exists {
			return dirty, failure(409, "proof_replay_detected")
		}
		if len(state.Nonces) >= maxNonceRecords {
			return dirty, &protocolError{429, "issuer_capacity_exceeded", 60}
		}
		grant := *state.CurrentGrant
		status = 200
		if path == AutoRenewPath {
			window := grant.ExpiresAt.Sub(grant.NotBefore) / 5
			if window > 24*time.Hour {
				window = 24 * time.Hour
			}
			eligibleAt := grant.ExpiresAt.Add(-window)
			if now.Before(eligibleAt) {
				// A valid early attempt must remain retryable with the exact proof
				// and key after Retry-After. Only successful eligibility consumes it.
				return dirty, &protocolError{429, "renewal_not_yet_eligible", int(math.Ceil(eligibleAt.Sub(now).Seconds()))}
			}
			ttl := authorizationBoundedTTL(time.Duration(state.TTLSeconds)*time.Second, state.Authorization.ExpiresAt, now)
			if ttl < time.Second || !now.Add(ttl).After(grant.ExpiresAt) {
				return dirty, &protocolError{429, "renewal_not_yet_eligible", max(1, int(math.Ceil(state.Authorization.ExpiresAt.Sub(now).Seconds())))}
			}
			state.Nonces[nonceKey] = input.IdentityProof.IssuedAt.Add(proofFreshness + time.Second)
			var err error
			grant, err = i.signGrantAt(ttl, now, state.CurrentGrant.RevocationEpoch)
			if err != nil {
				return true, err
			}
			state.CurrentGrant = &grant
			status = 201
		} else {
			state.Nonces[nonceKey] = input.IdentityProof.IssuedAt.Add(proofFreshness + time.Second)
		}
		var err error
		response, err = json.Marshal(GrantResponse{Data: DeviceRecord{DomainID: i.subject.DomainID, DeviceID: i.subject.DeviceID, Status: "active", GrantID: grant.GrantID}, Grant: grant})
		if err != nil {
			return true, err
		}
		record := idempotencyRecord{BodySHA256: bodyHash, Status: status, Response: response}
		if path == CurrentGrantPath {
			record.ExpiresAt = now.Add(proofFreshness)
		} else if state.SchemaVersion == 2 {
			// Bound permanent-authorization history. After seven days both the
			// old Grant and its proof are expired, so pruning cannot mint it again.
			record.ExpiresAt = grant.ExpiresAt.Add(7 * 24 * time.Hour)
		}
		state.Idempotency[cacheKey] = record
		return true, nil
	})
	return status, response, err
}

func authorizationBoundedTTL(policyTTL time.Duration, deadline, now time.Time) time.Duration {
	if deadline.IsZero() {
		return policyTTL
	}
	remaining := deadline.Sub(now).Truncate(time.Second)
	if remaining < policyTTL {
		return remaining
	}
	return policyTTL
}

func (i *Issuer) verifyDeviceProof(path, key string, input RenewalRequest, now time.Time) error {
	stored := i.subject
	if path == CurrentGrantPath && input.Identity.DeviceID == i.audience.DeviceID {
		stored = i.audience
	}
	if input.Identity.DeviceID != stored.DeviceID || input.Identity.DomainID != stored.DomainID || input.Identity.Type != stored.Type {
		return failure(401, "device_proof_invalid")
	}
	if input.Identity.PublicKey != stored.PublicKey {
		return failure(409, "renewal_identity_conflict")
	}
	proof := input.IdentityProof
	if proof.Nonce == "" || len(proof.Nonce) > 256 || proof.Signature.Alg != "Ed25519" {
		return failure(401, "device_proof_invalid")
	}
	if identity.VerifyProof(iscpcrypto.NewProvider(), stored, proof, i.relayID, key, now, proofFreshness) != nil {
		return failure(401, "device_proof_invalid")
	}
	return nil
}
