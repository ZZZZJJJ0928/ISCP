package iscplocalissuer

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

// AuthorizePermanentRenewal is an explicit setup/migration action, never a
// startup or device request. Revoked records cannot be resurrected by migration.
func (i *Issuer) AuthorizePermanentRenewal(grantFile string) error {
	return i.AuthorizePermanentScopes(grantFile, nil)
}

// AuthorizePermanentScopes is an explicit operator action; renewals cannot add
// scopes. Existing authorizations need a new revision/regrant to change scope.
func (i *Issuer) AuthorizePermanentScopes(grantFile string, scopes []string) error {
	if err := iscpauth.ValidateScopes(scopes); err != nil {
		return err
	}
	scopes = slices.Clone(scopes)
	slices.Sort(scopes)
	raw, err := readPrivateBounded(grantFile, 65536)
	if err != nil {
		return errors.New("authorization grant file unavailable")
	}
	var grant trust.Grant
	if decode(raw, &grant) != nil {
		return errors.New("invalid authorization grant")
	}
	ttl, err := i.validateGrant(grant)
	if err != nil {
		return err
	}
	return i.withRenewalState(func(state *renewalState) (bool, error) {
		if state.Authorization != nil && state.Authorization.Revoked {
			return false, errors.New("revoked authorization cannot be migrated or restored")
		}
		if state.CurrentGrant != nil && state.CurrentGrant.Signature.Value != grant.Signature.Value {
			return false, errors.New("authorization grant is not the current grant")
		}
		if state.SchemaVersion == 2 {
			if scopes != nil && !slices.Equal(scopes, state.Authorization.Scopes) {
				return false, errors.New("changing scopes requires explicit reauthorization")
			}
			return false, nil
		}
		// Preserve the TTL visible in the current signed Grant. A bounded
		// policy may have shortened its last Grant; increasing it here would
		// break the client's signed continuity fence on the next renewal.
		// Migrate old bounded-policy receipts too; they previously had no
		// expiry because their authorization deadline bounded retention.
		for key, record := range state.Idempotency {
			if record.Status == 201 && record.ExpiresAt.IsZero() {
				var cached GrantResponse
				if decode(record.Response, &cached) != nil {
					return false, errors.New("invalid renewal receipt")
				}
				if _, err := i.validateGrant(cached.Grant); err != nil {
					return false, err
				}
				record.ExpiresAt = cached.Grant.ExpiresAt.Add(7 * 24 * time.Hour)
				state.Idempotency[key] = record
			}
		}
		state.SchemaVersion, state.CurrentGrant, state.TTLSeconds = 2, &grant, ttl
		state.Authorization = &renewalAuthorization{AuthorizedAt: i.Now().UTC(), Lifetime: iscpauth.UntilRevoked, Revision: grant.RevocationEpoch, Scopes: scopes}
		return true, nil
	})
}

func (state *renewalState) policy(now time.Time) iscpauth.Policy {
	a := state.Authorization
	p := iscpauth.Policy{Version: state.SchemaVersion, Lifetime: iscpauth.Bounded, State: iscpauth.Active, ExpiresAt: a.ExpiresAt, Revision: a.Revision, Scopes: slices.Clone(a.Scopes)}
	if state.SchemaVersion == 2 {
		p.Lifetime = a.Lifetime
	}
	if a.Revoked {
		p.State = iscpauth.Revoked
	} else if !a.ExpiresAt.IsZero() && !now.Before(a.ExpiresAt) {
		p.State = iscpauth.Expired
	}
	return p
}

// Status is proof-bound, read-only and available after revocation. A Relay or
// unsigned HTTP error cannot invent a revocation, and a recorded active status
// cannot answer a fresh challenge after authorization was deleted.
func (i *Issuer) authorizationStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		writeProtocolError(w, failure(405, "method_not_allowed"))
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if !validIdempotencyKey(key) {
		writeProtocolError(w, failure(400, "idempotency_key_required"))
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
	var input RenewalRequest
	if err != nil || decode(raw, &input) != nil {
		writeProtocolError(w, failure(400, "invalid_request"))
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.Now().UTC()
	if err = i.verifyDeviceProof(CurrentGrantPath, key, input, now); err != nil {
		writeProtocolError(w, err)
		return
	}
	state, err := i.readRenewalState()
	if err != nil {
		writeProtocolError(w, err)
		return
	}
	if state.Authorization == nil || state.SchemaVersion != 2 {
		writeProtocolError(w, failure(404, "standing_authorization_not_found"))
		return
	}
	cap := i.capabilityBody(state, now)
	cap.Metadata["request_id"], cap.Metadata["request_digest"], cap.Metadata["request_device_id"] = key, hashBytes(raw), input.Identity.DeviceID
	// A status statement remains verifiable after deletion and cannot issue a Grant.
	cap.ExpiresAt = now.Add(time.Minute)
	signed, err := descriptor.Sign(iscpcrypto.NewProvider(), i.device, trustRootDescriptorType, cap, now)
	if err != nil {
		writeProtocolError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(signed)
}
