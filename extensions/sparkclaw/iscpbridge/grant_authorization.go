package iscpbridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	iscpconfig "github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

// RequireStandingAuthorization pins the new policy before any network access.
// New permanent-authorization profiles must set this on every process start.
func (c *GrantLifecycleClient) RequireStandingAuthorization() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.standing = true
}

func (c *GrantLifecycleClient) UsesStandingAuthorization() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.standing
}

// ErrAuthorizationRevoked is returned only after authenticating an issuer
// statement bound to a fresh possession proof. HTTP errors cannot set it.
var ErrAuthorizationRevoked = errors.New("standing authorization was revoked")

// AuthorizationPolicy authenticates a fresh issuer statement and returns a
// detached permission projection. Callers must never accept scopes from peers.
func (c *GrantLifecycleClient) AuthorizationPolicy(ctx context.Context) (iscpauth.Policy, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cap, err := c.capability(ctx, c.previous)
	if err != nil {
		return iscpauth.Policy{}, err
	}
	return iscpauth.Parse(cap.Metadata)
}

func (c *GrantLifecycleClient) CheckAuthorization(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.capability(ctx, c.previous)
	return err
}

func (c *GrantLifecycleClient) capability(ctx context.Context, previous trust.Grant) (descriptor.TrustRootDescriptor, error) {
	var cap descriptor.TrustRootDescriptor
	if c.revoked {
		return cap, ErrAuthorizationRevoked
	}
	if c.standing {
		return c.authorizationStatus(ctx, previous)
	}
	raw, err := c.request(ctx, http.MethodGet, "/v1/renewal-capability", "", nil)
	if err != nil {
		return cap, err
	}
	cap, policy, err := c.verifyCapability(raw, previous)
	if err != nil {
		return cap, err
	}
	if policy.Version == 2 {
		c.standing = true
		return c.authorizationStatus(ctx, previous)
	}
	if policy.State != iscpauth.Active || !time.Now().UTC().Before(policy.ExpiresAt) || cap.ExpiresAt.After(policy.ExpiresAt) {
		return cap, errors.New("Grant renewal capability authorization expiry mismatch")
	}
	return cap, nil
}

func (c *GrantLifecycleClient) authorizationStatus(ctx context.Context, previous trust.Grant) (descriptor.TrustRootDescriptor, error) {
	var cap descriptor.TrustRootDescriptor
	key, body, err := c.newRequest()
	if err != nil {
		return cap, err
	}
	raw, err := c.request(ctx, http.MethodPost, iscpauth.StatusPath, key, body)
	if err != nil {
		return cap, err
	}
	cap, policy, err := c.verifyCapability(raw, previous)
	if err != nil {
		return cap, err
	}
	digest := sha256.Sum256(body)
	if policy.Version != 2 || policy.Lifetime != iscpauth.UntilRevoked ||
		cap.Metadata["request_id"] != key || cap.Metadata["request_digest"] != hex.EncodeToString(digest[:]) ||
		cap.Metadata["request_device_id"] != c.device.Identity.DeviceID || cap.ExpiresAt.Sub(cap.IssuedAt) > time.Minute || policy.Revision < previous.RevocationEpoch {
		return cap, errors.New("standing authorization challenge or revision mismatch")
	}
	if policy.State == iscpauth.Revoked && policy.Revision > previous.RevocationEpoch {
		c.revoked = true
		return cap, ErrAuthorizationRevoked
	}
	if policy.State != iscpauth.Active || policy.Revision != previous.RevocationEpoch {
		return cap, errors.New("standing authorization is not active for this Grant")
	}
	return cap, nil
}

func (c *GrantLifecycleClient) verifyCapability(raw []byte, previous trust.Grant) (descriptor.TrustRootDescriptor, iscpauth.Policy, error) {
	var cap descriptor.TrustRootDescriptor
	var policy iscpauth.Policy
	var signed descriptor.SignedDescriptor
	if strictUnmarshal(raw, &signed) != nil || strictUnmarshal(signed.Descriptor, &cap) != nil {
		return cap, policy, errors.New("invalid Grant renewal capability descriptor")
	}
	now := time.Now().UTC()
	if signed.Type != descriptor.TypeSignedDescriptor || signed.DescriptorType != "iscp.trust_root.descriptor.v2" || cap.Type != signed.DescriptorType ||
		signed.SignedBy != c.issuer.DeviceID || signed.Signature.Alg != "Ed25519" || signed.Signature.KID != c.issuer.PublicKey.KID ||
		cap.TrustRootID != c.issuer.DeviceID || cap.DomainID != c.issuer.DomainID || cap.IssuedAt.After(now.Add(time.Second)) || !now.Before(cap.ExpiresAt) ||
		!cap.ExpiresAt.After(cap.IssuedAt) || cap.ExpiresAt.Sub(cap.IssuedAt) > 5*time.Minute || signed.SignedAt.Before(cap.IssuedAt) || signed.SignedAt.After(now.Add(time.Second)) {
		return cap, policy, errors.New("Grant renewal capability signer or validity mismatch")
	}
	if len(cap.Keys) != 1 || cap.Keys[0].KTY != "Ed25519" || cap.Keys[0].Use != "descriptor-signature" || cap.Keys[0].KID != c.issuer.PublicKey.KID ||
		cap.Keys[0].Public != c.issuer.PublicKey.Public || (cap.Keys[0].State != "" && cap.Keys[0].State != "active") {
		return cap, policy, errors.New("Grant renewal capability key differs from pinned issuer")
	}
	metadata := cap.Metadata
	if metadata["purpose"] != GrantRenewalCapabilityPurpose || metadata["grant_renewal"] != "true" || metadata["issuer_device_id"] != c.issuer.DeviceID ||
		metadata["relay_id"] != c.relayID || metadata["subject_device_id"] != previous.SubjectDeviceID || metadata["audience_device_id"] != previous.Audience ||
		len(previous.Permissions) != 1 || metadata["permission"] != previous.Permissions[0] {
		return cap, policy, errors.New("Grant renewal capability authorization binding mismatch")
	}
	if descriptor.Verify(c.provider, signed, c.issuer, iscpconfig.DefaultGate(iscpconfig.ProfileProduction), now) != nil {
		return cap, policy, errors.New("Grant renewal capability signature verification failed")
	}
	policy, err := iscpauth.Parse(metadata)
	return cap, policy, err
}
