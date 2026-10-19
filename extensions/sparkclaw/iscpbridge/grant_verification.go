package iscpbridge

import (
	"bytes"
	"encoding/json"
	"errors"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"slices"
	"time"
)

// These authorization checks are extracted unchanged from SparkClaw managed_lifecycle.go.
func verifyGrantContinuity(provider iscpcrypto.Provider, grant, previous trust.Grant, issuer identity.DeviceIdentity, relayID string, now time.Time, requireExtension bool) error {
	if err := verifyGrantSnapshot(provider, previous, issuer, relayID); err != nil {
		return err
	}
	if err := verifyGrantPairingBounds(grant, previous); err != nil {
		return err
	}
	if grant.Issuer != issuer.DeviceID || grant.Signature.Alg != "Ed25519" || grant.Signature.KID != issuer.PublicKey.KID || grant.GrantID == "" ||
		!slices.Equal(grant.Permissions, previous.Permissions) || !slices.Equal(grant.RelayConstraints, previous.RelayConstraints) || grant.RevocationEpoch < previous.RevocationEpoch {
		return errors.New("renewed Trust Grant changes the authorized scope, signer or revocation epoch")
	}
	if grant.ExpiresAt.Before(previous.ExpiresAt) || (requireExtension && !grant.ExpiresAt.After(previous.ExpiresAt)) ||
		grant.ExpiresAt.Sub(grant.NotBefore) <= 0 || grant.ExpiresAt.Sub(grant.NotBefore) > previous.ExpiresAt.Sub(previous.NotBefore) {
		return errors.New("renewed Trust Grant exceeds or rolls back the authorized lifetime")
	}
	if !requireExtension && grant.ExpiresAt.Equal(previous.ExpiresAt) {
		actual, _ := json.Marshal(grant)
		baseline, _ := json.Marshal(previous)
		if !bytes.Equal(actual, baseline) {
			return errors.New("current Trust Grant changes authorization without extending its lifetime")
		}
	}
	if err := trust.VerifyGrant(provider, grant, issuer, trust.VerifyOptions{Audience: previous.Audience, SubjectDeviceID: previous.SubjectDeviceID,
		ConfirmationThumbprint: previous.ConfirmationThumbprint, Permission: previous.Permissions[0], RelayID: relayID, CurrentRevocationEpoch: previous.RevocationEpoch, Now: now}); err != nil {
		return errors.New("renewed Trust Grant verification failed")
	}
	return nil
}

func verifyGrantSnapshot(provider iscpcrypto.Provider, grant trust.Grant, issuer identity.DeviceIdentity, relayID string) error {
	if grant.GrantID == "" || grant.Issuer != issuer.DeviceID || grant.Signature.Alg != "Ed25519" || grant.Signature.KID != issuer.PublicKey.KID ||
		grant.SubjectDeviceID == "" || grant.Audience == "" || grant.ConfirmationThumbprint == "" || len(grant.Permissions) == 0 || !grant.ExpiresAt.After(grant.NotBefore) {
		return errors.New("previous Trust Grant snapshot is invalid")
	}
	if err := trust.VerifyGrant(provider, grant, issuer, trust.VerifyOptions{Audience: grant.Audience, SubjectDeviceID: grant.SubjectDeviceID,
		ConfirmationThumbprint: grant.ConfirmationThumbprint, Permission: grant.Permissions[0], RelayID: relayID, CurrentRevocationEpoch: grant.RevocationEpoch, Now: grant.NotBefore}); err != nil {
		return errors.New("previous Trust Grant snapshot signature is invalid")
	}
	return nil
}

func verifyGrantPairingBounds(grant, previous trust.Grant) error {
	if grant.Audience != previous.Audience || grant.SubjectDeviceID != previous.SubjectDeviceID || grant.ConfirmationThumbprint != previous.ConfirmationThumbprint {
		return errors.New("renewed Trust Grant deviates from the authorized pairing")
	}
	for _, permission := range grant.Permissions {
		if !slices.Contains(previous.Permissions, permission) {
			return errors.New("renewed Trust Grant widens the authorized permissions")
		}
	}
	return nil
}

func GrantRenewalWindow(grant trust.Grant) time.Duration {
	ttl := grant.ExpiresAt.Sub(grant.NotBefore)
	window := ttl / 5
	if window > 24*time.Hour {
		window = 24 * time.Hour
	}
	if window <= 0 {
		window = time.Hour
	}
	return window
}

func VerifyGrantRenewal(provider iscpcrypto.Provider, grant, previous trust.Grant, issuer identity.DeviceIdentity, relayID string, now time.Time) error {
	return verifyGrantContinuity(provider, grant, previous, issuer, relayID, now, true)
}
