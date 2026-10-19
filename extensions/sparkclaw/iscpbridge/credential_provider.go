package iscpbridge

import (
	"context"
	"time"
)

// Credential, Relay ownership, and local connection generations are distinct
// domains. The provider owns recovery and persistence; it never writes a socket.
type CredentialGeneration string
type RelayOwnerGeneration string
type ConnectionEpoch uint64

type CredentialBinding struct {
	DomainID, DeviceID, ResourceBindingID, TargetServiceID string
	IssuerPublicKey, RelayPublicKey, TLSCertificateSHA256  string
}
type CredentialLease struct {
	Binding               CredentialBinding
	Enrollment            EnrollmentBundle
	CredentialGeneration  CredentialGeneration
	AuthorizationRevision string
	ExpiresAt             time.Time
	StateVersion          uint64
}
type CredentialInvalidationReason string

const (
	AuthenticationRequired CredentialInvalidationReason = "authentication_required"
	AccessRejected         CredentialInvalidationReason = "access_rejected"
	RotationRequired       CredentialInvalidationReason = "rotation_required"
)

type CredentialEventReason string

const (
	CredentialRotated   CredentialEventReason = "rotated"
	CredentialRecovered CredentialEventReason = "recovered"
	CredentialRevoked   CredentialEventReason = "revoked"
	IdentityChanged     CredentialEventReason = "identity_changed"
	ScopeChanged        CredentialEventReason = "scope_changed"
)

type CredentialEvent struct {
	Binding               CredentialBinding
	CredentialGeneration  CredentialGeneration
	AuthorizationRevision string
	StateVersion          uint64
	Reason                CredentialEventReason
	Lease                 *CredentialLease // nil for terminal authority states
}

type CredentialProvider interface {
	// ctx controls this waiter, not the shared provider recovery flight.
	EnsureAccess(ctx context.Context, binding CredentialBinding) (CredentialLease, error)
	// Invalidate performs a local compare-and-mark. A stale generation is a no-op;
	// it never revokes standing authority or deletes an unresolved control intent.
	Invalidate(binding CredentialBinding, expected CredentialGeneration, reason CredentialInvalidationReason) error
	// Subscribe publishes the current verified state when one exists, then ordered
	// changes. With no verified state it waits for the first verified lease/event;
	// ordinary recovery pending is never reported as revoked. ctx ends only this
	// subscription. Delivery must not block recovery.
	Subscribe(ctx context.Context, binding CredentialBinding) <-chan CredentialEvent
	// Close is the provider owner’s shutdown, the only caller cancellation that
	// ends all shared recovery work. It does not remove persisted identity/intent.
	Close() error
}
