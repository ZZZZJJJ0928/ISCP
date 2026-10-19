package iscpbridge

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
)

// VerifyRelayDiscovery verifies current signed discovery before a workbench
// connects. HTTPS establishes Relay origin authenticity; the enrollment's
// durable cloud Trust Root pin must still appear as an active grant signer.
// Descriptor content pins rotate with validity timestamps, so they are not
// substituted for that durable trust key.
func VerifyRelayDiscovery(ctx context.Context, bundle EnrollmentBundle) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("Relay discovery redirects are prohibited")
	}}
	return verifyRelayDiscovery(ctx, client, bundle, time.Now().UTC())
}

func verifyRelayDiscovery(ctx context.Context, client *http.Client, bundle EnrollmentBundle, now time.Time) error {
	if err := validateRelayURLs(ProfileProduction, bundle.RelayBaseURL, bundle.RelayWebSocketURL); err != nil {
		return err
	}
	provider := iscpcrypto.NewProvider()
	relay, _, err := fetchVerifiedRelayDescriptor(ctx, client, provider, bundle.RelayBaseURL, ProfileProduction, now)
	if err != nil {
		return errors.New("signed Relay discovery verification failed")
	}
	if relay.Type != "iscp.relay.descriptor.v2" || relay.RelayID != bundle.RelayID || strings.TrimRight(relay.BaseURL, "/") != strings.TrimRight(bundle.RelayBaseURL, "/") || relay.WebSocketURL != bundle.RelayWebSocketURL || !validDescriptorWindow(relay.IssuedAt, relay.ExpiresAt, now) {
		return errors.New("signed Relay descriptor does not match enrolled deployment")
	}
	if err := validateDiscoveryKeys(relay.SigningKeys); err != nil {
		return err
	}
	root, _, err := fetchVerifiedTrustRootDescriptor(ctx, client, provider, bundle.RelayBaseURL, ProfileProduction, now)
	if err != nil {
		return errors.New("signed cloud Trust Root discovery verification failed")
	}
	if root.Type != "iscp.trust_root.descriptor.v2" || root.TrustRootID != bundle.TrustRootIdentity.DeviceID || root.DomainID != bundle.TrustRootIdentity.DomainID || strings.TrimRight(root.BaseURL, "/") != strings.TrimRight(bundle.RelayBaseURL, "/") || !validDescriptorWindow(root.IssuedAt, root.ExpiresAt, now) {
		return errors.New("cloud Trust Root descriptor does not match enrollment")
	}
	if err := validateDiscoveryKeys(root.Keys); err != nil {
		return err
	}
	active, err := trustSignerIdentity(root, bundle.TrustRootIdentity.PublicKey.KID)
	if err != nil || active.PublicKey.Public != bundle.TrustRootIdentity.PublicKey.Public {
		return errors.New("cloud Trust Root active key does not match enrollment pin")
	}
	return nil
}

func validDescriptorWindow(issued, expires, now time.Time) bool {
	return !issued.IsZero() && issued.Before(expires) && !issued.After(now.Add(30*time.Second)) && now.Before(expires)
}

func validateDiscoveryKeys(keys []descriptor.PublicKey) error {
	if len(keys) == 0 || len(keys) > 32 {
		return errors.New("discovery key set is invalid")
	}
	for _, key := range keys {
		pub, err := iscpcrypto.DecodeBase64URL(key.Public)
		// Hosted operator key IDs are symbolic names, not device thumbprints.
		if key.KTY != "Ed25519" || key.KID == "" || len(key.KID) > 200 || err != nil || len(pub) != 32 {
			return errors.New("discovery public key is invalid")
		}
	}
	return nil
}
