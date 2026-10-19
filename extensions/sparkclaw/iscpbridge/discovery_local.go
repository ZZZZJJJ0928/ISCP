package iscpbridge

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	iscpconfig "github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func VerifyWorkbenchRelayDiscovery(ctx context.Context, profile string, bundle EnrollmentBundle) error {
	if (profile == "" || profile == ProfileProduction) && bundle.Mode == BundleModeWorkbenchNodeManaged {
		_, err := DiscoverNodeRelay(ctx, bundle)
		return err
	}
	if profile == "" || profile == ProfileProduction {
		return VerifyRelayDiscovery(ctx, bundle)
	}
	if profile != ProfileLocalLab || bundle.Mode != BundleModeWorkbenchLocalLab || bundle.RelaySignerIdentity == nil {
		return errors.New("local-lab discovery requires reference enrollment and signer pin")
	}
	if err := ValidateWorkbenchRelayURLs(profile, bundle.RelayBaseURL, bundle.RelayWebSocketURL); err != nil {
		return err
	}
	_, _, err := DiscoverLocalRelay(ctx, bundle.RelayBaseURL, bundle.RelayID, bundle.DomainID, bundle.RelaySignerIdentity)
	return err
}

// DiscoverLocalRelay is restricted to the isolated local reference service.
// Both advertised and runtime addresses are confined to known local aliases;
// signed Relay/domain IDs and the private enrollment's durable signer pin bind
// host-published and Docker-internal addresses to the same actual Relay.
func DiscoverLocalRelay(ctx context.Context, baseURL, relayID, domainID string, pinned *identity.DeviceIdentity) (descriptor.RelayDescriptor, identity.DeviceIdentity, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ws, err := LocalRelayWebSocketURL(baseURL)
	if err != nil {
		return descriptor.RelayDescriptor{}, identity.DeviceIdentity{}, err
	}
	if err := ValidateWorkbenchRelayURLs(ProfileLocalLab, baseURL, ws); err != nil {
		return descriptor.RelayDescriptor{}, identity.DeviceIdentity{}, err
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("local Relay discovery redirects are prohibited")
	}}
	defer client.CloseIdleConnections()
	signed, _, err := fetchSignedDescriptor(ctx, client, baseURL, "/.well-known/iscp/relay")
	if err != nil {
		return descriptor.RelayDescriptor{}, identity.DeviceIdentity{}, errors.New("read local reference Relay discovery")
	}
	return verifyLocalRelayDescriptor(signed, relayID, domainID, pinned, time.Now().UTC())
}

func verifyLocalRelayDescriptor(signed descriptor.SignedDescriptor, relayID, domainID string, pinned *identity.DeviceIdentity, now time.Time) (descriptor.RelayDescriptor, identity.DeviceIdentity, error) {
	var relay descriptor.RelayDescriptor
	if err := strictUnmarshal(signed.Descriptor, &relay); err != nil {
		return relay, identity.DeviceIdentity{}, errors.New("invalid local Relay descriptor")
	}
	if signed.Type != descriptor.TypeSignedDescriptor || signed.DescriptorType != "iscp.relay.descriptor.v2" || signed.Signature.Alg != "Ed25519" || signed.Signature.Value == "" || signed.SignedBy == "" || relay.Type != signed.DescriptorType || relay.RelayID != relayID || relay.DomainID != domainID || !validDescriptorWindow(relay.IssuedAt, relay.ExpiresAt, now) {
		return relay, identity.DeviceIdentity{}, errors.New("local Relay descriptor identity, signature or validity mismatch")
	}
	if err := ValidateWorkbenchRelayURLs(ProfileLocalLab, relay.BaseURL, relay.WebSocketURL); err != nil {
		return relay, identity.DeviceIdentity{}, errors.New("local Relay advertises an unauthorized endpoint")
	}
	if err := validateDiscoveryKeys(relay.SigningKeys); err != nil {
		return relay, identity.DeviceIdentity{}, err
	}
	signer, err := descriptorSelfSigner(relay.SigningKeys, relay.DomainID, signed.SignedBy, signed.Signature.KID)
	if err != nil {
		return relay, identity.DeviceIdentity{}, errors.New("local Relay descriptor has no active signer")
	}
	if err := ValidateLocalRelaySigner(signer); err != nil {
		return relay, signer, err
	}
	if pinned != nil && (pinned.DomainID != signer.DomainID || pinned.DeviceID != signer.DeviceID || pinned.PublicKey.KID != signer.PublicKey.KID || pinned.PublicKey.Public != signer.PublicKey.Public) {
		return relay, signer, errors.New("local Relay signer changed; prepare a fresh isolated lab")
	}
	if err := descriptor.Verify(iscpcrypto.NewProvider(), signed, signer, iscpconfig.DefaultGate(iscpconfig.ProfileProduction), now); err != nil {
		return relay, signer, errors.New("local Relay descriptor signature verification failed")
	}
	return relay, signer, nil
}

func ValidateLocalRelaySigner(signer identity.DeviceIdentity) error {
	pub, err := iscpcrypto.DecodeBase64URL(signer.PublicKey.Public)
	if signer.Type != identity.TypeDeviceIdentity || signer.DomainID == "" || signer.DeviceID == "" || signer.PublicKey.KTY != "Ed25519" || signer.PublicKey.Use != "identity-signature" || err != nil || len(pub) != 32 || signer.PublicKey.KID != iscpcrypto.Thumbprint("Ed25519", pub) {
		return errors.New("local reference Relay signer pin is invalid")
	}
	return nil
}

func LocalRelayWebSocketURL(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", errors.New("invalid local Relay URL")
	}
	u.Scheme = "ws"
	u.Path = "/v2/relay/duplex"
	ws := u.String()
	if err := ValidateWorkbenchRelayURLs(ProfileLocalLab, baseURL, ws); err != nil {
		return "", err
	}
	return ws, nil
}
