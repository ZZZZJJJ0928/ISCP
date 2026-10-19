package iscpbridge

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	iscpconfig "github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
)

// DiscoverNodeRelay verifies the standard signed Relay descriptor against the
// separately pinned Relay signer and IP TLS certificate. An invitation signer
// cannot sign this descriptor and no Cloud TrustRoot endpoint is substituted.
func DiscoverNodeRelay(ctx context.Context, bundle EnrollmentBundle) (descriptor.RelayDescriptor, error) {
	var relay descriptor.RelayDescriptor
	if bundle.Mode != BundleModeWorkbenchNodeManaged || bundle.RelaySignerIdentity == nil || ValidateLocalRelaySigner(*bundle.RelaySignerIdentity) != nil {
		return relay, errors.New("node-managed discovery requires a valid Relay signer pin")
	}
	if err := ValidateNodeRelayURLs(bundle.RelayBaseURL, bundle.RelayWebSocketURL); err != nil {
		return relay, err
	}
	tlsConfig, err := VerifiedTLSConfig(bundle.TLSCertificatePEM)
	if err != nil {
		return relay, err
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("Relay discovery redirects are prohibited")
	}}
	defer client.CloseIdleConnections()
	signed, _, err := fetchSignedDescriptor(ctx, client, bundle.RelayBaseURL, "/.well-known/iscp/relay")
	if err != nil {
		return relay, errors.New("read node-managed Relay discovery")
	}
	if err = strictUnmarshal(signed.Descriptor, &relay); err != nil {
		return relay, errors.New("invalid Relay descriptor")
	}
	now := time.Now().UTC()
	pin := *bundle.RelaySignerIdentity
	if signed.Type != descriptor.TypeSignedDescriptor || signed.DescriptorType != "iscp.relay.descriptor.v2" || relay.Type != signed.DescriptorType || relay.DomainID != bundle.DomainID || relay.RelayID != bundle.RelayID || strings.TrimRight(relay.BaseURL, "/") != strings.TrimRight(bundle.RelayBaseURL, "/") || relay.WebSocketURL != bundle.RelayWebSocketURL || !validDescriptorWindow(relay.IssuedAt, relay.ExpiresAt, now) || signed.SignedBy != pin.DeviceID || signed.Signature.KID != pin.PublicKey.KID || signed.Signature.Alg != "Ed25519" {
		return relay, errors.New("Relay descriptor origin or authority mismatch")
	}
	if err := validateDiscoveryKeys(relay.SigningKeys); err != nil {
		return relay, err
	}
	active, err := descriptorSelfSigner(relay.SigningKeys, bundle.DomainID, signed.SignedBy, signed.Signature.KID)
	if err != nil || active.PublicKey.Public != pin.PublicKey.Public {
		return relay, errors.New("Relay descriptor key does not match pin")
	}
	if err := descriptor.Verify(iscpcrypto.NewProvider(), signed, pin, iscpconfig.DefaultGate(iscpconfig.ProfileProduction), now); err != nil {
		return relay, errors.New("Relay descriptor signature verification failed")
	}
	return relay, nil
}
