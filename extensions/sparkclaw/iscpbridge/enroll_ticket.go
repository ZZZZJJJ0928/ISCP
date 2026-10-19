// Managed provisioning enrollment (ISCP v0.2, spec/provisioning.md): the
// Bridge consumes an iscp.pairing_ticket.v3 issued by the phone's Cloud and
// receives — in one registration call — its official device id, relay
// credentials, and the pre-authorized outbound Trust Grant
// (subject = bridge, audience = inviting phone). This replaces the legacy
// externally-issued enrollment bundle for JingSi-managed deployments.
package iscpbridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	iscpconfig "github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

// enrollmentWrapper mirrors the JingSi/happy transport wrapper: base64url of
// {"version":1,"ticket":<v2>,"ticket_v3":<v3>,"expected_audience_phone_id":
// "...","display_name":"..."}. The Bridge only consumes the v3 ticket — the
// dual-carried v2 exists for pre-v0.2 Happy clients.
type enrollmentWrapper struct {
	Version                 int                           `json:"version"`
	Ticket                  json.RawMessage               `json:"ticket"`
	TicketV3                *provisioning.PairingTicketV3 `json:"ticket_v3"`
	ExpectedAudiencePhoneID string                        `json:"expected_audience_phone_id"`
	DisplayName             string                        `json:"display_name"`
}

// TicketEnrollmentOptions drive one managed enrollment attempt.
type TicketEnrollmentOptions struct {
	// Payload is the QR/deep-link/copy transport string (base64url JSON of
	// the wrapper or a bare v3 ticket), or raw JSON.
	Payload string
	// RelayBaseURL / RelayWebSocketURL / TrustBaseURL target the managed
	// deployment; descriptors are fetched and verified from them.
	RelayBaseURL      string
	RelayWebSocketURL string
	TrustBaseURL      string
	DisplayName       string
	IdentityDirectory string
	KeyBackend        string
	KeyringService    string
	Profile           string
	Timeout           time.Duration
}

// DecodeTicketEnrollmentPayload parses the transport payload into the v3
// ticket plus wrapper hints. A payload that carries only a v2 ticket is
// rejected: the Bridge is a v0.2 client and relies on the signed grant role
// bindings.
func DecodeTicketEnrollmentPayload(payload string) (provisioning.PairingTicketV3, string, string, error) {
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		return provisioning.PairingTicketV3{}, "", "", errors.New("enrollment payload is required")
	}
	raw := []byte(trimmed)
	if !strings.HasPrefix(trimmed, "{") {
		decoded, err := base64.RawURLEncoding.DecodeString(trimmed)
		if err != nil {
			return provisioning.PairingTicketV3{}, "", "", errors.New("enrollment payload is not base64url or JSON")
		}
		raw = decoded
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return provisioning.PairingTicketV3{}, "", "", errors.New("enrollment payload is not a JSON object")
	}
	if _, isWrapper := probe["ticket"]; isWrapper || probe["ticket_v3"] != nil {
		var wrapper enrollmentWrapper
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			return provisioning.PairingTicketV3{}, "", "", errors.New("enrollment wrapper is invalid")
		}
		if wrapper.TicketV3 == nil {
			return provisioning.PairingTicketV3{}, "", "", errors.New("enrollment wrapper carries no v3 ticket; the issuing App predates ISCP v0.2")
		}
		return *wrapper.TicketV3, wrapper.ExpectedAudiencePhoneID, wrapper.DisplayName, nil
	}
	var ticket provisioning.PairingTicketV3
	if err := strictUnmarshal(raw, &ticket); err != nil || ticket.Type != provisioning.TypePairingTicketV3 {
		return provisioning.PairingTicketV3{}, "", "", errors.New("enrollment payload is not an iscp.pairing_ticket.v3")
	}
	return ticket, "", "", nil
}

type signedDescriptorResponse struct {
	Descriptor json.RawMessage `json:"descriptor"`
	Pin        string          `json:"pin"`
}

func fetchSignedDescriptor(ctx context.Context, client *http.Client, baseURL, wellKnownPath string) (descriptor.SignedDescriptor, string, error) {
	endpoint := strings.TrimRight(baseURL, "/") + wellKnownPath
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return descriptor.SignedDescriptor{}, "", errors.New("create descriptor discovery request")
	}
	response, err := client.Do(request)
	if err != nil {
		return descriptor.SignedDescriptor{}, "", fmt.Errorf("descriptor discovery: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, relayMaxBody))
	if err != nil || response.StatusCode != http.StatusOK {
		return descriptor.SignedDescriptor{}, "", fmt.Errorf("descriptor discovery returned HTTP %d", response.StatusCode)
	}
	var wire signedDescriptorResponse
	if err := json.Unmarshal(body, &wire); err != nil || len(wire.Descriptor) == 0 {
		return descriptor.SignedDescriptor{}, "", errors.New("descriptor discovery response is invalid")
	}
	var signed descriptor.SignedDescriptor
	if err := json.Unmarshal(wire.Descriptor, &signed); err != nil {
		return descriptor.SignedDescriptor{}, "", errors.New("signed descriptor is invalid")
	}
	// The pin is computed locally, never taken from the response: a
	// server-supplied pin attests to nothing.
	pin, err := descriptor.Pin(signed)
	if err != nil {
		return descriptor.SignedDescriptor{}, "", errors.New("signed descriptor is not canonicalizable")
	}
	return signed, pin, nil
}

// descriptorSelfSigner builds the verification identity for the key a signed
// descriptor names in its OWN signature.
//
// Trust model, deliberately: relay and trust-root descriptors are self-signed
// and ISCP v0.2's pairing ticket carries no descriptor pins, so verifying one
// cannot establish first-contact authenticity — that rests on TLS to the
// operator-supplied URL, plus the six-digit confirmation code the human
// compares on the phone. Nor is the descriptor pin a durable anchor: it covers
// issued_at/expires_at and therefore rotates on every re-issue.
//
// What verification does buy, and why it is not optional: it rejects a
// descriptor that is expired, rolled back to a retired key set, or truncated
// in transit, and it proves the serving origin holds the private key for a key
// the descriptor lists. The durable anchor after enrollment is separate and
// already in place — EnrollmentBundle.TrustRootIdentity pins the grant signer,
// and every VerifyGrant on session initiation and renewal checks against it.
func descriptorSelfSigner(keys []descriptor.PublicKey, domainID, deviceID, kid string) (identity.DeviceIdentity, error) {
	for _, key := range keys {
		if key.KID != kid || key.KTY != "Ed25519" {
			continue
		}
		if key.State == "revoked" || key.State == "next" {
			continue
		}
		return identity.DeviceIdentity{
			Type:     identity.TypeDeviceIdentity,
			DomainID: domainID,
			DeviceID: deviceID,
			PublicKey: identity.PublicKey{
				KTY: "Ed25519", Use: "identity-signature", KID: key.KID, Public: key.Public,
			},
		}, nil
	}
	return identity.DeviceIdentity{}, errors.New("descriptor is not signed by an active key it declares")
}

// fetchVerifiedRelayDescriptor discovers the relay descriptor and verifies its
// signature and expiry under the profile's gate before any field is trusted.
func fetchVerifiedRelayDescriptor(ctx context.Context, client *http.Client, provider iscpcrypto.Provider, baseURL, profile string, now time.Time) (descriptor.RelayDescriptor, string, error) {
	signed, pin, err := fetchSignedDescriptor(ctx, client, baseURL, "/.well-known/iscp/relay")
	if err != nil {
		return descriptor.RelayDescriptor{}, "", err
	}
	var relayDesc descriptor.RelayDescriptor
	if err := json.Unmarshal(signed.Descriptor, &relayDesc); err != nil {
		return descriptor.RelayDescriptor{}, "", errors.New("relay descriptor is invalid")
	}
	signer, err := descriptorSelfSigner(relayDesc.SigningKeys, relayDesc.DomainID, relayDesc.RelayID, signed.Signature.KID)
	if err != nil {
		return descriptor.RelayDescriptor{}, "", fmt.Errorf("relay %w", err)
	}
	if err := descriptor.Verify(provider, signed, signer, iscpconfig.DefaultGate(iscpconfig.Profile(profile)), now); err != nil {
		return descriptor.RelayDescriptor{}, "", fmt.Errorf("relay descriptor verification failed: %w", err)
	}
	return relayDesc, pin, nil
}

// fetchVerifiedTrustRootDescriptor is the trust-root counterpart.
func fetchVerifiedTrustRootDescriptor(ctx context.Context, client *http.Client, provider iscpcrypto.Provider, baseURL, profile string, now time.Time) (descriptor.TrustRootDescriptor, string, error) {
	signed, pin, err := fetchSignedDescriptor(ctx, client, baseURL, "/.well-known/iscp/trust-root")
	if err != nil {
		return descriptor.TrustRootDescriptor{}, "", err
	}
	var trustDesc descriptor.TrustRootDescriptor
	if err := json.Unmarshal(signed.Descriptor, &trustDesc); err != nil {
		return descriptor.TrustRootDescriptor{}, "", errors.New("trust root descriptor is invalid")
	}
	signer, err := descriptorSelfSigner(trustDesc.Keys, trustDesc.DomainID, trustDesc.TrustRootID, signed.Signature.KID)
	if err != nil {
		return descriptor.TrustRootDescriptor{}, "", fmt.Errorf("trust root %w", err)
	}
	if err := descriptor.Verify(provider, signed, signer, iscpconfig.DefaultGate(iscpconfig.Profile(profile)), now); err != nil {
		return descriptor.TrustRootDescriptor{}, "", fmt.Errorf("trust root descriptor verification failed: %w", err)
	}
	return trustDesc, pin, nil
}

// trustSignerIdentity builds the verification identity for the trust root's
// active grant-signature key matching kid. The identity's domain is the
// trust root's own (a managed multi-tenant root signs from its platform
// domain, distinct from the enrolled device domain).
func trustSignerIdentity(trustDesc descriptor.TrustRootDescriptor, kid string) (identity.DeviceIdentity, error) {
	for _, key := range trustDesc.Keys {
		if key.KID != kid || key.KTY != "Ed25519" {
			continue
		}
		if key.State == "revoked" || key.State == "next" {
			continue
		}
		return identity.DeviceIdentity{
			Type:     identity.TypeDeviceIdentity,
			DomainID: trustDesc.DomainID,
			DeviceID: trustDesc.TrustRootID,
			PublicKey: identity.PublicKey{
				KTY: "Ed25519", Use: "identity-signature", KID: key.KID, Public: key.Public,
			},
		}, nil
	}
	return identity.DeviceIdentity{}, errors.New("ticket is not signed by an active trust root key")
}

type ticketRegistrationResponse struct {
	Data struct {
		DeviceID string `json:"device_id"`
		DomainID string `json:"domain_id"`
	} `json:"data"`
	Access  RelayCredential `json:"access"`
	Refresh RelayCredential `json:"refresh"`
	Grant   trust.Grant     `json:"grant"`
}

// EnrollWithTicket runs the full managed enrollment: decode + verify the v3
// ticket against the discovered descriptors, fail the grant role invariants
// fast (before the one-time ticket is consumed), register with the relay,
// rebuild the identity around the Cloud-assigned official device id, verify
// the returned grant, resolve the phone peer's public identity, and persist
// the managed enrollment bundle.
func EnrollWithTicket(ctx context.Context, opts TicketEnrollmentOptions, enrollmentPath string, log func(string)) (EnrollmentBundle, error) {
	if log == nil {
		log = func(string) {}
	}
	now := time.Now().UTC()
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if err := validateRelayURLs(opts.Profile, opts.RelayBaseURL, opts.RelayWebSocketURL); err != nil {
		return EnrollmentBundle{}, err
	}
	client := &http.Client{Timeout: timeout}
	provider := iscpcrypto.NewProvider()

	ticket, expectedPhone, wrapperName, err := DecodeTicketEnrollmentPayload(opts.Payload)
	if err != nil {
		return EnrollmentBundle{}, err
	}

	// 1. Discover and verify both descriptors (signature + expiry under the
	//    profile gate); the ticket must be bound to exactly this
	//    relay/trust-root pair.
	relayDesc, _, err := fetchVerifiedRelayDescriptor(ctx, client, provider, opts.RelayBaseURL, opts.Profile, now)
	if err != nil {
		return EnrollmentBundle{}, err
	}
	trustBase := strings.TrimSpace(opts.TrustBaseURL)
	if trustBase == "" {
		trustBase = opts.RelayBaseURL
	}
	trustDesc, _, err := fetchVerifiedTrustRootDescriptor(ctx, client, provider, trustBase, opts.Profile, now)
	if err != nil {
		return EnrollmentBundle{}, err
	}
	if ticket.RelayID != relayDesc.RelayID || ticket.TrustRootID != trustDesc.TrustRootID {
		return EnrollmentBundle{}, fmt.Errorf("ticket is bound to relay %q / trust root %q, not this deployment", ticket.RelayID, ticket.TrustRootID)
	}
	signer, err := trustSignerIdentity(trustDesc, ticket.Signature.KID)
	if err != nil {
		return EnrollmentBundle{}, err
	}
	if err := provisioning.VerifyTicketV3(provider, ticket, signer, now); err != nil {
		return EnrollmentBundle{}, fmt.Errorf("pairing ticket verification failed: %w", err)
	}
	if expectedPhone != "" && expectedPhone != ticket.GrantAudience {
		return EnrollmentBundle{}, errors.New("wrapper's expected phone does not match the ticket grant audience")
	}
	log(fmt.Sprintf("Ticket %s verified (domain %s, audience phone %s, expires %s)",
		ticket.TicketID, ticket.DomainID, ticket.GrantAudience, ticket.ExpiresAt.Format(time.RFC3339)))

	// 2. Generate the provisional identity (the Cloud assigns the official
	//    dev_ id at registration; the key pair is final from the start).
	provisionalID := "sparkclaw-bridge-" + newWireID("dev")[4:20]
	_, files, err := GenerateEnrollmentRequestWithKeyBackend(
		opts.IdentityDirectory, ticket.DomainID, provisionalID, "gb10",
		opts.KeyBackend, opts.KeyringService, now,
	)
	if err != nil {
		return EnrollmentBundle{}, err
	}
	device, err := LoadDeviceWithKeyBackend(files.IdentityFile, files.KeyFile, opts.KeyBackend, opts.KeyringService)
	if err != nil {
		return EnrollmentBundle{}, err
	}
	// Audience-reversal fail-fast: reject before the one-time ticket is
	// consumed server-side (ISCP v0.2 grant role invariants).
	if _, err := provisioning.BindGrantRoles(ticket, device.Identity); err != nil {
		return EnrollmentBundle{}, fmt.Errorf("ticket grant role invariants reject this consumer: %w", err)
	}
	thumbprint, err := identity.Thumbprint(device.Identity)
	if err != nil {
		return EnrollmentBundle{}, errors.New("local identity thumbprint is invalid")
	}
	log("Device confirmation code: " + DeviceConfirmationCode(device.Identity.PublicKey.KID))
	log("Compare this code on the phone before approving the invitation.")

	// 3. Consume the ticket: identity + possession proof with
	//    challenge = ticket_id (the Cloud rejects self-reported challenges).
	displayName := strings.TrimSpace(opts.DisplayName)
	if displayName == "" {
		displayName = strings.TrimSpace(wrapperName)
	}
	if displayName == "" {
		displayName = "SparkClaw"
	}
	proof, err := device.CreateProof(provider, ticket.RelayID, ticket.TicketID, randomNonce(), now)
	if err != nil {
		return EnrollmentBundle{}, errors.New("create registration proof")
	}
	registerBody, err := json.Marshal(map[string]any{
		"ticket_v3":      ticket,
		"identity":       device.Identity,
		"identity_proof": proof,
		"display_name":   displayName,
		"metadata": map[string]any{
			"product_kind":      "sparkclaw",
			"runtime_kind":      "sparkclaw",
			"hardware_class":    "gb10",
			"protocol_versions": []string{manifestPayloadType, sparkclawBridgeProtocol},
		},
	})
	if err != nil {
		return EnrollmentBundle{}, errors.New("encode registration request")
	}
	endpoint := strings.TrimRight(opts.RelayBaseURL, "/") + "/v2/relay/devices/register-with-ticket"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(registerBody))
	if err != nil {
		return EnrollmentBundle{}, errors.New("create registration request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", newWireID("enroll"))
	response, err := client.Do(request)
	if err != nil {
		return EnrollmentBundle{}, fmt.Errorf("registration request: %w", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, relayMaxBody))
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return EnrollmentBundle{}, fmt.Errorf("registration failed with HTTP %d: %s", response.StatusCode, summarizeWireError(body))
	}
	var registration ticketRegistrationResponse
	if err := json.Unmarshal(body, &registration); err != nil ||
		registration.Data.DeviceID == "" || registration.Data.DomainID == "" {
		return EnrollmentBundle{}, errors.New("registration response is invalid")
	}
	log(fmt.Sprintf("Registered as official device %s (domain %s)", registration.Data.DeviceID, registration.Data.DomainID))

	// 4. Rebuild the identity around the official ids (same key pair) and
	//    persist it before anything else references the provisional id.
	officialIdentity := device.Identity
	officialIdentity.DeviceID = registration.Data.DeviceID
	officialIdentity.DomainID = registration.Data.DomainID
	if err := SaveDeviceIdentity(files.IdentityFile, officialIdentity); err != nil {
		return EnrollmentBundle{}, fmt.Errorf("persist official identity: %w", err)
	}
	device.Identity = officialIdentity

	// 5. Verify the returned grant before it touches disk: signed by the
	//    active trust root key, subject = official id, confirmation = our
	//    key, audience = the inviting phone, constrained to this relay.
	grantSigner, err := trustSignerIdentity(trustDesc, registration.Grant.Signature.KID)
	if err != nil {
		return EnrollmentBundle{}, err
	}
	permission := ""
	if len(registration.Grant.Permissions) > 0 {
		permission = registration.Grant.Permissions[0]
	}
	if err := trust.VerifyGrant(provider, registration.Grant, grantSigner, trust.VerifyOptions{
		Audience:               ticket.GrantAudience,
		SubjectDeviceID:        device.Identity.DeviceID,
		ConfirmationThumbprint: thumbprint,
		Permission:             permission,
		RelayID:                ticket.RelayID,
		Now:                    now,
	}); err != nil {
		return EnrollmentBundle{}, fmt.Errorf("returned Trust Grant verification failed: %w", err)
	}

	// 6. Resolve the inviting phone's public identity for hello verification
	//    (GET /v2/trust/devices/status, ISCP v0.2 typed response).
	phoneIdentity, err := fetchPeerIdentity(ctx, client, trustBase, registration.Data.DomainID, ticket.GrantAudience)
	if err != nil {
		return EnrollmentBundle{}, fmt.Errorf("resolve inviting phone identity: %w", err)
	}

	bundle := EnrollmentBundle{
		Type:              EnrollmentBundleType,
		Mode:              BundleModeManaged,
		DomainID:          registration.Data.DomainID,
		DeviceID:          registration.Data.DeviceID,
		RelayID:           relayDesc.RelayID,
		RelayBaseURL:      opts.RelayBaseURL,
		RelayWebSocketURL: opts.RelayWebSocketURL,
		TrustRootIdentity: grantSigner,
		Access:            registration.Access,
		Refresh:           registration.Refresh,
		Peers: []PeerAuthorization{{
			Identity:      phoneIdentity,
			OutboundGrant: registration.Grant,
		}},
		IssuedAt:  now,
		ExpiresAt: registration.Grant.ExpiresAt,
	}
	if err := bundle.Validate(now); err != nil {
		return EnrollmentBundle{}, fmt.Errorf("managed bundle validation failed: %w", err)
	}
	if err := SaveEnrollment(enrollmentPath, bundle); err != nil {
		return EnrollmentBundle{}, fmt.Errorf("persist enrollment bundle: %w", err)
	}
	log("Managed enrollment bundle persisted; the Bridge will initiate the session to the phone.")
	return bundle, nil
}

// fetchPeerIdentity resolves a peer's public identity through the trust
// read plane (iscp.trust.device_status.v2).
func fetchPeerIdentity(ctx context.Context, client *http.Client, trustBaseURL, domainID, deviceID string) (identity.DeviceIdentity, error) {
	endpoint := fmt.Sprintf("%s/v2/trust/devices/status?domain_id=%s&device_id=%s",
		strings.TrimRight(trustBaseURL, "/"), domainID, deviceID)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return identity.DeviceIdentity{}, errors.New("create device status request")
	}
	response, err := client.Do(request)
	if err != nil {
		return identity.DeviceIdentity{}, fmt.Errorf("device status request: %w", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, relayMaxBody))
	if response.StatusCode != http.StatusOK {
		return identity.DeviceIdentity{}, fmt.Errorf("device status returned HTTP %d", response.StatusCode)
	}
	var status struct {
		Identity identity.DeviceIdentity `json:"identity"`
		Status   string                  `json:"status"`
	}
	if err := json.Unmarshal(body, &status); err != nil || status.Identity.DeviceID == "" {
		return identity.DeviceIdentity{}, errors.New("device status response is invalid")
	}
	if status.Status == "revoked" || status.Status == "denied" {
		return identity.DeviceIdentity{}, errors.New("inviting phone is revoked")
	}
	return status.Identity, nil
}

func summarizeWireError(body []byte) string {
	var wire struct {
		Error struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &wire) == nil && wire.Error.Reason != "" {
		return wire.Error.Reason
	}
	if len(body) > 200 {
		body = body[:200]
	}
	return string(body)
}

// SaveDeviceIdentity rewrites the persisted public identity (used after the
// Cloud assigns the official device id; the key pair is unchanged).
func SaveDeviceIdentity(path string, id identity.DeviceIdentity) error {
	raw, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return errors.New("encode device identity")
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// DeviceConfirmationCode derives the six-digit out-of-band confirmation code
// the operator compares on the phone before approving the invitation. The
// label is the cross-stack constant shared with JingSi and happy — all three
// display the same code for the same identity key.
func DeviceConfirmationCode(kid string) string {
	digest := iscpcrypto.SHA256([]byte("iscp/happy/device-confirmation\x00" + kid))
	value := binary.BigEndian.Uint32(digest[:4]) % 1_000_000
	return fmt.Sprintf("%06d", value)
}
