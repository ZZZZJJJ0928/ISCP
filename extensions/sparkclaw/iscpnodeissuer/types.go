// Package iscpnodeissuer provides the node-owned enrollment authority. Relay
// transport authority and the Gateway's Owner/Client store remain independent.
package iscpnodeissuer

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

const (
	CredentialPrefix   = "sparkclaw-iscp-connect-v1."
	CredentialType     = "sparkclaw.iscp.connection.v1"
	ExchangePath       = "/api/sparkclaw/iscp-control/v1/exchange"
	Permission         = "sparkclaw.workbench.v1"
	MaxCredentialBytes = 48 << 10
	MaxFrameBytes      = 128 << 10
	NodeBundleMode     = "workbench-node-managed"
)

var ErrInvalid = errors.New("invalid enrollment input")
var ErrDenied = errors.New("enrollment denied")
var ErrConflict = errors.New("operation binding conflict")
var ErrExpired = errors.New("enrollment authority expired or consumed")
var ErrUnavailable = errors.New("issuer temporarily unavailable; retry the same operation")
var ErrUnknownOutcome = errors.New("operation outcome unknown; reconciliation required")
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)

type Credential struct {
	SchemaVersion            int                     `json:"schema_version"`
	Type                     string                  `json:"type"`
	Origin                   string                  `json:"origin"`
	TLSCertificatePEM        string                  `json:"tls_certificate_pem"`
	DomainID                 string                  `json:"domain_id"`
	RelayID                  string                  `json:"relay_id"`
	RelaySignerIdentity      identity.DeviceIdentity `json:"relay_signer_identity"`
	IssuerIdentity           identity.DeviceIdentity `json:"issuer_identity"`
	InvitationSignerIdentity identity.DeviceIdentity `json:"invitation_signer_identity"`
	IssuerRoute              string                  `json:"issuer_route"`
	ResponderIdentity        identity.DeviceIdentity `json:"responder_identity"`
	DeploymentID             string                  `json:"deployment_id"`
	OwnerID                  string                  `json:"owner_id"`
	ClientID                 string                  `json:"client_id"`
	InvitationID             string                  `json:"invitation_id"`
	IssuedAt                 time.Time               `json:"issued_at"`
	ExpiresAt                time.Time               `json:"expires_at"`
	Scopes                   []string                `json:"scopes"`
	BootstrapSecret          string                  `json:"bootstrap_secret"`
	Signature                identity.Signature      `json:"signature"`
}

func StrictDecode(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > MaxFrameBytes {
		return ErrInvalid
	}
	if _, err := canonical.ParseStrict(raw); err != nil {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return ErrInvalid
	}
	return nil
}
func Canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return canonical.Marshal(b)
}
func Digest(v any) string {
	b, e := Canonical(v)
	if e != nil {
		return ""
	}
	return c.Base64URL(c.SHA256(b))
}
func ValidateIdentity(id identity.DeviceIdentity) error {
	b, e := base64.RawURLEncoding.Strict().DecodeString(id.PublicKey.Public)
	if e != nil || len(b) != 32 || c.Base64URL(b) != id.PublicKey.Public || id.Type != identity.TypeDeviceIdentity || !identifier.MatchString(id.DomainID) || !identifier.MatchString(id.DeviceID) || id.PublicKey.KTY != "Ed25519" || id.PublicKey.Use != "identity-signature" || id.PublicKey.KID != c.Thumbprint("Ed25519", b) {
		return ErrInvalid
	}
	return nil
}
func (v Credential) signingInput() ([]byte, error) {
	raw, _ := json.Marshal(v)
	obj, _ := canonical.ParseStrict(raw)
	m := obj.(map[string]any)
	secret, e := base64.RawURLEncoding.Strict().DecodeString(v.BootstrapSecret)
	if e != nil || len(secret) != 32 || c.Base64URL(secret) != v.BootstrapSecret {
		return nil, ErrInvalid
	}
	delete(m, "bootstrap_secret")
	delete(m, "signature")
	m["bootstrap_secret_hash"] = c.Base64URL(c.SHA256(secret))
	b, e := canonical.MarshalValue(m)
	return append([]byte("SPARKCLAW-ISCP-CONNECTION-V1\x00"), b...), e
}
func SignCredential(v Credential, signer identity.Device) (Credential, error) {
	v.Type = CredentialType
	v.SchemaVersion = 1
	v.Signature = identity.Signature{}
	if v.InvitationSignerIdentity.PublicKey.KID != signer.Identity.PublicKey.KID {
		return Credential{}, ErrInvalid
	}
	b, e := v.signingInput()
	if e != nil {
		return Credential{}, e
	}
	v.Signature = identity.Signature{Alg: "Ed25519", KID: signer.Identity.PublicKey.KID, Value: c.Base64URL(c.NewProvider().Sign(signer.Private, b))}
	return v, nil
}
func (v Credential) Validate(now time.Time, allowExpired bool) error {
	if e := ValidateOrigin(v.Origin, v.TLSCertificatePEM, now, allowExpired); e != nil {
		return e
	}
	if v.Type != CredentialType || v.SchemaVersion != 1 || !v.ExpiresAt.After(v.IssuedAt) || v.ExpiresAt.Sub(v.IssuedAt) > 30*time.Minute || v.IssuedAt.After(now.Add(time.Minute)) {
		return ErrInvalid
	}
	if !allowExpired && !now.Before(v.ExpiresAt) {
		return ErrExpired
	}
	for _, s := range []string{v.DomainID, v.RelayID, v.IssuerRoute, v.DeploymentID, v.OwnerID, v.ClientID, v.InvitationID} {
		if !identifier.MatchString(s) {
			return ErrInvalid
		}
	}
	for _, id := range []identity.DeviceIdentity{v.RelaySignerIdentity, v.IssuerIdentity, v.InvitationSignerIdentity, v.ResponderIdentity} {
		if ValidateIdentity(id) != nil || id.DomainID != v.DomainID {
			return ErrInvalid
		}
	}
	if len(v.Scopes) == 0 || len(v.Scopes) > 32 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, s := range v.Scopes {
		if !identifier.MatchString(s) || seen[s] {
			return ErrInvalid
		}
		seen[s] = true
	}
	b, e := v.signingInput()
	if e != nil {
		return e
	}
	pubraw, _ := c.DecodeBase64URL(v.InvitationSignerIdentity.PublicKey.Public)
	pub, _ := c.Ed25519PublicKeyFromBytes(pubraw)
	sig, e := c.DecodeBase64URL(v.Signature.Value)
	if e != nil || len(sig) != 64 || v.Signature.Alg != "Ed25519" || v.Signature.KID != v.InvitationSignerIdentity.PublicKey.KID || !c.NewProvider().Verify(pub, b, sig) {
		return ErrDenied
	}
	return nil
}
func EncodeCredential(v Credential) (string, error) {
	b, e := json.Marshal(v)
	if e != nil || len(b) > MaxCredentialBytes {
		return "", ErrInvalid
	}
	return CredentialPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}
func ParseCredential(s string, now time.Time, allowExpired bool) (Credential, error) {
	var v Credential
	if !strings.HasPrefix(s, CredentialPrefix) || len(s) > len(CredentialPrefix)+(MaxCredentialBytes*4+2)/3 {
		return v, ErrInvalid
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(s, CredentialPrefix))
	if e != nil || base64.RawURLEncoding.EncodeToString(raw) != strings.TrimPrefix(s, CredentialPrefix) || len(raw) > MaxCredentialBytes || StrictDecode(raw, &v) != nil {
		return v, ErrInvalid
	}
	return v, v.Validate(now, allowExpired)
}

type Binding struct {
	DeploymentID string `json:"deployment_id"`
	OwnerID      string `json:"owner_id"`
	ClientID     string `json:"client_id"`
}
type Exchange struct {
	Version      int             `json:"version"`
	IssuerRoute  string          `json:"issuer_route"`
	OperationID  string          `json:"operation_id"`
	InvitationID string          `json:"invitation_id"`
	Step         string          `json:"step"`
	Frame        json.RawMessage `json:"frame"`
}
type ExchangeResponse struct {
	Version     int             `json:"version"`
	OperationID string          `json:"operation_id"`
	Step        string          `json:"step"`
	Frame       json.RawMessage `json:"frame"`
}
type WireError struct {
	Version int    `json:"version"`
	Code    string `json:"code"`
}

func (x Exchange) Validate() error {
	if x.Version != 1 || !identifier.MatchString(x.IssuerRoute) || !identifier.MatchString(x.OperationID) || len(x.OperationID) < 8 || !identifier.MatchString(x.InvitationID) || len(x.Frame) == 0 || len(x.Frame) > MaxFrameBytes-1024 {
		return ErrInvalid
	}
	switch x.Step {
	case "hello", "finish", "redeem", "renew", "recover", "status", "applied":
		return nil
	}
	return ErrInvalid
}

type RegistrationPreparation struct {
	OperationID          string                       `json:"operation_id"`
	InvitationID         string                       `json:"invitation_id"`
	Identity             identity.DeviceIdentity      `json:"identity"`
	Grant                trust.Grant                  `json:"grant"`
	TicketV3             provisioning.PairingTicketV3 `json:"ticket_v3"`
	Binding              Binding                      `json:"binding"`
	BindingDigest        string                       `json:"binding_digest"`
	ReceiptWrapPublicKey string                       `json:"receipt_wrap_public_key"`
}
type RegistrationCommit struct {
	OperationID   string                       `json:"operation_id"`
	BindingDigest string                       `json:"binding_digest"`
	IdentityProof identity.DeviceProof         `json:"proof"`
	TicketV3      provisioning.PairingTicketV3 `json:"ticket"`
}
type RegistrationReceipt struct {
	SchemaVersion   int       `json:"schema_version"`
	OperationID     string    `json:"operation_id"`
	BindingDigest   string    `json:"binding_digest"`
	DomainID        string    `json:"domain_id"`
	DeviceID        string    `json:"device_id"`
	State           string    `json:"state"`
	EphemeralPublic string    `json:"ephemeral_public"`
	Nonce           string    `json:"nonce"`
	Ciphertext      string    `json:"ciphertext"`
	IssuedAt        time.Time `json:"issued_at"`
}
type RelayRegistration interface {
	Prepare(context.Context, RegistrationPreparation) error
	Commit(context.Context, RegistrationCommit) (RegistrationReceipt, error)
	Status(context.Context, string, string) (RegistrationReceipt, error)
	Revoke(context.Context, string, string, uint64) error
	Recover(context.Context, RegistrationRecovery) (RegistrationReceipt, error)
}
type RelayCredentials struct {
	Access  iscpbridge.RelayCredential `json:"access"`
	Refresh iscpbridge.RelayCredential `json:"refresh"`
}

// Management owns business authorization. Implementations must inspect existing
// Gateway Clients before signing, including every renewal and result replay.
type Management interface {
	Identity(context.Context) (Binding, error)
	Client(context.Context, string) (bool, error)
	CreateClient(context.Context, string, string) (string, error)
	RevokeManagedClient(context.Context, string) error
}
type EnrollmentResult struct {
	Version                  int                         `json:"version"`
	OperationID              string                      `json:"operation_id"`
	InvitationID             string                      `json:"invitation_id"`
	Identity                 identity.DeviceIdentity     `json:"identity"`
	Binding                  Binding                     `json:"binding"`
	AuthorizationRevision    uint64                      `json:"authorization_revision"`
	InstallationID           string                      `json:"installation_id"`
	Scopes                   []string                    `json:"scopes"`
	Enrollment               iscpbridge.EnrollmentBundle `json:"enrollment"`
	Grant                    trust.Grant                 `json:"grant"`
	IssuerIdentity           identity.DeviceIdentity     `json:"issuer_identity"`
	InvitationSignerIdentity identity.DeviceIdentity     `json:"invitation_signer_identity"`
	ResponderIdentity        identity.DeviceIdentity     `json:"responder_identity"`
	Signature                identity.Signature          `json:"signature"`
}

func SignObject(kind string, v any, signer identity.Device) (identity.Signature, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return identity.Signature{}, e
	}
	in, e := canonical.SignatureInput(kind, b)
	if e != nil {
		return identity.Signature{}, e
	}
	return identity.Signature{Alg: "Ed25519", KID: signer.Identity.PublicKey.KID, Value: c.Base64URL(c.NewProvider().Sign(signer.Private, in))}, nil
}
func VerifyObject(kind string, v any, signer identity.DeviceIdentity, sig identity.Signature) error {
	if ValidateIdentity(signer) != nil || sig.Alg != "Ed25519" || sig.KID != signer.PublicKey.KID {
		return ErrDenied
	}
	raw, _ := json.Marshal(v)
	in, e := canonical.SignatureInput(kind, raw)
	if e != nil {
		return ErrInvalid
	}
	pb, _ := c.DecodeBase64URL(signer.PublicKey.Public)
	pub, _ := c.Ed25519PublicKeyFromBytes(pb)
	sb, e := c.DecodeBase64URL(sig.Value)
	if e != nil || len(sb) != 64 || !c.NewProvider().Verify(pub, in, sb) {
		return ErrDenied
	}
	return nil
}

type RegistrationRecovery struct {
	OperationID          string                  `json:"operation_id"`
	BindingDigest        string                  `json:"binding_digest"`
	Identity             identity.DeviceIdentity `json:"identity"`
	Grant                trust.Grant             `json:"grant"`
	Proof                identity.DeviceProof    `json:"proof"`
	ReceiptWrapPublicKey string                  `json:"receipt_wrap_public_key"`
	Revision             uint64                  `json:"revision"`
}

func ValidateOrigin(origin, certPEM string, now time.Time, allowExpired bool) error {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || len(origin) > 512 || strings.ContainsAny(origin, "\r\n") || len(certPEM) > 16<<10 || certPEM == "" {
		return ErrInvalid
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || u.Hostname() != ip.String() || u.RawPath != "" || u.ForceQuery || u.String() != origin {
		return ErrInvalid
	}
	if u.Port() != "" {
		p, e := strconv.Atoi(u.Port())
		if e != nil || p < 1 || p > 65535 || strconv.Itoa(p) != u.Port() {
			return ErrInvalid
		}
	}
	block, rest := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return ErrInvalid
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil || cert.VerifyHostname(ip.String()) != nil || (!allowExpired && now.After(cert.NotAfter)) || now.Before(cert.NotBefore) {
		return ErrInvalid
	}

	return nil
}
