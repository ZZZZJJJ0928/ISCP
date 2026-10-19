package iscpnodeissuer

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"time"
)

// Each side independently creates its ephemeral key. Persisted private material
// is encrypted by Store; no process ever constructs its remote peer's key.
type ClientHello struct {
	Version          int                     `json:"version"`
	OperationID      string                  `json:"operation_id"`
	InvitationID     string                  `json:"invitation_id"`
	IssuerRoute      string                  `json:"issuer_route"`
	DeploymentID     string                  `json:"deployment_id"`
	CredentialDigest string                  `json:"credential_digest"`
	Identity         identity.DeviceIdentity `json:"identity"`
	EphemeralPublic  string                  `json:"ephemeral_public"`
	Nonce            string                  `json:"nonce"`
	Proof            identity.DeviceProof    `json:"proof"`
	MAC              string                  `json:"mac"`
}
type ServerHello struct {
	Version         int                     `json:"version"`
	OperationID     string                  `json:"operation_id"`
	HelloDigest     string                  `json:"hello_digest"`
	EphemeralPublic string                  `json:"ephemeral_public"`
	Challenge       string                  `json:"challenge"`
	ExpiresAt       time.Time               `json:"expires_at"`
	IssuerIdentity  identity.DeviceIdentity `json:"issuer_identity"`
	MAC             string                  `json:"mac"`
	Signature       identity.Signature      `json:"signature"`
}
type Finished struct {
	Version          int    `json:"version"`
	OperationID      string `json:"operation_id"`
	TranscriptDigest string `json:"transcript_digest"`
	MAC              string `json:"mac"`
}
type Channel struct {
	Key            []byte   `json:"key"`
	Transcript     []byte   `json:"transcript"`
	Ready          bool     `json:"ready"`
	ClientFinished Finished `json:"client_finished"`
	ServerFinished Finished `json:"server_finished"`
}
type SealedFrame struct {
	Version     int    `json:"version"`
	OperationID string `json:"operation_id"`
	Sequence    uint64 `json:"sequence"`
	Nonce       string `json:"nonce"`
	Ciphertext  string `json:"ciphertext"`
}
type RedeemRequest struct {
	IdentityProof  identity.DeviceProof `json:"identity_proof"`
	InstallationID string               `json:"installation_id"`
}

func NewWrapKey() ([]byte, string, error) {
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return nil, "", e
	}
	return k.Bytes(), c.Base64URL(k.PublicKey().Bytes()), nil
}
func shared(priv []byte, pub string) ([]byte, error) {
	k, e := ecdh.X25519().NewPrivateKey(priv)
	if e != nil {
		return nil, ErrInvalid
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(pub)
	if e != nil || len(raw) != 32 {
		return nil, ErrInvalid
	}
	p, e := ecdh.X25519().NewPublicKey(raw)
	if e != nil {
		return nil, ErrInvalid
	}
	s, e := k.ECDH(p)
	if e != nil {
		return nil, ErrDenied
	}
	return s, nil
}
func PublicWrapKey(priv []byte) (string, error) {
	k, e := ecdh.X25519().NewPrivateKey(priv)
	if e != nil {
		return "", ErrInvalid
	}
	return c.Base64URL(k.PublicKey().Bytes()), nil
}
func NewClientHello(v Credential, device identity.Device, operation string, now time.Time) (ClientHello, []byte, error) {
	priv, pub, e := NewWrapKey()
	if e != nil {
		return ClientHello{}, nil, e
	}
	proof, e := device.CreateProof(c.NewProvider(), v.IssuerIdentity.DeviceID, v.InvitationID, c.Base64URL(c.RandomBytes(24)), now)
	if e != nil {
		return ClientHello{}, nil, e
	}
	h := ClientHello{Version: 1, OperationID: operation, InvitationID: v.InvitationID, IssuerRoute: v.IssuerRoute, DeploymentID: v.DeploymentID, CredentialDigest: Digest(v), Identity: device.Identity, EphemeralPublic: pub, Nonce: c.Base64URL(c.RandomBytes(32)), Proof: proof}
	secret, _ := c.DecodeBase64URL(v.BootstrapSecret)
	in, _ := Canonical(h)
	h.MAC = c.Base64URL(c.HMACSHA256(secret, append([]byte("sparkclaw/iscp-node/client-hello/v1\x00"), in...)))
	return h, priv, nil
}
func VerifyClientHello(v Credential, h ClientHello, now time.Time) error {
	if h.Version != 1 || h.InvitationID != v.InvitationID || h.IssuerRoute != v.IssuerRoute || h.DeploymentID != v.DeploymentID || h.CredentialDigest != Digest(v) || !identifier.MatchString(h.OperationID) || len(h.OperationID) < 8 || ValidateIdentity(h.Identity) != nil || h.Identity.DomainID != v.DomainID || h.Identity.DeviceID == v.ResponderIdentity.DeviceID {
		return ErrDenied
	}
	if identity.VerifyProof(c.NewProvider(), h.Identity, h.Proof, v.IssuerIdentity.DeviceID, v.InvitationID, now, 5*time.Minute) != nil {
		return ErrDenied
	}
	secret, _ := c.DecodeBase64URL(v.BootstrapSecret)
	got, e := c.DecodeBase64URL(h.MAC)
	if e != nil {
		return ErrDenied
	}
	h.MAC = ""
	in, _ := Canonical(h)
	if !c.EqualMAC(got, c.HMACSHA256(secret, append([]byte("sparkclaw/iscp-node/client-hello/v1\x00"), in...))) {
		return ErrDenied
	}
	for _, s := range []string{h.EphemeralPublic, h.Nonce} {
		b, e := c.DecodeBase64URL(s)
		if e != nil || len(b) != 32 {
			return ErrInvalid
		}
	}
	return nil
}
func NewServerHello(v Credential, h ClientHello, issuer identity.Device, now time.Time) (ServerHello, Channel, error) {
	priv, pub, e := NewWrapKey()
	if e != nil {
		return ServerHello{}, Channel{}, e
	}
	out := ServerHello{Version: 1, OperationID: h.OperationID, HelloDigest: Digest(h), EphemeralPublic: pub, Challenge: c.Base64URL(c.RandomBytes(32)), ExpiresAt: now.Add(5 * time.Minute), IssuerIdentity: issuer.Identity}
	in, _ := Canonical(out)
	secret, _ := c.DecodeBase64URL(v.BootstrapSecret)
	out.MAC = c.Base64URL(c.HMACSHA256(secret, append([]byte("sparkclaw/iscp-node/server-hello/v1\x00"), in...)))
	out.Signature, e = SignObject("sparkclaw.iscp.server-hello.v1", out, issuer)
	if e != nil {
		return ServerHello{}, Channel{}, e
	}
	ch, e := deriveChannel(v, h, out, priv, h.EphemeralPublic)
	return out, ch, e
}
func AcceptServerHello(v Credential, h ClientHello, out ServerHello, priv []byte, now time.Time) (Channel, error) {
	if out.Version != 1 || out.OperationID != h.OperationID || out.HelloDigest != Digest(h) || !now.Before(out.ExpiresAt) || out.ExpiresAt.After(now.Add(6*time.Minute)) || Digest(out.IssuerIdentity) != Digest(v.IssuerIdentity) || VerifyObject("sparkclaw.iscp.server-hello.v1", out, v.IssuerIdentity, out.Signature) != nil {
		return Channel{}, ErrDenied
	}
	unsigned := out
	unsigned.MAC = ""
	unsigned.Signature = identity.Signature{}
	in, _ := Canonical(unsigned)
	secret, _ := c.DecodeBase64URL(v.BootstrapSecret)
	got, e := c.DecodeBase64URL(out.MAC)
	if e != nil || !c.EqualMAC(got, c.HMACSHA256(secret, append([]byte("sparkclaw/iscp-node/server-hello/v1\x00"), in...))) {
		return Channel{}, ErrDenied
	}
	return deriveChannel(v, h, out, priv, out.EphemeralPublic)
}
func deriveChannel(v Credential, h ClientHello, s ServerHello, priv []byte, remote string) (Channel, error) {
	transcript, e := Canonical(struct {
		Protocol   string      `json:"protocol"`
		Credential string      `json:"credential"`
		Hello      ClientHello `json:"hello"`
		Server     ServerHello `json:"server"`
	}{"sparkclaw.iscp.provisioning.v1", Digest(v), h, s})
	if e != nil {
		return Channel{}, e
	}
	sec, e := shared(priv, remote)
	if e != nil {
		return Channel{}, e
	}
	oob, _ := c.DecodeBase64URL(v.BootstrapSecret)
	key, e := c.NewProvider().HKDF(append(sec, oob...), c.SHA256(transcript), []byte("sparkclaw/iscp-node/provisioning/key/v1"), 32)
	return Channel{Key: key, Transcript: transcript}, e
}
func (ch Channel) Finished(role, operation string) Finished {
	in := append([]byte("sparkclaw/iscp-node/finished/v1\x00"+role+"\x00"), c.SHA256(ch.Transcript)...)
	return Finished{1, operation, c.Base64URL(c.SHA256(ch.Transcript)), c.Base64URL(c.HMACSHA256(ch.Key, in))}
}
func (ch Channel) VerifyFinished(f Finished, role, operation string) error {
	expected := ch.Finished(role, operation)
	if f.Version != 1 || f.OperationID != operation || f.TranscriptDigest != expected.TranscriptDigest {
		return ErrDenied
	}
	a, e := c.DecodeBase64URL(f.MAC)
	b, _ := c.DecodeBase64URL(expected.MAC)
	if e != nil || !c.EqualMAC(a, b) {
		return ErrDenied
	}
	return nil
}
func frameAAD(ch Channel, operation, role string, sequence uint64) []byte {
	b := append([]byte("sparkclaw/iscp-node/frame/v1\x00"+operation+"\x00"+role+"\x00"), c.SHA256(ch.Transcript)...)
	return binary.BigEndian.AppendUint64(b, sequence)
}
func SealFrame(ch Channel, operation, role string, seq uint64, v any) (SealedFrame, error) {
	if !ch.Ready || len(ch.Key) != 32 {
		return SealedFrame{}, ErrDenied
	}
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > MaxFrameBytes-1024 {
		return SealedFrame{}, ErrInvalid
	}
	nonce := c.RandomBytes(12)
	ct, e := c.NewProvider().Seal(ch.Key, nonce, raw, frameAAD(ch, operation, role, seq))
	return SealedFrame{1, operation, seq, c.Base64URL(nonce), c.Base64URL(ct)}, e
}
func OpenFrame(ch Channel, f SealedFrame, operation, role string, seq uint64, v any) error {
	if !ch.Ready || f.Version != 1 || f.OperationID != operation || f.Sequence != seq {
		return ErrDenied
	}
	n, e := c.DecodeBase64URL(f.Nonce)
	if e != nil {
		return ErrInvalid
	}
	ct, e := c.DecodeBase64URL(f.Ciphertext)
	if e != nil || len(ct) > MaxFrameBytes {
		return ErrInvalid
	}
	raw, e := c.NewProvider().Open(ch.Key, n, ct, frameAAD(ch, operation, role, seq))
	if e != nil {
		return ErrDenied
	}
	return StrictDecode(raw, v)
}
func receiptTranscript(r RegistrationReceipt, id identity.DeviceIdentity) []byte {
	return []byte("sparkclaw/iscp-node/relay-receipt/v1\x00" + r.OperationID + "\x00" + r.BindingDigest + "\x00" + r.DomainID + "\x00" + r.DeviceID + "\x00" + id.PublicKey.KID)
}
func OpenRegistrationReceipt(r RegistrationReceipt, privateRaw []byte, id identity.DeviceIdentity) (RelayCredentials, error) {
	var out RelayCredentials
	if r.SchemaVersion != 1 || r.State != "committed" || r.DomainID != id.DomainID || r.DeviceID != id.DeviceID {
		return out, ErrDenied
	}
	sec, e := shared(privateRaw, r.EphemeralPublic)
	if e != nil {
		return out, e
	}
	public, e := PublicWrapKey(privateRaw)
	if e != nil {
		return out, e
	}
	pub, _ := c.DecodeBase64URL(public)
	eph, _ := c.DecodeBase64URL(r.EphemeralPublic)
	t := receiptTranscript(r, id)
	info := append(append(append([]byte{}, t...), pub...), eph...)
	key, e := c.NewProvider().HKDF(sec, nil, info, 32)
	if e != nil {
		return out, e
	}
	n, e := c.DecodeBase64URL(r.Nonce)
	if e != nil {
		return out, ErrDenied
	}
	ct, e := c.DecodeBase64URL(r.Ciphertext)
	if e != nil {
		return out, ErrDenied
	}
	raw, e := c.NewProvider().Open(key, n, ct, t)
	if e != nil {
		return out, ErrDenied
	}
	if StrictDecode(raw, &out) != nil || out.Access.DomainID != id.DomainID || out.Access.DeviceID != id.DeviceID || out.Refresh.DomainID != id.DomainID || out.Refresh.DeviceID != id.DeviceID {
		return out, ErrDenied
	}
	return out, nil
}

// SealRegistrationReceipt is shared with a cooperating Relay adapter and tests.
func SealRegistrationReceipt(r RegistrationReceipt, pub string, id identity.DeviceIdentity, tokens RelayCredentials) (RegistrationReceipt, error) {
	priv, eph, e := NewWrapKey()
	if e != nil {
		return r, e
	}
	r.EphemeralPublic = eph
	r.SchemaVersion = 1
	r.State = "committed"
	r.DomainID = id.DomainID
	r.DeviceID = id.DeviceID
	sec, e := shared(priv, pub)
	if e != nil {
		return r, e
	}
	p, _ := c.DecodeBase64URL(pub)
	ep, _ := c.DecodeBase64URL(eph)
	t := receiptTranscript(r, id)
	key, e := c.NewProvider().HKDF(sec, nil, append(append(append([]byte{}, t...), p...), ep...), 32)
	if e != nil {
		return r, e
	}
	raw, _ := json.Marshal(tokens)
	nonce := c.RandomBytes(12)
	ct, e := c.NewProvider().Seal(key, nonce, raw, t)
	r.Nonce = c.Base64URL(nonce)
	r.Ciphertext = c.Base64URL(ct)
	return r, e
}
