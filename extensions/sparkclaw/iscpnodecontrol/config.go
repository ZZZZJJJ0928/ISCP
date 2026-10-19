package iscpnodecontrol

import (
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"os"
	"path/filepath"
	"time"
)

type FileConfig struct {
	ControlAuthorization string `json:"control_authorization,omitempty"`
	Active               bool   `json:"active"`
	SchemaVersion        int    `json:"schema_version"`
	Initiator            bool   `json:"initiator"`
	IdentityFile         string `json:"identity_file"`
	KeyFile              string `json:"key_file"`
	KeyBackend           string `json:"key_backend"`
	KeyringService       string `json:"keyring_service,omitempty"`
	PeerIdentityFile     string `json:"peer_identity_file"`
	IssuerIdentityFile   string `json:"issuer_identity_file"`
	GrantFile            string `json:"grant_file"`
	EnrollmentFile       string `json:"enrollment_file"`
}

func ReadPrivate(path string, out any) error {
	raw, e := ReadPrivateBytes(path)
	if e != nil {
		return e
	}
	if n.StrictDecode(raw, out) != nil {
		return n.ErrInvalid
	}
	return nil
}
func ReadPrivateBytes(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, n.ErrInvalid
	}
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 4<<20 {
		return nil, n.ErrInvalid
	}
	return os.ReadFile(path)
}
func LoadSigner(identityPath, keyPath string) (identity.Device, error) {
	var id identity.DeviceIdentity
	if e := ReadPrivate(identityPath, &id); e != nil {
		return identity.Device{}, e
	}
	raw, e := ReadPrivateBytes(keyPath)
	if e != nil {
		return identity.Device{}, e
	}
	kb, e := c.DecodeBase64URL(string(raw))
	if e != nil {
		return identity.Device{}, n.ErrInvalid
	}
	key, e := c.Ed25519PrivateKeyFromBytes(kb)
	if e != nil || c.Base64URL(key.Public().Bytes()) != id.PublicKey.Public || n.ValidateIdentity(id) != nil {
		return identity.Device{}, n.ErrInvalid
	}
	return identity.Device{Identity: id, Private: key}, nil
}
func LoadPeer(path string, h Handler) (*Peer, error) {
	var cfg FileConfig
	if e := ReadPrivate(path, &cfg); e != nil {
		return nil, e
	}
	if cfg.SchemaVersion != 1 {
		return nil, n.ErrInvalid
	}
	dev, e := iscpbridge.LoadDeviceWithKeyBackend(cfg.IdentityFile, cfg.KeyFile, cfg.KeyBackend, cfg.KeyringService)
	if e != nil {
		return nil, e
	}
	var peer, issuer identity.DeviceIdentity
	var grant trust.Grant
	var bundle iscpbridge.EnrollmentBundle
	for _, v := range []struct {
		path string
		out  any
	}{{cfg.PeerIdentityFile, &peer}, {cfg.IssuerIdentityFile, &issuer}, {cfg.GrantFile, &grant}, {cfg.EnrollmentFile, &bundle}} {
		if e = ReadPrivate(v.path, v.out); e != nil {
			return nil, e
		}
	}
	relay, e := iscpbridge.NewRelayCredentialClient(iscpbridge.ProfileProduction, cfg.EnrollmentFile, bundle, dev, 15*time.Second)
	if e != nil {
		return nil, e
	}
	if e = relay.ConfigureServiceCredentialProvider(issuer); e != nil {
		return nil, e
	}
	p, e := newPeer(PeerConfig{cfg.Initiator, dev, peer, issuer, grant, bundle.RelayID}, relay, h, cfg.ControlAuthorization == "until_revoked", cfg.Active, cfg.GrantFile)
	if e != nil {
		return nil, e
	}
	p.enrollmentFile = cfg.EnrollmentFile
	return p, nil
}
func (p *Peer) SetHandler(h Handler) { p.mu.Lock(); defer p.mu.Unlock(); p.handler = h }
