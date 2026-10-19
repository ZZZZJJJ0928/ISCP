// Derived from ISCP v0.2.0-rc.1 reference Relay; see UPSTREAM_LICENSE.txt.
// Deployment adapters preserve its public protocol and persisted signer.
package iscprelayreference

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

// Deployment-only identity storage; it changes no ISCP wire message.
type signerRecord struct {
	Version    int                     `json:"version"`
	Identity   identity.DeviceIdentity `json:"identity"`
	PrivateKey string                  `json:"private_key"`
}

func persistentSigner(provider crypto.Provider, cfg Config, now time.Time) (identity.Device, error) {
	if cfg.SignerFile == "" {
		return identity.NewDevice(provider, cfg.DomainID, cfg.RelayID+"-signer", now)
	}
	if !filepath.IsAbs(cfg.SignerFile) {
		return identity.Device{}, errors.New("signer file must be absolute")
	}
	directory := filepath.Dir(cfg.SignerFile)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return identity.Device{}, errors.New("signer directory must be private")
	}
	lock, err := os.OpenFile(cfg.SignerFile+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return identity.Device{}, err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return identity.Device{}, err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	info, err = os.Lstat(cfg.SignerFile)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 32768 {
			return identity.Device{}, errors.New("signer record must be private and bounded")
		}
		raw, err := os.ReadFile(cfg.SignerFile)
		if err != nil {
			return identity.Device{}, err
		}
		var record signerRecord
		if err = json.Unmarshal(raw, &record); err != nil {
			return identity.Device{}, errors.New("invalid signer record")
		}
		private, err := base64.RawURLEncoding.DecodeString(record.PrivateKey)
		if err != nil {
			return identity.Device{}, errors.New("invalid signer key encoding")
		}
		key, err := crypto.Ed25519PrivateKeyFromBytes(private)
		if err != nil {
			return identity.Device{}, errors.New("invalid signer key")
		}
		id := record.Identity
		if record.Version != 1 || id.Type != identity.TypeDeviceIdentity || id.DomainID != cfg.DomainID || id.DeviceID != cfg.RelayID+"-signer" || id.PublicKey.KTY != "Ed25519" || id.PublicKey.Use != "identity-signature" || id.PublicKey.Public != crypto.Base64URL(key.Public().Bytes()) || id.PublicKey.KID != crypto.Thumbprint("Ed25519", key.Public().Bytes()) {
			return identity.Device{}, errors.New("signer identity does not match configuration and key")
		}
		return identity.Device{Identity: id, Private: key}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return identity.Device{}, err
	}
	device, err := identity.NewDevice(provider, cfg.DomainID, cfg.RelayID+"-signer", now)
	if err != nil {
		return identity.Device{}, err
	}
	raw, err := json.Marshal(signerRecord{Version: 1, Identity: device.Identity, PrivateKey: base64.RawURLEncoding.EncodeToString(device.Private.BytesForDevStore())})
	if err != nil {
		return identity.Device{}, err
	}
	f, err := os.CreateTemp(directory, ".signer-")
	if err != nil {
		return identity.Device{}, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return identity.Device{}, err
	}
	if err = os.Rename(f.Name(), cfg.SignerFile); err != nil {
		return identity.Device{}, err
	}
	parent, err := os.Open(directory)
	if err != nil {
		return identity.Device{}, err
	}
	defer parent.Close()
	if err = parent.Sync(); err != nil {
		return identity.Device{}, err
	}
	return device, nil
}
