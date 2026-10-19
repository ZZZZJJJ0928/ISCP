// Package iscplocalenroll enrolls independently generated devices into the
// locked SDK reference Relay running in the isolated local Docker laboratory.
package iscplocalenroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

type Options struct {
	RelayURL            string
	RelayID             string
	DomainID            string
	DeviceID            string
	IdentityDirectory   string
	EnrollmentFile      string
	RuntimeRelayURL     string
	RuntimeWebSocketURL string
}

type Summary struct {
	Profile               string `json:"relay_profile"`
	DomainID              string `json:"domain_id"`
	DeviceID              string `json:"device_id"`
	DeviceThumbprint      string `json:"device_thumbprint"`
	RelayID               string `json:"relay_id"`
	RelayURL              string `json:"relay_url"`
	RelayWebSocketURL     string `json:"relay_websocket_url"`
	RelaySignerThumbprint string `json:"relay_signer_thumbprint"`
	IdentityDirectory     string `json:"identity_directory"`
	IdentityFile          string `json:"identity_file"`
	EnrollmentFile        string `json:"enrollment_file"`
}

func Enroll(ctx context.Context, opts Options) (Summary, error) {
	var summary Summary
	if opts.RelayID == "" || opts.DomainID == "" || opts.DeviceID == "" || len(opts.RelayID) > 200 || len(opts.DomainID) > 200 || len(opts.DeviceID) > 200 || opts.IdentityDirectory == "" || opts.EnrollmentFile == "" {
		return summary, errors.New("local enrollment requires Relay/domain/device IDs and private output paths")
	}
	var err error
	opts.IdentityDirectory, err = filepath.Abs(opts.IdentityDirectory)
	if err != nil {
		return summary, errors.New("resolve local identity directory")
	}
	opts.EnrollmentFile, err = filepath.Abs(opts.EnrollmentFile)
	if err != nil {
		return summary, errors.New("resolve local enrollment path")
	}
	if opts.RuntimeRelayURL == "" {
		opts.RuntimeRelayURL = strings.TrimRight(opts.RelayURL, "/")
	}
	if opts.RuntimeWebSocketURL == "" {
		opts.RuntimeWebSocketURL, err = iscpbridge.LocalRelayWebSocketURL(opts.RuntimeRelayURL)
		if err != nil {
			return summary, err
		}
	}
	if err := iscpbridge.ValidateWorkbenchRelayURLs(iscpbridge.ProfileLocalLab, opts.RuntimeRelayURL, opts.RuntimeWebSocketURL); err != nil {
		return summary, err
	}
	var pin *identity.DeviceIdentity
	if _, err := os.Lstat(opts.EnrollmentFile); err == nil {
		old, err := loadEnrollment(opts.EnrollmentFile)
		if err != nil {
			return summary, err
		}
		if old.Mode != iscpbridge.BundleModeWorkbenchLocalLab || old.RelayID != opts.RelayID || old.DomainID != opts.DomainID || old.DeviceID != opts.DeviceID || old.RelaySignerIdentity == nil {
			return summary, errors.New("existing local enrollment belongs to another device or Relay")
		}
		pin = old.RelaySignerIdentity
	} else if !errors.Is(err, os.ErrNotExist) {
		return summary, errors.New("inspect local enrollment output")
	}
	desc, signer, err := iscpbridge.DiscoverLocalRelay(ctx, opts.RelayURL, opts.RelayID, opts.DomainID, pin)
	if err != nil {
		return summary, err
	}
	if err := os.MkdirAll(opts.IdentityDirectory, 0700); err != nil {
		return summary, errors.New("create private local identity directory")
	}
	info, err := os.Lstat(opts.IdentityDirectory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return summary, errors.New("local identity directory must be private (0700)")
	}
	identityFile := filepath.Join(opts.IdentityDirectory, iscpbridge.IdentityFileName)
	keyFile := filepath.Join(opts.IdentityDirectory, iscpbridge.IdentityKeyFileName)
	if _, err := os.Lstat(identityFile); errors.Is(err, os.ErrNotExist) {
		if _, _, err := iscpbridge.GenerateEnrollmentRequestWithKeyBackend(opts.IdentityDirectory, opts.DomainID, opts.DeviceID, "local-lab", iscpbridge.IdentityKeyBackendFile, "", time.Now().UTC()); err != nil {
			return summary, errors.New("generate independent local device identity")
		}
	} else if err != nil {
		return summary, errors.New("inspect local device identity")
	}
	for i, path := range []string{identityFile, keyFile} {
		info, err := os.Lstat(path)
		limit := int64(32 << 10)
		if i == 1 {
			limit = 4096
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() > limit || (i == 1 && info.Mode().Perm()&0077 != 0) {
			return summary, errors.New("local identity material must be bounded regular files with private key permissions")
		}
	}
	if err := os.Chmod(identityFile, 0600); err != nil {
		return summary, errors.New("protect private lab identity record")
	}
	device, err := iscpbridge.LoadDeviceWithKeyBackend(identityFile, keyFile, iscpbridge.IdentityKeyBackendFile, "")
	if err != nil || device.Identity.DomainID != opts.DomainID || device.Identity.DeviceID != opts.DeviceID {
		return summary, errors.New("local identity does not match requested enrolled device")
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return summary, errors.New("generate local enrollment nonce")
	}
	encodedNonce := base64.RawURLEncoding.EncodeToString(nonce)
	proof, err := device.CreateProof(iscpcrypto.NewProvider(), opts.RelayID, "iscp/local-lab/bind-self/"+encodedNonce, encodedNonce, time.Now().UTC())
	if err != nil {
		return summary, errors.New("create local enrollment possession proof")
	}
	raw, _ := json.Marshal(struct {
		Identity identity.DeviceIdentity `json:"identity"`
		Proof    identity.DeviceProof    `json:"proof"`
	}{device.Identity, proof})
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(opts.RelayURL, "/")+"/v2/relay/devices/bind-self", bytes.NewReader(raw))
	if err != nil {
		return summary, errors.New("create local bind-self request")
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("local enrollment redirects are prohibited")
	}}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return summary, errors.New("local reference Relay enrollment failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return summary, errors.New("local reference Relay rejected device enrollment")
	}
	var issued struct {
		Access struct {
			iscpbridge.RelayCredential
			Revoked bool `json:"revoked"`
		} `json:"access"`
		Refresh struct {
			iscpbridge.RelayCredential
			Revoked bool `json:"revoked"`
		} `json:"refresh"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&issued); err != nil || decoder.Decode(new(any)) != io.EOF || issued.Access.Revoked || issued.Refresh.Revoked {
		return summary, errors.New("invalid issued local Relay credentials")
	}
	now := time.Now().UTC()
	expires := issued.Refresh.ExpiresAt
	if desc.ExpiresAt.Before(expires) {
		expires = desc.ExpiresAt
	}
	bundle := iscpbridge.EnrollmentBundle{Type: iscpbridge.EnrollmentBundleType, Mode: iscpbridge.BundleModeWorkbenchLocalLab, DomainID: opts.DomainID, DeviceID: opts.DeviceID, RelayID: opts.RelayID, RelayBaseURL: opts.RuntimeRelayURL, RelayWebSocketURL: opts.RuntimeWebSocketURL, RelaySignerIdentity: &signer, Access: issued.Access.RelayCredential, Refresh: issued.Refresh.RelayCredential, IssuedAt: now, ExpiresAt: expires}
	if err := bundle.ValidateCredentials(now); err != nil {
		return summary, errors.New("issued local Relay credentials have invalid device binding or validity")
	}
	if !now.Before(bundle.Access.ExpiresAt) {
		return summary, errors.New("issued local access credential already expired")
	}
	if err := iscpbridge.SaveEnrollment(opts.EnrollmentFile, bundle); err != nil {
		return summary, errors.New("persist private local Relay enrollment")
	}
	return Summary{Profile: iscpbridge.ProfileLocalLab, DomainID: opts.DomainID, DeviceID: opts.DeviceID, DeviceThumbprint: device.Identity.PublicKey.KID, RelayID: opts.RelayID, RelayURL: opts.RuntimeRelayURL, RelayWebSocketURL: opts.RuntimeWebSocketURL, RelaySignerThumbprint: signer.PublicKey.KID, IdentityDirectory: opts.IdentityDirectory, IdentityFile: identityFile, EnrollmentFile: opts.EnrollmentFile}, nil
}

func loadEnrollment(path string) (iscpbridge.EnrollmentBundle, error) {
	var bundle iscpbridge.EnrollmentBundle
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 512<<10 || info.Mode().Perm()&0077 != 0 {
		return bundle, errors.New("existing enrollment must be a bounded private regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return bundle, errors.New("read existing enrollment")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil || decoder.Decode(new(any)) != io.EOF {
		return bundle, errors.New("decode existing enrollment")
	}
	return bundle, nil
}
