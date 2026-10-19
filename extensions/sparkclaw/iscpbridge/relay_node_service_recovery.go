package iscpbridge

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

const serviceRecoveryPath = "/api/sparkclaw/iscp-control/v1/service-recover"

var ErrNodeServiceRecoveryExpired = errors.New("authenticated service recovery receipt expired; retry a fresh operation")

type serviceRecoveryRequest struct {
	OperationID          string                  `json:"operation_id"`
	Identity             identity.DeviceIdentity `json:"identity"`
	Proof                identity.DeviceProof    `json:"proof"`
	ReceiptWrapPublicKey string                  `json:"receipt_wrap_public_key"`
}
type serviceRecoveryPending struct {
	Version     int                    `json:"version"`
	Request     serviceRecoveryRequest `json:"request"`
	WrapPrivate string                 `json:"wrap_private"`
}

// RecoverNodeServiceCredentials reaches only the operator's pre-enrolled
// service-peer recovery adapter, after verifying its signed declared capability
// and existing Relay/TLS pins. It cannot enroll a new peer or authorize business.
// Caller MUST SaveEnrollment then CommitNodeServiceRecovery; the sealed receipt
// remains replayable until the new credential pair has been durably applied.
func RecoverNodeServiceCredentials(ctx context.Context, bundle EnrollmentBundle, device identity.Device, pendingFile string) (EnrollmentBundle, error) {
	var zero EnrollmentBundle
	if bundle.Mode != BundleModeWorkbenchNodeManaged || bundle.DomainID != device.Identity.DomainID || bundle.DeviceID != device.Identity.DeviceID || !filepath.IsAbs(pendingFile) || ValidateLocalRelaySigner(device.Identity) != nil {
		return zero, errors.New("service recovery requires the original node-managed peer identity")
	}
	st, err := os.Lstat(filepath.Dir(pendingFile))
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return zero, errors.New("service recovery requires a private pending directory")
	}
	desc, err := DiscoverNodeRelay(ctx, bundle)
	if err != nil {
		return zero, err
	}
	if desc.Metadata["sparkclaw_service_peer_recovery"] != "v1" {
		return zero, errors.New("Relay has not declared operator service-peer recovery")
	}
	provider := c.NewProvider()
	storageKey, err := provider.HKDF(device.Private.BytesForDevStore(), nil, []byte("sparkclaw/iscp-node/service-recovery-storage/v1\x00"+device.Identity.PublicKey.KID), 32)
	if err != nil {
		return zero, err
	}
	var pending serviceRecoveryPending
	st, err = os.Lstat(pendingFile)
	if errors.Is(err, os.ErrNotExist) {
		priv, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return zero, e
		}
		b := c.RandomBytes(16)
		b[6] = (b[6] & 15) | 64
		b[8] = (b[8] & 63) | 128
		op := fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
		pending = serviceRecoveryPending{Version: 1, Request: serviceRecoveryRequest{OperationID: op, Identity: device.Identity, ReceiptWrapPublicKey: c.Base64URL(priv.PublicKey().Bytes())}, WrapPrivate: c.Base64URL(priv.Bytes())}
		challenge := strings.Join([]string{"sparkclaw/iscp-node/service-recovery/v1", op, pending.Request.ReceiptWrapPublicKey}, "\x00")
		pending.Request.Proof, err = device.CreateProof(provider, bundle.RelayID, challenge, randomNonce(), time.Now().UTC())
		if err != nil {
			return zero, err
		}
		raw, _ := json.Marshal(pending)
		nonce := c.RandomBytes(12)
		ct, e := provider.Seal(storageKey, nonce, raw, []byte("service-recovery-v1"))
		if e != nil {
			return zero, e
		}
		if e = writeSecretFile(pendingFile, []byte(c.Base64URL(append(nonce, ct...)))); e != nil {
			return zero, e
		}
	} else if err != nil {
		return zero, err
	} else {
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 32<<10 {
			return zero, errors.New("invalid service recovery pending file")
		}
		raw, e := os.ReadFile(pendingFile)
		if e != nil {
			return zero, e
		}
		blob, e := base64.RawURLEncoding.Strict().DecodeString(string(raw))
		if e != nil || len(blob) < 28 {
			return zero, errors.New("invalid service recovery pending encoding")
		}
		plain, e := provider.Open(storageKey, blob[:12], blob[12:], []byte("service-recovery-v1"))
		if e != nil || strictUnmarshal(plain, &pending) != nil || pending.Version != 1 || pending.Request.Identity.DeviceID != device.Identity.DeviceID || pending.Request.Identity.PublicKey.Public != device.Identity.PublicKey.Public {
			return zero, errors.New("service recovery pending identity mismatch")
		}
	}
	tlsConfig, err := VerifiedTLSConfig(bundle.TLSCertificatePEM)
	if err != nil {
		return zero, err
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("service recovery redirects prohibited") }}
	defer client.CloseIdleConnections()
	raw, _ := json.Marshal(pending.Request)
	canonicalRaw, err := canonical.Marshal(raw)
	if err != nil {
		return zero, err
	}
	digest := c.Base64URL(c.SHA256(canonicalRaw))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(bundle.RelayBaseURL, "/")+serviceRecoveryPath, bytes.NewReader(raw))
	if err != nil {
		return zero, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return zero, errors.New("service recovery outcome unknown; retry retained operation")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return zero, &relayHTTPError{status: res.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 32<<10))
	if err != nil {
		return zero, err
	}
	var receipt nodeRelayReceipt
	if strictUnmarshal(body, &receipt) != nil {
		return zero, errors.New("invalid service recovery receipt")
	}
	credentials, err := openNodeRelayReceipt(receipt, pending.Request.OperationID, digest, pending.WrapPrivate, device.Identity)
	if err != nil {
		return zero, err
	}
	for _, cred := range []RelayCredential{credentials.Access, credentials.Refresh} {
		if cred.DomainID != bundle.DomainID || cred.DeviceID != bundle.DeviceID || cred.Token == "" {
			return zero, errors.New("recovered service credentials differ from peer")
		}
		if !time.Now().Before(cred.ExpiresAt) {
			if err := CommitNodeServiceRecovery(pendingFile); err != nil {
				return zero, err
			}
			return zero, ErrNodeServiceRecoveryExpired
		}
	}
	updated := bundle
	updated.Access = credentials.Access
	updated.Refresh = credentials.Refresh
	updated.IssuedAt = time.Now().UTC()
	updated.ExpiresAt = desc.ExpiresAt
	if updated.Refresh.ExpiresAt.Before(updated.ExpiresAt) {
		updated.ExpiresAt = updated.Refresh.ExpiresAt
	}
	if err = updated.ValidateCredentials(time.Now().UTC()); err != nil {
		return zero, err
	}
	return updated, nil
}

func CommitNodeServiceRecovery(pendingFile string) error {
	if !filepath.IsAbs(pendingFile) {
		return errors.New("service recovery pending path must be absolute")
	}
	if err := os.Remove(pendingFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir, err := os.Open(filepath.Dir(pendingFile))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
