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
	"strings"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

type nodeRefreshPending struct {
	Version     int                  `json:"version"`
	OperationID string               `json:"operation_id"`
	Refresh     string               `json:"refresh"`
	WrapPrivate string               `json:"wrap_private"`
	WrapPublic  string               `json:"wrap_public"`
	Proof       identity.DeviceProof `json:"proof"`
}
type nodeRelayReceipt struct {
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
type rotatedRelayCredentials struct {
	Access  RelayCredential `json:"access"`
	Refresh RelayCredential `json:"refresh"`
}

func (c *RelayClient) nodeRefreshPath() string { return c.enrollmentPath + ".refresh.pending" }
func (c *RelayClient) hasNodeRefreshPending() bool {
	_, err := os.Lstat(c.nodeRefreshPath())
	return !errors.Is(err, os.ErrNotExist)
}
func (c *RelayClient) refreshStorageKey() ([]byte, error) {
	return c.provider.HKDF(c.device.Private.BytesForDevStore(), nil, []byte("sparkclaw/iscp-node/refresh-storage/v1\x00"+c.device.Identity.PublicKey.KID), 32)
}
func (c *RelayClient) loadNodeRefresh() (nodeRefreshPending, error) {
	var p nodeRefreshPending
	st, err := os.Lstat(c.nodeRefreshPath())
	if err != nil {
		return p, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 32<<10 {
		return p, errors.New("invalid pending Relay refresh file")
	}
	raw, err := os.ReadFile(c.nodeRefreshPath())
	if err != nil {
		return p, err
	}
	blob, err := base64.RawURLEncoding.Strict().DecodeString(string(raw))
	if err != nil || len(blob) < 28 {
		return p, errors.New("invalid pending Relay refresh encoding")
	}
	key, err := c.refreshStorageKey()
	if err != nil {
		return p, err
	}
	plain, err := c.provider.Open(key, blob[:12], blob[12:], []byte("node-refresh-v1"))
	if err != nil {
		return p, errors.New("pending Relay refresh authentication failed")
	}
	if strictUnmarshal(plain, &p) != nil || p.Version != 1 || p.Refresh == "" {
		return p, errors.New("invalid pending Relay refresh request")
	}
	return p, nil
}
func (client *RelayClient) saveNodeRefresh(p nodeRefreshPending) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	key, err := client.refreshStorageKey()
	if err != nil {
		return err
	}
	nonce := c.RandomBytes(12)
	ct, err := client.provider.Seal(key, nonce, raw, []byte("node-refresh-v1"))
	if err != nil {
		return err
	}
	return writeSecretFile(client.nodeRefreshPath(), []byte(c.Base64URL(append(nonce, ct...))))
}

// refreshNodeCredentials is called under the per-device Relay client lock.
// Exact PoP and wrap key are committed before the request; a lost response or
// process restart replays that request and decrypts only its own sealed receipt.
func (client *RelayClient) refreshNodeCredentials(ctx context.Context) (rotatedRelayCredentials, error) {
	var result rotatedRelayCredentials
	p, err := client.loadNodeRefresh()
	if errors.Is(err, os.ErrNotExist) {
		priv, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return result, e
		}
		b := make([]byte, 16)
		if _, e = rand.Read(b); e != nil {
			return result, e
		}
		b[6] = (b[6] & 15) | 64
		b[8] = (b[8] & 63) | 128
		op := fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
		p = nodeRefreshPending{Version: 1, OperationID: op, Refresh: client.enrollment.Refresh.Token, WrapPrivate: c.Base64URL(priv.Bytes()), WrapPublic: c.Base64URL(priv.PublicKey().Bytes())}
		challenge := strings.Join([]string{"sparkclaw/iscp-node/refresh/v1", p.OperationID, c.Base64URL(c.SHA256([]byte(p.Refresh))), p.WrapPublic}, "\x00")
		p.Proof, e = client.device.CreateProof(client.provider, client.enrollment.RelayID, challenge, randomNonce(), time.Now().UTC())
		if e != nil {
			return result, e
		}
		if err = client.saveNodeRefresh(p); err != nil {
			return result, err
		}
	} else if err != nil {
		return result, err
	}
	proofRaw, _ := json.Marshal(p.Proof)
	body, _ := json.Marshal(map[string]string{"refresh": p.Refresh})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(client.enrollment.RelayBaseURL, "/")+relayRefreshPath, bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", p.OperationID)
	req.Header.Set("X-SparkClaw-Refresh-Wrap-Key", p.WrapPublic)
	req.Header.Set("X-SparkClaw-Refresh-Proof", c.Base64URL(proofRaw))
	res, err := client.client.Do(req)
	if err != nil {
		return result, errors.New("Relay refresh outcome unknown; retry retained operation")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return result, &relayHTTPError{status: res.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 32<<10))
	if err != nil {
		return result, err
	}
	var receipt nodeRelayReceipt
	if strictUnmarshal(raw, &receipt) != nil {
		return result, errors.New("invalid Relay refresh receipt")
	}
	digestRaw, _ := json.Marshal(struct {
		OperationID string               `json:"operation_id"`
		RefreshHash string               `json:"refresh_hash"`
		WrapPublic  string               `json:"wrap_public"`
		Proof       identity.DeviceProof `json:"proof"`
	}{p.OperationID, c.Base64URL(c.SHA256([]byte(p.Refresh))), p.WrapPublic, p.Proof})
	canonicalRaw, err := canonical.Marshal(digestRaw)
	if err != nil {
		return result, err
	}
	digest := c.Base64URL(c.SHA256(canonicalRaw))
	return openNodeRelayReceipt(receipt, p.OperationID, digest, p.WrapPrivate, client.device.Identity)
}

func openNodeRelayReceipt(receipt nodeRelayReceipt, operation, digest, private string, id identity.DeviceIdentity) (rotatedRelayCredentials, error) {
	var result rotatedRelayCredentials
	if receipt.SchemaVersion != 1 || receipt.State != "committed" || receipt.OperationID != operation || receipt.BindingDigest != digest || receipt.DomainID != id.DomainID || receipt.DeviceID != id.DeviceID {
		return result, errors.New("Relay refresh receipt binding mismatch")
	}
	privRaw, err := c.DecodeBase64URL(private)
	if err != nil {
		return result, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(privRaw)
	if err != nil {
		return result, err
	}
	serverRaw, err := c.DecodeBase64URL(receipt.EphemeralPublic)
	if err != nil {
		return result, err
	}
	server, err := ecdh.X25519().NewPublicKey(serverRaw)
	if err != nil {
		return result, err
	}
	shared, err := priv.ECDH(server)
	if err != nil {
		return result, err
	}
	transcript := []byte(strings.Join([]string{"sparkclaw/iscp-node/relay-receipt/v1", operation, digest, receipt.DomainID, receipt.DeviceID, id.PublicKey.KID}, "\x00"))
	info := append(append(append([]byte(nil), transcript...), priv.PublicKey().Bytes()...), serverRaw...)
	key, err := c.NewProvider().HKDF(shared, nil, info, 32)
	if err != nil {
		return result, err
	}
	nonce, err := c.DecodeBase64URL(receipt.Nonce)
	if err != nil || len(nonce) != 12 {
		return result, errors.New("invalid Relay receipt nonce")
	}
	cipher, err := c.DecodeBase64URL(receipt.Ciphertext)
	if err != nil {
		return result, err
	}
	plain, err := c.NewProvider().Open(key, nonce, cipher, transcript)
	if err != nil {
		return result, errors.New("Relay refresh receipt authentication failed")
	}
	if strictUnmarshal(plain, &result) != nil {
		return result, errors.New("invalid sealed Relay credentials")
	}
	return result, nil
}
