package iscpbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

const (
	GrantRenewalCapabilityPurpose = "sparkclaw-local-grant-renewal"
	grantLifecycleMaxBody         = 64 << 10
	grantLifecycleMaxPending      = 128 << 10
	grantLifecycleMaxRetryAfter   = 5 * time.Minute
)

// ErrGrantRenewalResultExpired means the original request succeeded with a
// verified Grant that has since expired. It was durably retired; the caller
// may attempt a fresh renewal, but must not authorize with the expired result.
var ErrGrantRenewalResultExpired = errors.New("confirmed Grant renewal result expired; retry with a fresh request")

// GrantLifecycleHTTPError contains only a status and bounded pacing hint. The
// issuer's response text and possession proof never enter diagnostics.
type GrantLifecycleHTTPError struct {
	StatusCode int
	delay      time.Duration
}

func (e *GrantLifecycleHTTPError) Error() string {
	return fmt.Sprintf("grant lifecycle HTTP %d", e.StatusCode)
}
func (e *GrantLifecycleHTTPError) RetryAfter() time.Duration { return e.delay }

type grantLifecycleRequest struct {
	Identity identity.DeviceIdentity `json:"identity"`
	Proof    identity.DeviceProof    `json:"identity_proof"`
}

type pendingGrantRenewal struct {
	SchemaVersion int         `json:"schema_version"`
	BaseURL       string      `json:"base_url"`
	DeviceID      string      `json:"device_id"`
	DeviceKey     string      `json:"device_key"`
	IssuerID      string      `json:"issuer_id"`
	IssuerKey     string      `json:"issuer_key"`
	RelayID       string      `json:"relay_id"`
	Key           string      `json:"idempotency_key"`
	Body          []byte      `json:"body_base64"`
	Previous      trust.Grant `json:"previous"`
	RetryAt       time.Time   `json:"retry_at,omitempty"`
}

// GrantLifecycleClient is a bounded, pinned local-issuer client. A renewal is
// one durable logical request: key, proof and encoded body all survive unknown
// outcomes. Call CommitRenewal only after the returned Grant has been saved.
type GrantLifecycleClient struct {
	mu             sync.Mutex
	baseURL        string
	pendingFile    string
	device         identity.Device
	issuer         identity.DeviceIdentity
	relayID        string
	provider       iscpcrypto.Provider
	http           *http.Client
	previous       trust.Grant
	pending        *pendingGrantRenewal
	completed      *trust.Grant
	retryAt        time.Time
	statusRetryAt  time.Time
	controlRetryAt time.Time
	standing       bool
	revoked        bool
}

// ValidateGrantLifecycleURL permits TLS issuer endpoints and explicit local
// HTTP endpoints only. Plain HTTP must be loopback or the fixed Docker alias.
func ValidateGrantLifecycleURL(baseURL string) error {
	u, err := url.Parse(baseURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return errors.New("invalid grant lifecycle issuer URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("grant lifecycle issuer requires HTTPS or explicit local HTTP")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("invalid grant lifecycle issuer port")
		}
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && host != "iscp-local-issuer" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("grant lifecycle plain HTTP issuer must be local")
		}
	}
	return nil
}

func NewGrantLifecycleClient(baseURL, pendingFile string, device identity.Device, issuer identity.DeviceIdentity, relayID string, previous trust.Grant, timeout time.Duration) (*GrantLifecycleClient, error) {
	if err := ValidateGrantLifecycleURL(baseURL); err != nil {
		return nil, err
	}
	if relayID == "" || pendingFile == "" || len(previous.Permissions) != 1 || device.Identity.DomainID != issuer.DomainID ||
		(device.Identity.DeviceID != previous.SubjectDeviceID && device.Identity.DeviceID != previous.Audience) {
		return nil, errors.New("grant lifecycle authorization binding is incomplete")
	}
	if ValidateLocalRelaySigner(device.Identity) != nil || ValidateLocalRelaySigner(issuer) != nil || len(device.Private.BytesForDevStore()) != 64 {
		return nil, errors.New("grant lifecycle identity or signer pin is invalid")
	}
	provider := iscpcrypto.NewProvider()
	if err := verifyGrantSnapshot(provider, previous, issuer, relayID); err != nil {
		return nil, err
	}
	thumb, _ := identity.Thumbprint(device.Identity)
	if device.Identity.DeviceID == previous.SubjectDeviceID && thumb != previous.ConfirmationThumbprint {
		return nil, errors.New("grant lifecycle subject key does not match the authorized Grant")
	}
	proof, err := device.CreateProof(provider, relayID, "grant-lifecycle-key-check", randomNonce(), time.Now().UTC())
	if err != nil || identity.VerifyProof(provider, device.Identity, proof, relayID, "grant-lifecycle-key-check", proof.IssuedAt, time.Second) != nil {
		return nil, errors.New("grant lifecycle private key does not match identity")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if timeout > time.Minute {
		return nil, errors.New("grant lifecycle timeout exceeds limit")
	}
	pendingFile, err = filepath.Abs(pendingFile)
	if err != nil {
		return nil, errors.New("invalid grant lifecycle pending file")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.HasPrefix(baseURL, "http://") {
		transport.Proxy = nil
	}
	c := &GrantLifecycleClient{baseURL: strings.TrimRight(baseURL, "/"), pendingFile: pendingFile, device: device, issuer: issuer,
		relayID: relayID, provider: provider, previous: cloneLifecycleGrant(previous), http: &http.Client{Timeout: timeout, Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("grant lifecycle redirects are prohibited")
			}}}
	if err := c.loadPending(); err != nil {
		c.http.CloseIdleConnections()
		return nil, err
	}
	return c, nil
}

func (c *GrantLifecycleClient) HasPendingRenewal() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pending != nil
}

func (c *GrantLifecycleClient) Current(ctx context.Context) (trust.Grant, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cap, err := c.capability(ctx, c.previous)
	if err != nil {
		return trust.Grant{}, err
	}
	key, body, err := c.newRequest()
	if err != nil {
		return trust.Grant{}, err
	}
	raw, err := c.request(ctx, http.MethodPost, "/v1/grants/current", key, body)
	if err != nil {
		return trust.Grant{}, err
	}
	grant, err := c.decodeGrant(raw)
	if err != nil {
		return trust.Grant{}, err
	}
	if err := c.verifyResult(grant, c.previous, cap, false); err != nil {
		return trust.Grant{}, err
	}
	return grant, nil
}

func (c *GrantLifecycleClient) Renew(ctx context.Context, previous trust.Grant) (trust.Grant, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.device.Identity.DeviceID != previous.SubjectDeviceID {
		return trust.Grant{}, errors.New("only the Grant subject may renew")
	}
	if err := verifyGrantSnapshot(c.provider, previous, c.issuer, c.relayID); err != nil {
		return trust.Grant{}, err
	}
	if err := verifyLifecycleBaseline(previous, c.previous); err != nil {
		return trust.Grant{}, err
	}
	cap, err := c.capability(ctx, previous)
	if err != nil {
		return trust.Grant{}, err
	}
	if c.pending == nil {
		key, body, err := c.newRequest()
		if err != nil {
			return trust.Grant{}, err
		}
		c.pending = &pendingGrantRenewal{SchemaVersion: 1, BaseURL: c.baseURL, DeviceID: c.device.Identity.DeviceID, DeviceKey: c.device.Identity.PublicKey.KID,
			IssuerID: c.issuer.DeviceID, IssuerKey: c.issuer.PublicKey.KID, RelayID: c.relayID, Key: key, Body: body, Previous: cloneLifecycleGrant(previous)}
		if err := c.savePending(); err != nil {
			c.pending = nil
			return trust.Grant{}, err
		}
	}
	raw, err := c.request(ctx, http.MethodPost, "/v2/relay/devices/auto-renew-grant", c.pending.Key, c.pending.Body)
	if err != nil {
		var status *GrantLifecycleHTTPError
		if errors.As(err, &status) && status.StatusCode >= 400 && status.StatusCode < 500 && status.StatusCode != 408 && status.StatusCode != 429 {
			if clearErr := c.clearPending(); clearErr != nil {
				return trust.Grant{}, clearErr
			}
		} else if errors.As(err, &status) && status.StatusCode == 429 {
			c.pending.RetryAt = c.retryAt
			if saveErr := c.savePending(); saveErr != nil {
				return trust.Grant{}, saveErr
			}
		}
		return trust.Grant{}, err
	}
	grant, err := c.decodeGrant(raw)
	if err != nil {
		return trust.Grant{}, err
	}
	if !time.Now().UTC().Before(grant.ExpiresAt) {
		return trust.Grant{}, c.retireExpiredResult(grant, cap)
	}
	if err := c.verifyResult(grant, c.pending.Previous, cap, true); err != nil {
		return trust.Grant{}, err
	}
	// The caller may have saved the successful result and crashed before
	// CommitRenewal. Its current snapshot then equals the deduplicated result.
	if err := c.verifyResult(grant, previous, cap, false); err != nil {
		return trust.Grant{}, err
	}
	accepted := cloneLifecycleGrant(grant)
	c.completed = &accepted
	return grant, nil
}

// AcceptGrant advances the current-grant rollback fence after caller storage
// succeeds. Current does not mutate that fence before the caller has saved it.
func (c *GrantLifecycleClient) AcceptGrant(grant trust.Grant) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := verifyGrantContinuity(c.provider, grant, c.previous, c.issuer, c.relayID, time.Now().UTC(), false); err != nil {
		return err
	}
	c.previous = cloneLifecycleGrant(grant)
	return nil
}

// CommitRenewal retires a successfully verified logical request only after
// the caller durably saved its result. Unknown or rejected results cannot be
// committed. A crash before this call leaves the same bytes replayable.
func (c *GrantLifecycleClient) CommitRenewal() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		return nil
	}
	if c.completed == nil {
		return errors.New("cannot commit an unconfirmed Grant renewal")
	}
	accepted := cloneLifecycleGrant(*c.completed)
	if err := c.clearPending(); err != nil {
		return err
	}
	if verifyLifecycleBaseline(accepted, c.previous) == nil {
		c.previous = accepted
	}
	return nil
}

func (c *GrantLifecycleClient) newRequest() (string, []byte, error) {
	key := newWireID("grant")
	proof, err := c.device.CreateProof(c.provider, c.relayID, key, randomNonce(), time.Now().UTC())
	if err != nil {
		return "", nil, errors.New("create Grant lifecycle possession proof")
	}
	body, err := json.Marshal(grantLifecycleRequest{Identity: c.device.Identity, Proof: proof})
	if err != nil {
		return "", nil, errors.New("encode Grant lifecycle request")
	}
	return key, body, nil
}

func (c *GrantLifecycleClient) verifyResult(grant, previous trust.Grant, cap descriptor.TrustRootDescriptor, extension bool) error {
	return c.verifyResultAt(grant, previous, cap, extension, time.Now().UTC())
}

func (c *GrantLifecycleClient) verifyResultAt(grant, previous trust.Grant, cap descriptor.TrustRootDescriptor, extension bool, now time.Time) error {
	if err := verifyGrantContinuity(c.provider, grant, previous, c.issuer, c.relayID, now, extension); err != nil {
		return err
	}
	policy, err := iscpauth.Parse(cap.Metadata)
	if err != nil {
		return err
	}
	if policy.Lifetime == iscpauth.Bounded && grant.ExpiresAt.After(policy.ExpiresAt) {
		return errors.New("Grant result exceeds the pinned authorization expiry")
	}
	return nil
}

func (c *GrantLifecycleClient) retireExpiredResult(grant trust.Grant, cap descriptor.TrustRootDescriptor) error {
	// Verify the issuer's success at a historically valid instant, with every
	// original renewal bound. This only resolves its outcome: neither the
	// expired Grant nor an older revocation epoch replaces the caller's fence.
	if err := c.verifyResultAt(grant, c.pending.Previous, cap, true, grant.NotBefore); err != nil {
		return err
	}
	if err := c.clearPending(); err != nil {
		return err
	}
	return ErrGrantRenewalResultExpired
}

func (c *GrantLifecycleClient) decodeGrant(raw []byte) (trust.Grant, error) {
	var result struct {
		Data  json.RawMessage `json:"data,omitempty"`
		Grant trust.Grant     `json:"grant"`
	}
	if strictUnmarshal(raw, &result) != nil || result.Grant.GrantID == "" {
		return trust.Grant{}, errors.New("invalid Grant lifecycle response")
	}
	return result.Grant, nil
}

func (c *GrantLifecycleClient) request(ctx context.Context, method, path, key string, body []byte) ([]byte, error) {
	retryAt := c.retryAt
	if path == iscpauth.StatusPath {
		retryAt = c.statusRetryAt
	} else if path == iscpauth.DeletePath || path == iscpauth.DeleteReceiptPath {
		retryAt = c.controlRetryAt
	}
	if delay := time.Until(retryAt); delay > 0 {
		return nil, &GrantLifecycleHTTPError{StatusCode: 429, delay: delay}
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("create Grant lifecycle HTTP request")
	}
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, errors.New("Grant lifecycle HTTP request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		status := &GrantLifecycleHTTPError{StatusCode: response.StatusCode}
		if response.StatusCode == http.StatusTooManyRequests {
			status.delay = boundedLifecycleRetryAfter(response.Header.Get("Retry-After"), time.Now().UTC())
			if path == iscpauth.StatusPath {
				c.statusRetryAt = time.Now().UTC().Add(status.delay)
			} else if path == iscpauth.DeletePath || path == iscpauth.DeleteReceiptPath {
				c.controlRetryAt = time.Now().UTC().Add(status.delay)
			} else {
				c.retryAt = time.Now().UTC().Add(status.delay)
			}
		}
		return nil, status
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, grantLifecycleMaxBody+1))
	if err != nil || len(raw) > grantLifecycleMaxBody {
		return nil, errors.New("Grant lifecycle response exceeds limit or is incomplete")
	}
	return raw, nil
}

func boundedLifecycleRetryAfter(value string, now time.Time) time.Duration {
	delay := time.Second
	if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 32); err == nil && seconds > 0 {
		delay = time.Duration(seconds) * time.Second
	} else if date, err := http.ParseTime(value); err == nil && date.After(now) {
		delay = date.Sub(now)
	}
	if delay > grantLifecycleMaxRetryAfter {
		delay = grantLifecycleMaxRetryAfter
	}
	return delay
}

func (c *GrantLifecycleClient) loadPending() error {
	info, err := os.Lstat(c.pendingFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > grantLifecycleMaxPending {
		return errors.New("Grant renewal pending file must be a bounded private regular file")
	}
	file, err := os.Open(c.pendingFile)
	if err != nil {
		return errors.New("read Grant renewal pending file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("Grant renewal pending file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, grantLifecycleMaxPending+1))
	if err != nil || len(raw) > grantLifecycleMaxPending {
		return errors.New("Grant renewal pending file exceeds limit or is unreadable")
	}
	var pending pendingGrantRenewal
	if strictUnmarshal(raw, &pending) != nil || pending.SchemaVersion != 1 || pending.BaseURL != c.baseURL || pending.DeviceID != c.device.Identity.DeviceID ||
		pending.DeviceKey != c.device.Identity.PublicKey.KID || pending.IssuerID != c.issuer.DeviceID || pending.IssuerKey != c.issuer.PublicKey.KID || pending.RelayID != c.relayID ||
		len(pending.Key) < 16 || len(pending.Key) > 128 || len(pending.Body) == 0 || len(pending.Body) > grantLifecycleMaxBody || pending.RetryAt.After(time.Now().UTC().Add(grantLifecycleMaxRetryAfter)) {
		return errors.New("Grant renewal pending request binding is invalid")
	}
	if verifyGrantSnapshot(c.provider, pending.Previous, c.issuer, c.relayID) != nil || verifyLifecycleBaseline(c.previous, pending.Previous) != nil {
		return errors.New("Grant renewal pending authorization snapshot is invalid")
	}
	var request grantLifecycleRequest
	if strictUnmarshal(pending.Body, &request) != nil || request.Identity.DeviceID != c.device.Identity.DeviceID || request.Identity.DomainID != c.device.Identity.DomainID ||
		request.Identity.PublicKey != c.device.Identity.PublicKey || request.Proof.Signature.Alg != "Ed25519" ||
		identity.VerifyProof(c.provider, c.device.Identity, request.Proof, c.relayID, pending.Key, request.Proof.IssuedAt, time.Second) != nil {
		return errors.New("Grant renewal pending possession proof is invalid")
	}
	c.pending = &pending
	c.retryAt = pending.RetryAt
	return nil
}

func verifyLifecycleBaseline(grant, previous trust.Grant) error {
	if verifyGrantPairingBounds(grant, previous) != nil || grant.Issuer != previous.Issuer || grant.Signature.KID != previous.Signature.KID ||
		!equalLifecycleScope(grant, previous) || grant.ExpiresAt.Before(previous.ExpiresAt) || grant.RevocationEpoch < previous.RevocationEpoch {
		return errors.New("Grant lifecycle snapshot rolls back the authorized pairing")
	}
	return nil
}

func equalLifecycleScope(a, b trust.Grant) bool {
	return slices.Equal(a.Permissions, b.Permissions) && slices.Equal(a.RelayConstraints, b.RelayConstraints)
}

func cloneLifecycleGrant(grant trust.Grant) trust.Grant {
	grant.Permissions = append([]string(nil), grant.Permissions...)
	grant.RelayConstraints = append([]string(nil), grant.RelayConstraints...)
	return grant
}

func (c *GrantLifecycleClient) savePending() error {
	if info, err := os.Lstat(c.pendingFile); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0) {
		return errors.New("Grant renewal pending path is not a private regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect Grant renewal pending file")
	}
	raw, err := json.Marshal(c.pending)
	if err != nil || len(raw) > grantLifecycleMaxPending || writeSecretFile(c.pendingFile, raw) != nil {
		return errors.New("persist Grant renewal pending request")
	}
	return syncGrantPendingDirectory(c.pendingFile)
}

func (c *GrantLifecycleClient) clearPending() error {
	if err := os.Remove(c.pendingFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("retire Grant renewal pending request")
	}
	if err := syncGrantPendingDirectory(c.pendingFile); err != nil {
		return err
	}
	c.pending, c.completed = nil, nil
	return nil
}

func syncGrantPendingDirectory(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("open Grant renewal pending directory")
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return errors.New("sync Grant renewal pending directory")
	}
	return nil
}
