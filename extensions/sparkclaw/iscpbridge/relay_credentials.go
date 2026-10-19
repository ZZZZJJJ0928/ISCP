package iscpbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func NewRelayClient(profile, enrollmentPath string, enrollment EnrollmentBundle, device identity.Device, timeout time.Duration) (*RelayClient, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if err := validateRelayURLs(profile, enrollment.RelayBaseURL, enrollment.RelayWebSocketURL); err != nil {
		return nil, err
	}
	if device.Identity.DomainID != enrollment.DomainID || device.Identity.DeviceID != enrollment.DeviceID {
		return nil, errors.New("device identity does not match enrollment")
	}
	return &RelayClient{
		provider:       iscpcrypto.NewProvider(),
		device:         device,
		enrollmentPath: enrollmentPath,
		profile:        profile,
		timeout:        timeout,
		client:         &http.Client{Timeout: timeout},
		enrollment:     enrollment,
	}, nil
}

// NewRelayCredentialClient uses enrolled cloud access credentials without
// importing Bridge session-grant semantics. End-to-end workbench grants and
// issuer pins remain entirely separate from this cloud credential bundle.
func NewRelayCredentialClient(profile, enrollmentPath string, enrollment EnrollmentBundle, device identity.Device, timeout time.Duration) (*RelayClient, error) {
	if err := ValidateWorkbenchRelayURLs(profile, enrollment.RelayBaseURL, enrollment.RelayWebSocketURL); err != nil {
		return nil, err
	}
	if profile == ProfileLocalLab && enrollment.Mode != BundleModeWorkbenchLocalLab {
		return nil, errors.New("local-lab Relay requires reference enrollment")
	}
	if profile == ProfileProduction && enrollment.Mode == BundleModeWorkbenchLocalLab {
		return nil, errors.New("production Relay rejects local-lab enrollment")
	}
	if err := enrollment.ValidateCredentials(time.Now().UTC()); err != nil {
		return nil, err
	}
	client, err := NewRelayClient(profile, enrollmentPath, enrollment, device, timeout)
	if err != nil {
		return nil, err
	}
	client.credentialOnly = true
	if profile == ProfileLocalLab {
		client.client.Transport = &http.Transport{Proxy: nil}
	} else if enrollment.Mode == BundleModeWorkbenchNodeManaged {
		tlsConfig, err := VerifiedTLSConfig(enrollment.TLSCertificatePEM)
		if err != nil {
			return nil, err
		}
		client.client.Transport = &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig}
		client.client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("Relay redirects are prohibited") }
	}
	return client, nil
}

func (c *RelayClient) validateEnrollment(bundle EnrollmentBundle, now time.Time) error {
	if c.credentialOnly {
		return bundle.ValidateCredentials(now)
	}
	return bundle.Validate(now)
}

func (c *RelayClient) Enrollment() EnrollmentBundle {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enrollment
}

func (c *RelayClient) ensureAccess(ctx context.Context) error {
	bundle := c.Enrollment()
	if time.Until(bundle.Access.ExpiresAt) > time.Minute && !c.localEnrollmentRefreshDue(bundle) && !c.hasNodeRefreshPending() {
		return nil
	}
	return c.refresh(ctx)
}

func (c *RelayClient) refresh(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Until(c.enrollment.Access.ExpiresAt) > time.Minute && !c.localEnrollmentRefreshDue(c.enrollment) && !c.hasNodeRefreshPending() {
		return nil
	}
	// Local enrollment validity comes from signed discovery and rotating Relay
	// credentials, independently of permanent workbench consent. Refresh both
	// together; otherwise a healthy daily credential rotation leaves yesterday's
	// outer bundle expiry behind and prevents the next connection/restart.
	var localExpiry time.Time
	if c.credentialOnly && c.enrollment.Mode == BundleModeWorkbenchNodeManaged {
		discovery, err := DiscoverNodeRelay(ctx, c.enrollment)
		if err != nil {
			return err
		}
		if discovery.Metadata["sparkclaw_refresh_receipts"] != "v1" {
			return errors.New("Relay has not declared transactional node refresh receipts")
		}
		localExpiry = discovery.ExpiresAt
	} else if c.credentialOnly && c.profile == ProfileLocalLab {
		if !time.Now().Before(c.enrollment.Refresh.ExpiresAt) {
			return errors.New("local Relay refresh credential expired")
		}
		discovery, _, err := DiscoverLocalRelay(ctx, c.enrollment.RelayBaseURL, c.enrollment.RelayID, c.enrollment.DomainID, c.enrollment.RelaySignerIdentity)
		if err != nil {
			return err
		}
		localExpiry = discovery.ExpiresAt
	}
	var credentials rotatedRelayCredentials
	if c.enrollment.Mode == BundleModeWorkbenchNodeManaged {
		var err error
		credentials, err = c.refreshNodeCredentials(ctx)
		if err != nil {
			return err
		}
	} else {
		body, _ := json.Marshal(map[string]string{"refresh": c.enrollment.Refresh.Token})
		endpoint := strings.TrimRight(c.enrollment.RelayBaseURL, "/") + relayRefreshPath
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return errors.New("create Relay credential refresh request")
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := c.client.Do(request)
		if err != nil {
			return fmt.Errorf("refresh Relay credential: %w", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, relayMaxBody))
			return &relayHTTPError{status: response.StatusCode}
		}
		decoder := json.NewDecoder(io.LimitReader(response.Body, relayMaxBody))
		if err := decoder.Decode(&credentials); err != nil {
			return errors.New("decode Relay credential refresh response")
		}
	}
	if credentials.Access.DomainID != c.enrollment.DomainID || credentials.Access.DeviceID != c.enrollment.DeviceID ||
		credentials.Refresh.DomainID != c.enrollment.DomainID || credentials.Refresh.DeviceID != c.enrollment.DeviceID {
		return errors.New("refreshed Relay credential has an invalid device binding")
	}
	now := time.Now().UTC()
	if !now.Before(credentials.Access.ExpiresAt) || !now.Before(credentials.Refresh.ExpiresAt) {
		return errors.New("refreshed Relay credentials are already expired")
	}
	updated := c.enrollment
	updated.Access = credentials.Access
	updated.Refresh = credentials.Refresh
	if !localExpiry.IsZero() {
		updated.ExpiresAt = localExpiry
		if credentials.Refresh.ExpiresAt.Before(updated.ExpiresAt) {
			updated.ExpiresAt = credentials.Refresh.ExpiresAt
		}
	}
	if err := c.validateEnrollment(updated, now); err != nil {
		return fmt.Errorf("validate refreshed Relay credentials: %w", err)
	}
	if err := SaveEnrollment(c.enrollmentPath, updated); err != nil {
		return fmt.Errorf("persist rotated Relay credentials: %w", err)
	}
	c.enrollment = updated
	if updated.Mode == BundleModeWorkbenchNodeManaged {
		if err := os.Remove(c.nodeRefreshPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("cleanup retained Relay refresh")
		}
	}
	return nil
}

func (c *RelayClient) accessProof(token, method, path, audience string) (string, error) {
	challenge := strings.Join([]string{
		"iscp/v2/relay/access-proof",
		strings.ToUpper(method),
		path,
		iscpcrypto.Base64URL(iscpcrypto.SHA256([]byte(token))),
	}, "\x00")
	proof, err := c.device.CreateProof(c.provider, audience, challenge, randomNonce(), time.Now().UTC())
	if err != nil {
		return "", errors.New("create Relay access proof")
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return "", errors.New("encode Relay access proof")
	}
	return iscpcrypto.Base64URL(raw), nil
}

// UpdateEnrollment applies a mutation to the enrollment bundle under the
// client lock and persists it atomically (used by grant renewal and
// credential recovery). The mutation must keep the bundle valid.
func (c *RelayClient) UpdateEnrollment(mutate func(*EnrollmentBundle)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	updated := c.enrollment
	mutate(&updated)
	if err := c.validateEnrollment(updated, time.Now().UTC()); err != nil {
		return fmt.Errorf("validate updated enrollment: %w", err)
	}
	if err := SaveEnrollment(c.enrollmentPath, updated); err != nil {
		return fmt.Errorf("persist updated enrollment: %w", err)
	}
	c.enrollment = updated
	return nil
}
