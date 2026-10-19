package iscpbridge

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func (c *RelayClient) localEnrollmentRefreshDue(bundle EnrollmentBundle) bool {
	return c.credentialOnly && (c.profile == ProfileLocalLab || bundle.Mode == BundleModeWorkbenchNodeManaged) && time.Until(bundle.ExpiresAt) <= time.Minute
}

// RefreshLocalRelayEnrollment repairs an expired local discovery envelope only
// through the original pinned Relay and its still-valid refresh credential.
// It never enrolls a device, changes trust/identity, or modifies session grants
// and standing authorization. Normal loading continues to reject expired data.
func RefreshLocalRelayEnrollment(ctx context.Context, path string, bundle EnrollmentBundle, device identity.Device) (EnrollmentBundle, error) {
	now := time.Now().UTC()
	if bundle.Mode != BundleModeWorkbenchLocalLab || bundle.RelaySignerIdentity == nil || !now.Before(bundle.Refresh.ExpiresAt) {
		return EnrollmentBundle{}, errors.New("local enrollment recovery requires an existing signer pin and valid refresh credential")
	}
	checkTime := now
	if !now.Before(bundle.ExpiresAt) {
		checkTime = bundle.ExpiresAt.Add(-time.Nanosecond)
	}
	if err := bundle.ValidateCredentials(checkTime); err != nil {
		return EnrollmentBundle{}, err
	}
	if err := ValidateLocalRelaySigner(*bundle.RelaySignerIdentity); err != nil {
		return EnrollmentBundle{}, err
	}
	client, err := NewRelayClient(ProfileLocalLab, path, bundle, device, 30*time.Second)
	if err != nil {
		return EnrollmentBundle{}, err
	}
	client.credentialOnly = true
	client.client.Transport = &http.Transport{Proxy: nil}
	client.client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("local Relay credential redirects are prohibited")
	}
	defer client.client.CloseIdleConnections()
	if err = client.refresh(ctx); err != nil {
		return EnrollmentBundle{}, err
	}
	return client.Enrollment(), nil
}
