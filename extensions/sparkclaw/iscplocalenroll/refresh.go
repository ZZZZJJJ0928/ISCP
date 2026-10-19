package iscplocalenroll

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
)

// Refresh reuses an existing local device and Relay refresh credential. Missing
// identity material fails closed; unlike Enroll, it never creates a device or
// calls bind-self.
func Refresh(ctx context.Context, opts Options) (Summary, error) {
	var summary Summary
	if opts.RelayURL != "" || opts.RelayID != "" || opts.DomainID != "" || opts.DeviceID != "" || opts.RuntimeRelayURL != "" || opts.RuntimeWebSocketURL != "" {
		return summary, errors.New("refresh-existing accepts only existing identity and enrollment paths")
	}
	directory, err := filepath.Abs(opts.IdentityDirectory)
	if err != nil || opts.IdentityDirectory == "" || opts.EnrollmentFile == "" {
		return summary, errors.New("existing private identity and enrollment paths are required")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return summary, errors.New("local identity directory must be private (0700)")
	}
	path, err := filepath.Abs(opts.EnrollmentFile)
	if err != nil {
		return summary, err
	}
	bundle, err := loadEnrollment(path)
	if err != nil {
		return summary, err
	}
	identityPath, keyPath := filepath.Join(directory, iscpbridge.IdentityFileName), filepath.Join(directory, iscpbridge.IdentityKeyFileName)
	for _, p := range []string{identityPath, keyPath} {
		info, err := os.Lstat(p)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 32<<10 || info.Mode().Perm()&0077 != 0 {
			return summary, errors.New("existing private device material is required")
		}
	}
	device, err := iscpbridge.LoadDeviceWithKeyBackend(identityPath, keyPath, iscpbridge.IdentityKeyBackendFile, "")
	if err != nil {
		return summary, errors.New("load existing local device identity")
	}
	updated, err := iscpbridge.RefreshLocalRelayEnrollment(ctx, path, bundle, device)
	if err != nil {
		return summary, err
	}
	return Summary{Profile: iscpbridge.ProfileLocalLab, DomainID: updated.DomainID, DeviceID: updated.DeviceID, DeviceThumbprint: device.Identity.PublicKey.KID, RelayID: updated.RelayID, RelayURL: updated.RelayBaseURL, RelayWebSocketURL: updated.RelayWebSocketURL, RelaySignerThumbprint: updated.RelaySignerIdentity.PublicKey.KID, IdentityDirectory: directory, IdentityFile: identityPath, EnrollmentFile: path}, nil
}
