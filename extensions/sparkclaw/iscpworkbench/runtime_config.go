package iscpworkbench

import (
	"context"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
)

// LoadRuntimeConfig adds verified local Relay recovery to process startup.
// LoadConfig (and -check) remain read-only and reject expired enrollments.
// Recovery requires the same private device, pinned local Relay and a live
// refresh credential; no expired bundle authorizes a business connection.
func LoadRuntimeConfig(ctx context.Context, path string) (Config, error) {
	cfg, originalErr := LoadConfig(path)
	if originalErr == nil {
		return cfg, nil
	}
	// The control loader retains every private-key, peer, issuer and historical
	// Grant check while allowing expired Relay data for recovery inspection.
	cfg, err := LoadControlConfig(path)
	if err == nil && cfg.Mode == "node-managed" {
		m, err := loadMaterialMode(cfg, true)
		if err != nil {
			return Config{}, originalErr
		}
		return recoverNodeRuntime(ctx, path, cfg, m)
	}
	if err != nil || cfg.EffectiveRelayProfile() != iscpbridge.ProfileLocalLab {
		return Config{}, originalErr
	}
	material, err := loadMaterialMode(cfg, true)
	if err != nil || material.enrollment.Mode != iscpbridge.BundleModeWorkbenchLocalLab || time.Now().Before(material.enrollment.ExpiresAt) || !time.Now().Before(material.enrollment.Refresh.ExpiresAt) {
		return Config{}, originalErr
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err = iscpbridge.RefreshLocalRelayEnrollment(ctx, cfg.EnrollmentFile, material.enrollment, material.device); err != nil {
		return Config{}, err
	}
	return LoadConfig(path)
}
