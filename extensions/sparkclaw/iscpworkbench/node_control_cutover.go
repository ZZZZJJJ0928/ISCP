package iscpworkbench

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
)

// UpgradeNodeControlV2 is used only by the explicit maintenance CLI. It retains
// the original private identity, binding and all issuer/Relay/TLS pins. A signed
// read-only lookup must prove the new control namespace exists before activation.
func UpgradeNodeControlV2(ctx context.Context, path, evidence string) error {
	if !iscpnodeissuer.ValidActivationEvidence(evidence) {
		return iscpnodeissuer.ErrInvalid
	}
	cfg, err := LoadControlConfig(path)
	if err != nil {
		return err
	}
	if cfg.Mode != "node-managed" || cfg.Role != RoleInitiator {
		return errors.New("control upgrade requires the original node-managed initiator")
	}
	if err = iscpbridge.CheckLegacyCredentialPending(cfg.EnrollmentFile); err != nil {
		return err
	}
	m, err := loadMaterialMode(cfg, true)
	if err != nil {
		return err
	}
	// Only this explicit migration recognizes the former transport path. The
	// normal runtime continues requiring the canonical duplex URL.
	ws, err := url.Parse(m.enrollment.RelayWebSocketURL)
	if err != nil || (ws.Path != "/v2/relay/connect" && ws.Path != "/v2/relay/duplex") {
		return errors.New("control upgrade requires a known original Relay path")
	}
	ws.Path = "/v2/relay/duplex"
	updated := m.enrollment
	updated.RelayWebSocketURL = ws.String()
	if err = iscpbridge.ValidateWorkbenchRelayURLs(cfg.EffectiveRelayProfile(), updated.RelayBaseURL, updated.RelayWebSocketURL); err != nil {
		return err
	}
	client, err := newNodeLifecycle(cfg, m)
	if err != nil {
		return err
	}
	stored, err := client.UpgradeControlV2(ctx, evidence)
	if err != nil {
		return err
	}
	// The encrypted cutover receipt is durable before either file changes. A
	// crash between the writes can safely repeat this explicit read-only command.
	if err = iscpbridge.SaveEnrollment(cfg.EnrollmentFile, updated); err != nil {
		return err
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	return iscpnodeissuer.WritePrivateAtomic(cfg.IssuerControlFile, raw)
}
