package iscpnodeclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	bridge "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
)

// UpgradeControlV2 is an explicit maintenance operation, never a runtime
// fallback. It neither imports old operation history nor consumes an invitation.
// The operator must stop the old helper and fence old server writers first.
func (cl *Client) UpgradeControlV2(ctx context.Context, evidence string) (StoredConfig, error) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if !node.ValidActivationEvidence(evidence) {
		return StoredConfig{}, node.ErrInvalid
	}
	if err := cl.noLegacyPending(); err != nil {
		return StoredConfig{}, err
	}
	transport, err := control.NewClient(cl.cfg.Origin, cl.cfg.IssuerIdentity.DeviceID, cl.device, cl.cfg.IssuerIdentity, cl.http)
	if err != nil {
		return StoredConfig{}, err
	}
	probe := control.Request{Action: "lookup", Key: control.Key{DomainID: cl.device.Identity.DomainID, DeviceID: cl.device.Identity.DeviceID, Namespace: control.CredentialNamespace, OperationID: "maintenance-" + control.RandomID()}, SemanticDigest: control.RandomID()}
	out, err := transport.Attempt(ctx, probe, "")
	if err != nil {
		return StoredConfig{}, err
	}
	if out.Status == nil || out.Status.State != "absent" || !out.Status.HistoryComplete || out.Status.CredentialGeneration == "0" {
		return StoredConfig{}, control.ErrUnknown
	}
	// A short file critical section covers only local evidence persistence. The
	// fresh HTTPS proof and all network I/O above are outside every file lock.
	unlock, err := bridge.LockPrivateCheckpoint(ctx, filepath.Join(cl.directory, controlJournalName+".lock"))
	if err != nil {
		return StoredConfig{}, err
	}
	defer unlock()
	if err = cl.noLegacyPending(); err != nil {
		return StoredConfig{}, err
	}
	if err = cl.write("control-cutover.v2", struct {
		Evidence string          `json:"activation_evidence_sha256"`
		Config   StoredConfig    `json:"original_config"`
		Probe    control.Request `json:"probe"`
		Status   *control.Status `json:"status"`
		At       time.Time       `json:"recorded_at"`
	}{evidence, cl.cfg, probe, out.Status, time.Now().UTC()}); err != nil {
		return StoredConfig{}, err
	}
	cl.cfg.ControlV2 = true
	return cl.StoredConfig(), nil
}

func (cl *Client) noLegacyPending() error {
	_, err := os.Lstat(filepath.Join(cl.directory, "lifecycle.pending"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return node.ErrLegacyPending
}
