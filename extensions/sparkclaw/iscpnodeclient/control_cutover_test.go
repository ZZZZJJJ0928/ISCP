package iscpnodeclient

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
)

func TestExplicitControlUpgradePreservesIdentityAndBlocksLegacyPending(t *testing.T) {
	cl, _, _, _, _ := setupClientStoreMode(t, time.Minute, node.NewMemoryStore(), "upgrade-control-operation", true)
	enrolled, err := cl.Enroll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	cl.cfg.ControlV2 = false // Existing disk config is never silently upgraded.
	original := cl.StoredConfig()
	if cl.UsesControlV2() {
		t.Fatal("legacy client silently upgraded")
	}
	evidence := control.RandomID()
	if err = cl.write("lifecycle.pending", map[string]string{"operation_id": "unknown-old-operation"}); err != nil {
		t.Fatal(err)
	}
	if _, err = cl.UpgradeControlV2(t.Context(), evidence); !errors.Is(err, node.ErrLegacyPending) {
		t.Fatal("legacy pending was discarded", err)
	}
	if _, err = os.Stat(filepath.Join(cl.directory, "lifecycle.pending")); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(cl.directory, "lifecycle.pending")); err != nil {
		t.Fatal(err)
	}
	upgraded, err := cl.UpgradeControlV2(t.Context(), evidence)
	if err != nil {
		t.Fatal(err)
	}
	if !upgraded.ControlV2 {
		t.Fatal("upgrade missing")
	}
	upgraded.ControlV2 = false
	if !reflect.DeepEqual(original, upgraded) {
		t.Fatal("upgrade changed original authority or binding")
	}
	var receipt struct {
		Evidence string          `json:"activation_evidence_sha256"`
		Status   *control.Status `json:"status"`
	}
	if err = cl.read("control-cutover.v2", &receipt); err != nil || receipt.Evidence != evidence || receipt.Status == nil || !receipt.Status.HistoryComplete {
		t.Fatal("cutover evidence missing", err)
	}
	if err = cl.write("lifecycle.pending", map[string]string{"operation_id": "late-old-helper"}); err != nil {
		t.Fatal(err)
	}
	if _, err = NewStored(cl.StoredConfig(), cl.device, cl.directory, enrolled.Grant); !errors.Is(err, node.ErrLegacyPending) {
		t.Fatal("v2 startup ignored old helper evidence", err)
	}
}
