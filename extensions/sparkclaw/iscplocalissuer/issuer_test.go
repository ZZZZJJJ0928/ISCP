package iscplocalissuer

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

func fixture(t *testing.T) (*Issuer, string) {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"desktop", "backend"} {
		dev, err := identity.NewDevice(iscpcrypto.NewProvider(), "approved-test-domain", name, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(dev.Identity)
		if err = os.WriteFile(filepath.Join(root, name+".json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(root, "issuer")
	if _, err := Initialize(dir, filepath.Join(root, "desktop.json"), filepath.Join(root, "backend.json"), "approved-relay"); err != nil {
		t.Fatal(err)
	}
	issuer, err := Load(filepath.Join(dir, "issuer.json"))
	if err != nil {
		t.Fatal(err)
	}
	return issuer, dir
}

func TestFixedGrantIsSDKVerifiableAndAudited(t *testing.T) {
	i, dir := fixture(t)
	grant, err := i.Sign(30 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tp, _ := identity.Thumbprint(i.subject)
	opts := trust.VerifyOptions{Audience: "backend", SubjectDeviceID: "desktop", ConfirmationThumbprint: tp, Permission: Permission, RelayID: "approved-relay", CurrentRevocationEpoch: 1, Now: time.Now().UTC()}
	if err = trust.VerifyGrant(iscpcrypto.NewProvider(), grant, i.device.Identity, opts); err != nil {
		t.Fatal(err)
	}
	opts.Now = grant.ExpiresAt
	if err = trust.VerifyGrant(iscpcrypto.NewProvider(), grant, i.device.Identity, opts); err == nil {
		t.Fatal("expired grant accepted")
	}
	journal, err := os.ReadFile(filepath.Join(dir, "issuance.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(journal, []byte(grant.GrantID)) || bytes.Contains(journal, []byte(grant.Signature.Value)) || bytes.Contains(journal, []byte(i.token)) {
		t.Fatal("journal missing provenance or leaks secrets")
	}
	if _, err = Initialize(dir, filepath.Join(filepath.Dir(dir), "desktop.json"), filepath.Join(filepath.Dir(dir), "backend.json"), "approved-relay"); err == nil {
		t.Fatal("overwrote issuer")
	}
}

func TestManagementRequiresAuthorizationAndCannotChoosePeers(t *testing.T) {
	i, _ := fixture(t)
	for _, tc := range []struct {
		body, credential string
		status           int
	}{
		{`{}`, "", 401},
		{`{}`, "Bearer wrong", 401},
		{`{}`, i.token, 401},
		{`{"subject_device_id":"another"}`, "Bearer " + i.token, 400},
		{`{"ttl_seconds":1801}`, "Bearer " + i.token, 400},
		{`{"ttl_seconds":-1}`, "Bearer " + i.token, 400},
		{`{} {}`, "Bearer " + i.token, 400},
		{strings.Repeat("x", 1025), "Bearer " + i.token, 400},
		{`{"ttl_seconds":1}`, "Bearer " + i.token, 200},
	} {
		r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/grants", strings.NewReader(tc.body))
		r.Header.Set("Authorization", tc.credential)
		w := httptest.NewRecorder()
		i.Handler().ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("body %q status %d want %d", tc.body, w.Code, tc.status)
		}
	}
}

func TestIssuerRejectsSymlinkSecretsAndCrossDomainPeers(t *testing.T) {
	i, dir := fixture(t)
	_ = i
	key := filepath.Join(dir, "issuer.key")
	if err := os.Rename(key, key+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key+".original", key); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "issuer.json")); err == nil {
		t.Fatal("symlink signing key accepted")
	}
	other, err := identity.NewDevice(iscpcrypto.NewProvider(), "another-domain", "backend", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(other.Identity)
	audience := filepath.Join(filepath.Dir(dir), "backend.json")
	_ = os.WriteFile(audience, raw, 0o600)
	if _, err := Initialize(dir+"-new", filepath.Join(filepath.Dir(dir), "desktop.json"), audience, "approved-relay"); err == nil {
		t.Fatal("cross Domain peers accepted")
	}
}
