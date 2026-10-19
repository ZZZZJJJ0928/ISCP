// Derived from ISCP v0.2.0-rc.1 reference Relay; see UPSTREAM_LICENSE.txt.
// Deployment adapters preserve its public protocol and persisted signer.
package iscprelayreference

import (
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistentSignerRestartAndFailClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{DomainID: "deployment-test", RelayID: "relay-test", SignerFile: filepath.Join(dir, "signer.json")}
	provider := crypto.NewProvider()
	first, err := persistentSigner(provider, cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := persistentSigner(provider, cfg, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if first.Identity.PublicKey != second.Identity.PublicKey || !first.Identity.CreatedAt.Equal(second.Identity.CreatedAt) {
		t.Fatal("restart changed identity")
	}
	now := time.Now()
	proof, err := second.CreateProof(provider, "test", "test", "nonce", now)
	if err != nil {
		t.Fatal(err)
	}
	if err = identity.VerifyProof(provider, first.Identity, proof, "test", "test", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(cfg.SignerFile)
	if err != nil {
		t.Fatal(err)
	}
	changed := cfg
	changed.DomainID = "wrong-domain"
	if _, err = persistentSigner(provider, changed, time.Now()); err == nil {
		t.Fatal("accepted mismatched domain")
	}
	after, err := os.ReadFile(cfg.SignerFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(original) != string(after) {
		t.Fatal("failure replaced signer")
	}
	if err = os.Chmod(cfg.SignerFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = persistentSigner(provider, cfg, time.Now()); err == nil {
		t.Fatal("accepted public key storage")
	}
	if err = os.Chmod(cfg.SignerFile, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg.SignerFile, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = persistentSigner(provider, cfg, time.Now()); err == nil {
		t.Fatal("replaced corrupt signer")
	}
}
