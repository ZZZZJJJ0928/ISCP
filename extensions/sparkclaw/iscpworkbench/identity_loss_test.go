package iscpworkbench

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeclient"
)

func TestMissingOriginalPrivateKeyFailsClosedWithoutChangingEnrollmentOrPending(t *testing.T) {
	profile, cfg := nodeConfigurationFixture(t)
	raw, err := os.ReadFile(cfg.IssuerControlFile)
	if err != nil {
		t.Fatal(err)
	}
	var stored iscpnodeclient.StoredConfig
	if err = json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	stored.ControlV2 = true
	raw, err = json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg.IssuerControlFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(profile)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewEndpoint(loaded, nil, nil)
	if err != nil {
		t.Fatal("valid original profile could not start", err)
	}
	if err = endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	identityFile := filepath.Join(cfg.IdentityDirectory, iscpbridge.IdentityFileName)
	keyFile := filepath.Join(cfg.IdentityDirectory, iscpbridge.IdentityKeyFileName)
	original, err := iscpbridge.LoadDeviceWithKeyBackend(identityFile, keyFile, "file", "")
	if err != nil {
		t.Fatal(err)
	}
	// Existing pending ciphertext is opaque to startup until its original private
	// key is available. Missing-key paths must not replace or discard it.
	pending := filepath.Join(cfg.IdentityDirectory, "node-control", "operations.v2")
	if err = os.WriteFile(pending, []byte("retained-original-pending-ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot := func() map[string][]byte {
		t.Helper()
		files := map[string][]byte{}
		err := filepath.WalkDir(cfg.IdentityDirectory, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || path == keyFile {
				return nil
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(cfg.IdentityDirectory, path)
			if err != nil {
				return err
			}
			files[rel] = contents
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return files
	}
	before := snapshot()
	heldKey := filepath.Join(t.TempDir(), "original-private-key")
	if err = os.Rename(keyFile, heldKey); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		name string
		load func() error
	}{
		{"LoadDevice", func() error {
			_, err := iscpbridge.LoadDeviceWithKeyBackend(identityFile, keyFile, "file", "")
			return err
		}},
		{"LoadConfig", func() error { _, err := LoadConfig(profile); return err }},
		{"LoadControlConfig", func() error { _, err := LoadControlConfig(profile); return err }},
		{"LoadRuntimeConfig", func() error { _, err := LoadRuntimeConfig(t.Context(), profile); return err }},
		{"NewEndpoint", func() error {
			ep, err := NewEndpoint(loaded, nil, nil)
			if ep != nil {
				ep.Close()
				t.Fatal("consumer allocated a replacement identity")
			}
			return err
		}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			if err := entry.load(); err == nil {
				t.Fatal("missing original private key was accepted")
			}
			if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
				t.Fatal("a replacement private key was created", err)
			}
			if !reflect.DeepEqual(before, snapshot()) {
				t.Fatal("missing-key path changed original identity, pins, enrollment or pending evidence")
			}
		})
	}
	if err = os.Rename(heldKey, keyFile); err != nil {
		t.Fatal(err)
	}
	restored, err := iscpbridge.LoadDeviceWithKeyBackend(identityFile, keyFile, "file", "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.Identity, original.Identity) || !bytes.Equal(restored.Private.BytesForDevStore(), original.Private.BytesForDevStore()) {
		t.Fatal("restoring key did not retain original identity")
	}
	recovered, err := LoadRuntimeConfig(t.Context(), profile)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err = NewEndpoint(recovered, nil, nil)
	if err != nil {
		t.Fatal("restored original consumer could not initialize", err)
	}
	if err = endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, snapshot()) {
		t.Fatal("restoring original key changed enrollment or pending evidence")
	}
}
