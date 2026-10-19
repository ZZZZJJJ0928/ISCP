package iscpbridge

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialV2PreservesLegacyPendingWithoutRecoveryAttempt(t *testing.T) {
	for _, suffix := range []string{".refresh.pending", ".service-recovery"} {
		t.Run(suffix, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "enrollment")
			original := []byte("original-encrypted-operation-and-id")
			if err := os.WriteFile(path+suffix, original, 0600); err != nil {
				t.Fatal(err)
			}
			r := &RelayClient{enrollmentPath: path}
			calls := 0
			recover := func(context.Context, CredentialBinding, CredentialGeneration) (CredentialLease, error) {
				calls++
				return CredentialLease{}, nil
			}
			if err := r.ConfigureCredentialProvider(CredentialBinding{}, recover); !errors.Is(err, ErrLegacyCredentialPending) {
				t.Fatal("configuration ignored old operation", err)
			}
			p := &managedCredentialProvider{relay: r, recovery: recover}
			if _, err := p.EnsureAccess(t.Context(), CredentialBinding{}); !errors.Is(err, ErrLegacyCredentialPending) {
				t.Fatal("recovery ignored late old operation", err)
			}
			if calls != 0 {
				t.Fatal("new protocol attempted recovery beside old unknown")
			}
			got, err := os.ReadFile(path + suffix)
			if err != nil || !bytes.Equal(original, got) {
				t.Fatal("old evidence was altered", err)
			}
			if _, err := os.Stat(path + ".service.operations.v2"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("new protocol journal was created")
			}
		})
	}
}
