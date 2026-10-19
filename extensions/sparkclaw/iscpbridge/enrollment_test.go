package iscpbridge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func TestRequirePrivateFileRejectsGroupOrOtherAccess(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o604} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if err := requirePrivateFile(path); err == nil || !strings.Contains(err.Error(), "group or other access") {
				t.Fatalf("requirePrivateFile(%#o) error = %v", mode.Perm(), err)
			}
		})
	}
}

func TestRequirePrivateFileAcceptsOwnerOnlyAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requirePrivateFile(path); err != nil {
		t.Fatalf("requirePrivateFile(0600): %v", err)
	}
}

func TestGenerateEnrollmentRequestIncludesVerifiableDeviceProof(t *testing.T) {
	now := time.Now().UTC()
	request, _, err := GenerateEnrollmentRequestWithProof(
		filepath.Join(t.TempDir(), "identity"),
		"domain-localmind", "sparkclaw-device", "arm64",
		IdentityKeyBackendFile, DefaultIdentityKeyringService,
		EnrollmentProofOptions{
			Audience:  "localmind-enrollment",
			Challenge: "short-lived-challenge",
			Nonce:     "test-nonce",
		},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.DeviceProof == nil {
		t.Fatal("enrollment request omitted the device proof")
	}
	if err := identity.VerifyProof(
		iscpcrypto.NewProvider(), request.Identity, *request.DeviceProof,
		"localmind-enrollment", "short-lived-challenge", now, time.Minute,
	); err != nil {
		t.Fatalf("verify enrollment proof: %v", err)
	}
}

func TestGenerateEnrollmentRequestRequiresChallengeAndAudienceTogether(t *testing.T) {
	_, _, err := GenerateEnrollmentRequestWithProof(
		filepath.Join(t.TempDir(), "identity"),
		"domain-localmind", "sparkclaw-device", "arm64",
		IdentityKeyBackendFile, DefaultIdentityKeyringService,
		EnrollmentProofOptions{Challenge: "challenge-only"},
		time.Now().UTC(),
	)
	if err == nil || !strings.Contains(err.Error(), "provided together") {
		t.Fatalf("incomplete proof options error = %v", err)
	}
}
