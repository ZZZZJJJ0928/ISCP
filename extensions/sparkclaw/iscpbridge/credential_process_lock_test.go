package iscpbridge

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCredentialCheckpointSerializesIndependentProcesses(t *testing.T) {
	if path := os.Getenv("ISCP_TEST_CREDENTIAL_LOCK_CHILD"); path != "" {
		ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		defer cancel()
		unlock, err := lockCredentialFile(ctx, path)
		if os.Getenv("ISCP_TEST_CREDENTIAL_LOCK_BLOCKED") == "1" {
			if !errors.Is(err, context.DeadlineExceeded) {
				if unlock != nil {
					unlock()
				}
				t.Fatal("independent process crossed held file lock", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		unlock()
		return
	}
	path := filepath.Join(t.TempDir(), "credential-checkpoint.lock")
	unlock, err := lockCredentialFile(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	run := func(blocked string) {
		command := exec.Command(os.Args[0], "-test.run=^TestCredentialCheckpointSerializesIndependentProcesses$", "-test.count=1")
		command.Env = append(os.Environ(), "ISCP_TEST_CREDENTIAL_LOCK_CHILD="+path, "ISCP_TEST_CREDENTIAL_LOCK_BLOCKED="+blocked)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("independent process lock: %v %s", err, output)
		}
	}
	run("1")
	unlock()
	unlock = nil
	run("0")
}
