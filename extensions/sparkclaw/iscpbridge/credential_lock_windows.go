//go:build windows

package iscpbridge

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"time"
)

func lockCredentialFile(ctx context.Context, path string) (func(), error) {
	file, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	info, e := file.Stat()
	if e != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("invalid credential lock file")
	}
	overlapped := &windows.Overlapped{}
	for {
		e = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped)
		if e == nil {
			return func() { _ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, overlapped); _ = file.Close() }, nil
		}
		if e != windows.ERROR_LOCK_VIOLATION {
			file.Close()
			return nil, e
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Atomic file replacement and FlushFileBuffers in writeSecretFile provide the
// Windows durability boundary; directories cannot be fsynced through os.File.
func syncCredentialDirectory(string) error { return nil }
