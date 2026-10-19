package iscpbridge

import "context"

// LockPrivateCheckpoint protects a short encrypted checkpoint read/CAS/write
// across helper processes. The caller must release it before network I/O.
func LockPrivateCheckpoint(ctx context.Context, path string) (func(), error) {
	return lockCredentialFile(ctx, path)
}
