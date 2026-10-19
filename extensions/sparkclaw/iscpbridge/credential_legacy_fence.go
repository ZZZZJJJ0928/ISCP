package iscpbridge

import (
	"errors"
	"os"
	"path/filepath"
)

var ErrLegacyCredentialPending = errors.New("legacy credential operation remains unresolved; explicit maintenance required")

// CheckLegacyCredentialPending never imports, discards, or infers a terminal
// outcome for an old operation. Operators must resolve its original evidence
// before switching namespaces, and stop old helpers before maintenance.
func CheckLegacyCredentialPending(enrollmentPath string) error {
	if !filepath.IsAbs(enrollmentPath) {
		return ErrLegacyCredentialPending
	}
	for _, suffix := range []string{".refresh.pending", ".service-recovery"} {
		_, err := os.Lstat(enrollmentPath + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		return ErrLegacyCredentialPending
	}
	return nil
}
