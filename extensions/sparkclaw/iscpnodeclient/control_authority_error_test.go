package iscpnodeclient

import (
	"errors"
	"testing"
	"time"

	bridge "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func TestVerifiedIssuerTerminalCannotRegressItsOwnRevision(t *testing.T) {
	issuer, err := identity.NewDevice(c.NewProvider(), "domain", "issuer", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	cl := &Client{cfg: StoredConfig{IssuerIdentity: issuer.Identity, Revision: 7}}
	// The wire client has already verified correlation and the issuer signature.
	// This boundary compares only that issuer's counter, never the Relay lease's.
	for _, tc := range []struct {
		revision string
		terminal bool
	}{{"6", false}, {"7", true}, {"8", true}} {
		t.Run(tc.revision, func(t *testing.T) {
			revision := control.Counter(tc.revision)
			result := cl.controlAuthorityError(&control.Error{Code: "authorization_revoked", AuthorizationRevision: &revision})
			var source *bridge.CredentialAuthorityTermination
			if errors.As(result, &source) != tc.terminal {
				t.Fatalf("terminal=%v: %v", tc.terminal, result)
			}
			if tc.terminal && (source.AuthorityPublicKey != issuer.Identity.PublicKey.Public || source.AuthorizationRevision != tc.revision) {
				t.Fatalf("wrong source: %+v", source)
			}
		})
	}
}
