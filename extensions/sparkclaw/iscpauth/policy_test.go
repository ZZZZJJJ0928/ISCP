package iscpauth

import (
	"maps"
	"testing"
	"time"
)

func TestPolicyRejectsAmbiguousPermanentAndLegacyMetadata(t *testing.T) {
	active := map[string]string{"authorization_version": "2", "authorization_lifetime": UntilRevoked, "authorization_revision": "1", "authorization_state": Active}
	for _, state := range []string{Active, Revoked} {
		data := maps.Clone(active)
		data["authorization_state"] = state
		p, err := Parse(data)
		if err != nil || p.Lifetime != UntilRevoked || !p.ExpiresAt.IsZero() {
			t.Fatal(p, err)
		}
		round := map[string]string{}
		p.AddTo(round)
		if !maps.Equal(data, round) {
			t.Fatal("policy did not round trip")
		}
	}
	for _, change := range []func(map[string]string){
		func(m map[string]string) { m["authorization_expires_at"] = "" },
		func(m map[string]string) { m["authorization_state"] = Expired },
		func(m map[string]string) { delete(m, "authorization_version") },
		func(m map[string]string) { m["authorization_revision"] = "0" },
		func(m map[string]string) { m["authorization_revision"] = "01" },
		func(m map[string]string) { m["authorization_revision"] = "18446744073709551616" },
		func(m map[string]string) { m["authorization_lifetime"] = "forever" },
	} {
		data := maps.Clone(active)
		change(data)
		if _, err := Parse(data); err == nil {
			t.Fatal("invalid policy accepted", data)
		}
	}
	legacy := map[string]string{"authorization_expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}
	if p, err := Parse(legacy); err != nil || p.Version != 1 || p.Lifetime != Bounded {
		t.Fatal(p, err)
	}
}

func TestScopesAreExplicitAndNeverWildcardOrMalformed(t *testing.T) {
	p := Policy{Version: 2, Lifetime: UntilRevoked, State: Active, Revision: 1, Scopes: []string{"settings.read", "tool.files.search"}}
	metadata := map[string]string{}
	p.AddTo(metadata)
	parsed, err := Parse(metadata)
	if err != nil || !parsed.Allows("settings.read") || parsed.Allows("settings.write") {
		t.Fatal(parsed, err)
	}
	for _, raw := range []string{`null`, `["*"]`, `["settings.read","settings.read"]`, `["Admin"]`, `[1]`} {
		metadata["authorization_scopes"] = raw
		if _, err := Parse(metadata); err == nil {
			t.Fatalf("invalid scopes accepted: %s", raw)
		}
	}
	delete(metadata, "authorization_scopes")
	old, err := Parse(metadata)
	if err != nil || old.Allows("settings.read") {
		t.Fatal("legacy authorization gained new scopes")
	}
}
