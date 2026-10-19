package iscpnodeissuer

import (
	"errors"
	"testing"

	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
)

func TestExplicitIssuerHistoryCutoverPreservesUnresolvedLegacyEvidence(t *testing.T) {
	store := NewMemoryStore()
	f, _ := controlFixture(t, store)
	id := f.credential.InvitationID
	if err := store.Update(t.Context(), id, func(s *State) error {
		s.Control = nil
		s.Operations["legacy-pending"] = &Operation{ID: "legacy-pending", State: "pending", Renew: &LifecycleRequest{Kind: "recover"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	evidence := control.RandomID()
	if err := f.issuer.ActivateControlHistory(t.Context(), id, evidence); !errors.Is(err, ErrLegacyPending) {
		t.Fatal("unknown old operation was imported or discarded", err)
	}
	s, _ := store.Read(t.Context(), id)
	if s.Control != nil || s.Operations["legacy-pending"].State != "pending" {
		t.Fatal("maintenance altered unresolved history")
	}
	if err := store.Update(t.Context(), id, func(s *State) error { s.Operations["legacy-pending"].State = "applied"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := f.issuer.ActivateControlHistory(t.Context(), id, evidence); err != nil {
		t.Fatal(err)
	}
	s, _ = store.Read(t.Context(), id)
	if s.Control == nil || s.Control.ActivationEvidence != evidence || s.Control.Generation != "1" || s.Operations["legacy-pending"].State != "applied" || s.Device.DeviceID != f.client.Identity.DeviceID {
		t.Fatal("explicit cutover replaced original binding or evidence")
	}
	if err := f.issuer.ActivateControlHistory(t.Context(), id, evidence); !errors.Is(err, ErrConflict) {
		t.Fatal("maintenance reinitialized an established namespace", err)
	}
}
