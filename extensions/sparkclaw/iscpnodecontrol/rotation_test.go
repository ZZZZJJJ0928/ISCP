package iscpnodecontrol

import (
	"bytes"
	"context"
	"encoding/json"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type verifyingAdapter struct {
	revoked  bool
	verified int
}

func (v *verifyingAdapter) Prepare(context.Context, n.RegistrationPreparation) error {
	return n.ErrDenied
}
func (v *verifyingAdapter) Commit(context.Context, n.RegistrationCommit) (n.RegistrationReceipt, error) {
	return n.RegistrationReceipt{}, n.ErrDenied
}
func (v *verifyingAdapter) Status(context.Context, string, string) (n.RegistrationReceipt, error) {
	return n.RegistrationReceipt{}, n.ErrDenied
}
func (v *verifyingAdapter) Revoke(context.Context, string, string, uint64) error { return n.ErrDenied }
func (v *verifyingAdapter) Recover(context.Context, n.RegistrationRecovery) (n.RegistrationReceipt, error) {
	return n.RegistrationReceipt{}, n.ErrDenied
}
func (v *verifyingAdapter) VerifyServicePeer(context.Context, identity.DeviceIdentity, identity.DeviceProof, string) error {
	v.verified++
	if v.revoked {
		return n.ErrDenied
	}
	return nil
}
func TestControlGrantRotationPersistsProofAndRejectsRollbackAndRevokedService(t *testing.T) {
	a, b, signer := newDevice(t, "agent"), newDevice(t, "broker"), newDevice(t, "grant-issuer")
	sign := func(id string, before, after time.Time, permission string) trust.Grant {
		g, e := trust.SignGrant(c.NewProvider(), signer, trust.Grant{GrantID: id, SubjectDeviceID: a.Identity.DeviceID, ConfirmationThumbprint: a.Identity.PublicKey.KID, Audience: b.Identity.DeviceID, Permissions: []string{permission}, RelayConstraints: []string{"relay"}, NotBefore: before, ExpiresAt: after, RevocationEpoch: 1})
		if e != nil {
			t.Fatal(e)
		}
		return g
	}
	now := time.Now().UTC()
	seed := sign("expired-seed", now.Add(-time.Hour), now.Add(-time.Minute), ControlPermission)
	dir := filepath.Join(t.TempDir(), "private")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, "control.grant.json")
	raw, _ := json.Marshal(seed)
	if n.WritePrivateAtomic(file, raw) != nil {
		t.Fatal("private seed persistence")
	}
	h := &hub{queues: map[string][]json.RawMessage{}}
	peer, e := newPeer(PeerConfig{false, b, a.Identity, signer.Identity, seed, "relay"}, queuedRelay{h, b.Identity.DeviceID}, nil, true, true, file)
	if e != nil || peer.Ready() {
		t.Fatal("expired seed cannot authorize payload", e)
	}
	adapter := &verifyingAdapter{}
	f, e := NewForwarder("node-route", peer, adapter)
	if e != nil {
		t.Fatal(e)
	}
	fresh := sign("fresh-grant", now, now.Add(7*24*time.Hour), ControlPermission)
	build := func(g trust.Grant, nonce string) ControlGrantUpdate {
		proof, e := a.CreateProof(c.NewProvider(), b.Identity.DeviceID, ControlGrantChallenge("node-route", g), nonce, time.Now().UTC())
		if e != nil {
			t.Fatal(e)
		}
		return ControlGrantUpdate{1, "node-route", a.Identity, g, proof}
	}
	request := build(fresh, "proof-nonce-original")
	post := func(x ControlGrantUpdate) int {
		body, _ := json.Marshal(x)
		req := httptest.NewRequest("POST", ControlGrantPath, bytes.NewReader(body))
		res := httptest.NewRecorder()
		f.Handler().ServeHTTP(res, req)
		return res.Code
	}
	if status := post(request); status != 200 {
		t.Fatal("approved rotation failed", status)
	}
	if post(request) != 200 {
		t.Fatal("byte-identical repeat failed")
	}
	var persisted trust.Grant
	if ReadPrivate(file, &persisted) != nil || persisted.GrantID != fresh.GrantID {
		t.Fatal("Grant file not durable")
	}
	if _, e = ReadPrivateBytes(file + ".proof-receipts"); e != nil {
		t.Fatal("proof receipt missing", e)
	}
	rollback := sign("rollback-grant", now.Add(-time.Minute), now.Add(time.Hour), ControlPermission)
	if post(build(rollback, "rollback-nonce")) != 403 {
		t.Fatal("Grant rollback accepted")
	}
	widened := sign("business-grant", now.Add(time.Second), now.Add(time.Hour), n.Permission)
	if post(build(widened, "widen-nonce")) != 403 {
		t.Fatal("business permission allowed by control policy")
	}
	next := sign("next-grant", now.Add(time.Millisecond), now.Add(time.Hour), ControlPermission)
	if post(build(next, request.Proof.Nonce)) != 403 {
		t.Fatal("changed proof under same nonce admitted")
	}
	adapter.revoked = true
	if post(request) != 403 {
		t.Fatal("cached active grant revived revoked service")
	}
	if adapter.verified < 5 {
		t.Fatal("live service state was not checked for every attempt")
	}
}
func TestPrivateSocketCrashRecoveryPreservesLiveAndOrdinaryFiles(t *testing.T) {
	dir, e := os.MkdirTemp(os.TempDir(), "node-s-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "issuer.sock")
	listener, e := ListenPrivateUnix(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ListenPrivateUnix(path); e != n.ErrConflict {
		t.Fatal("live socket displaced", e)
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	listener.Close()
	recovered, e := ListenPrivateUnix(path)
	if e != nil {
		t.Fatal("dead socket not recovered", e)
	}
	recovered.Close()
	file := filepath.Join(dir, "ordinary")
	if e = os.WriteFile(file, []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ListenPrivateUnix(file); e != n.ErrConflict {
		t.Fatal("ordinary file displaced", e)
	}
}
