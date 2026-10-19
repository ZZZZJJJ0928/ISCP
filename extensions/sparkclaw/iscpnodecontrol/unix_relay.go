package iscpnodecontrol

import (
	"bytes"
	"context"
	"encoding/json"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"time"
)

type UnixRelay struct{ http *http.Client }

func NewUnixRelay(socket string) (*UnixRelay, error) {
	if !filepath.IsAbs(socket) {
		return nil, n.ErrInvalid
	}
	return &UnixRelay{&http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}, CheckRedirect: func(*http.Request, []*http.Request) error { return n.ErrDenied }}}, nil
}
func (u *UnixRelay) call(ctx context.Context, method string, in, out any) error {
	return u.callPath(ctx, "/v1/registrations/"+method, in, out)
}
func (u *UnixRelay) callPath(ctx context.Context, path string, in, out any) error {
	b, e := json.Marshal(in)
	if e != nil {
		return n.ErrInvalid
	}
	req, e := http.NewRequestWithContext(ctx, "POST", "http://local"+path, bytes.NewReader(b))
	if e != nil {
		return n.ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := u.http.Do(req)
	if e != nil {
		return n.ErrUnknownOutcome
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, n.MaxFrameBytes+1))
	if e != nil || len(raw) > n.MaxFrameBytes {
		return n.ErrUnavailable
	}
	if res.StatusCode != 200 && res.StatusCode != 201 {
		switch res.StatusCode {
		case 400:
			return n.ErrInvalid
		case 401, 403:
			return n.ErrDenied
		case 409:
			return n.ErrConflict
		case 410:
			return n.ErrExpired
		default:
			return n.ErrUnavailable
		}
	}
	if out != nil {
		if e = json.Unmarshal(raw, out); e != nil {
			return n.ErrUnavailable
		}
	}
	return nil
}
func (u *UnixRelay) Prepare(ctx context.Context, p n.RegistrationPreparation) error {
	return u.call(ctx, "prepare", p, nil)
}
func (u *UnixRelay) Commit(ctx context.Context, p n.RegistrationCommit) (n.RegistrationReceipt, error) {
	var out n.RegistrationReceipt
	e := u.call(ctx, "commit", p, &out)
	return out, e
}
func (u *UnixRelay) Status(ctx context.Context, op, digest string) (n.RegistrationReceipt, error) {
	var out n.RegistrationReceipt
	e := u.call(ctx, "status", map[string]string{"operation_id": op, "binding_digest": digest}, &out)
	return out, e
}
func (u *UnixRelay) Revoke(ctx context.Context, op, device string, rev uint64) error {
	return u.call(ctx, "revoke", struct {
		OperationID string `json:"operation_id"`
		DeviceID    string `json:"device_id"`
		Revision    uint64 `json:"revision"`
	}{op, device, rev}, nil)
}
func (u *UnixRelay) Recover(ctx context.Context, p n.RegistrationRecovery) (n.RegistrationReceipt, error) {
	var out n.RegistrationReceipt
	e := u.call(ctx, "recover", p, &out)
	return out, e
}

func (u *UnixRelay) VerifyServicePeer(ctx context.Context, id identity.DeviceIdentity, proof identity.DeviceProof, challenge string) error {
	var out struct {
		State    string `json:"state"`
		DeviceID string `json:"device_id"`
	}
	e := u.callPath(ctx, "/v1/service-peers/verify", struct {
		Identity  identity.DeviceIdentity `json:"identity"`
		Proof     identity.DeviceProof    `json:"proof"`
		Challenge string                  `json:"challenge"`
	}{id, proof, challenge}, &out)
	if e != nil {
		return e
	}
	if out.State != "active" || out.DeviceID != id.DeviceID {
		return n.ErrDenied
	}
	return nil
}
