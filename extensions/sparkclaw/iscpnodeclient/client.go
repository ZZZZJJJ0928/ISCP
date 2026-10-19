// Package iscpnodeclient owns enrollment and lifecycle network operations. It
// never changes an active desktop profile; the helper activates a verified result.
package iscpnodeclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type StoredConfig struct {
	ControlV2           bool                    `json:"control_v2,omitempty"`
	Origin              string                  `json:"origin"`
	TLSCertificatePEM   string                  `json:"tls_certificate_pem"`
	IssuerRoute         string                  `json:"issuer_route"`
	InvitationID        string                  `json:"invitation_id"`
	IssuerIdentity      identity.DeviceIdentity `json:"issuer_identity"`
	RelaySignerIdentity identity.DeviceIdentity `json:"relay_signer_identity"`
	ResponderIdentity   identity.DeviceIdentity `json:"responder_identity"`
	Binding             iscpnodeissuer.Binding  `json:"binding"`
	Revision            uint64                  `json:"revision"`
	Scopes              []string                `json:"scopes"`
	RelayID             string                  `json:"relay_id"`
}
type PendingEnrollment struct {
	InstallationID   string                           `json:"installation_id"`
	Version          int                              `json:"version"`
	CredentialDigest string                           `json:"credential_digest"`
	OperationID      string                           `json:"operation_id"`
	Hello            iscpnodeissuer.ClientHello       `json:"hello"`
	Private          []byte                           `json:"private"`
	Channel          *iscpnodeissuer.Channel          `json:"channel,omitempty"`
	Redeem           *iscpnodeissuer.SealedFrame      `json:"redeem,omitempty"`
	Result           *iscpnodeissuer.EnrollmentResult `json:"result,omitempty"`
}
type Client struct {
	mu                   sync.Mutex
	authorityMu          sync.Mutex
	authorityFlight      *authorizationFlight
	authorityChanged     chan struct{}
	authorityGeneration  uint64
	authorityMutations   uint64
	authorityGrantDigest string
	authorityRevoked     bool
	credential           *iscpnodeissuer.Credential
	cfg                  StoredConfig
	device               identity.Device
	directory            string
	http                 *http.Client
	storageKey           []byte
	pending              *pendingLifecycle
	previous             trust.Grant
	completed            *trust.Grant
	revoked              bool
	installationID       string
}

func New(encoded string, device identity.Device, directory string) (*Client, error) {
	v, e := iscpnodeissuer.ParseCredential(encoded, time.Now().UTC(), true)
	if e != nil {
		return nil, e
	}
	client, e := newClient(StoredConfig{ControlV2: true, Origin: v.Origin, TLSCertificatePEM: v.TLSCertificatePEM, IssuerRoute: v.IssuerRoute, InvitationID: v.InvitationID, IssuerIdentity: v.IssuerIdentity, RelaySignerIdentity: v.RelaySignerIdentity, ResponderIdentity: v.ResponderIdentity, Binding: iscpnodeissuer.Binding{DeploymentID: v.DeploymentID, OwnerID: v.OwnerID, ClientID: v.ClientID}, Revision: 1, Scopes: v.Scopes, RelayID: v.RelayID}, device, directory, trust.Grant{})
	if e != nil {
		return nil, e
	}
	client.credential = &v
	return client, nil
}
func NewStored(cfg StoredConfig, device identity.Device, directory string, previous trust.Grant) (*Client, error) {
	cl, err := newClient(cfg, device, directory, previous)
	if err == nil && cfg.ControlV2 {
		err = cl.noLegacyPending()
	}
	if err != nil {
		return nil, err
	}
	return cl, nil
}
func newClient(cfg StoredConfig, device identity.Device, directory string, previous trust.Grant) (*Client, error) {
	if iscpnodeissuer.ValidateOrigin(cfg.Origin, cfg.TLSCertificatePEM, time.Now().UTC(), true) != nil {
		return nil, iscpnodeissuer.ErrInvalid
	}
	if iscpnodeissuer.ValidateIdentity(device.Identity) != nil || iscpnodeissuer.ValidateIdentity(cfg.IssuerIdentity) != nil || device.Identity.DomainID != cfg.IssuerIdentity.DomainID || len(device.Private.BytesForDevStore()) != 64 || !filepath.IsAbs(directory) || cfg.Revision == 0 {
		return nil, iscpnodeissuer.ErrInvalid
	}
	if e := os.MkdirAll(directory, 0700); e != nil {
		return nil, e
	}
	st, e := os.Lstat(directory)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return nil, iscpnodeissuer.ErrInvalid
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cfg.TLSCertificatePEM)) {
		return nil, iscpnodeissuer.ErrInvalid
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, MaxIdleConnsPerHost: 2, ResponseHeaderTimeout: 15 * time.Second}
	h := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return iscpnodeissuer.ErrDenied }}
	key, e := c.NewProvider().HKDF(device.Private.BytesForDevStore(), nil, []byte("sparkclaw/iscp-node/client-storage/v1\x00"+cfg.InvitationID+"\x00"+device.Identity.PublicKey.KID), 32)
	if e != nil {
		return nil, e
	}
	cfg.Scopes = append([]string(nil), cfg.Scopes...)
	previous = cloneGrant(previous)
	return &Client{cfg: cfg, device: device, directory: directory, http: h, storageKey: key, previous: previous, authorityGrantDigest: iscpnodeissuer.Digest(previous)}, nil
}
func (cl *Client) StoredConfig() StoredConfig {
	cfg := cl.cfg
	cfg.Scopes = append([]string(nil), cfg.Scopes...)
	return cfg
}
func (cl *Client) read(name string, out any) error {
	path := filepath.Join(cl.directory, name)
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4<<20 {
		return iscpnodeissuer.ErrInvalid
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(string(raw))
	if e != nil || len(b) < 28 {
		return iscpnodeissuer.ErrInvalid
	}
	plain, e := c.NewProvider().Open(cl.storageKey, b[:12], b[12:], []byte(name))
	if e != nil {
		return iscpnodeissuer.ErrDenied
	}
	return json.Unmarshal(plain, out)
}
func (cl *Client) write(name string, v any) error {
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > 4<<20 {
		return iscpnodeissuer.ErrInvalid
	}
	n := c.RandomBytes(12)
	ct, e := c.NewProvider().Seal(cl.storageKey, n, raw, []byte(name))
	if e != nil {
		return e
	}
	return iscpnodeissuer.WritePrivateAtomic(filepath.Join(cl.directory, name), []byte(c.Base64URL(append(n, ct...))))
}
func (cl *Client) exchange(ctx context.Context, operation, step string, frame any, out any) error {
	raw, e := json.Marshal(frame)
	if e != nil {
		return e
	}
	x := iscpnodeissuer.Exchange{Version: 1, IssuerRoute: cl.cfg.IssuerRoute, OperationID: operation, InvitationID: cl.cfg.InvitationID, Step: step, Frame: raw}
	body, _ := json.Marshal(x)
	req, e := http.NewRequestWithContext(ctx, "POST", cl.cfg.Origin+iscpnodeissuer.ExchangePath, bytes.NewReader(body))
	if e != nil {
		return iscpnodeissuer.ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := cl.http.Do(req)
	if e != nil {
		return iscpnodeissuer.ErrUnavailable
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, iscpnodeissuer.MaxFrameBytes+1))
	if e != nil || len(b) > iscpnodeissuer.MaxFrameBytes {
		return iscpnodeissuer.ErrInvalid
	}
	if res.StatusCode != 200 {
		switch res.StatusCode {
		case 400:
			return iscpnodeissuer.ErrInvalid
		case 401, 403:
			return iscpnodeissuer.ErrDenied
		case 409:
			return iscpnodeissuer.ErrConflict
		case 410:
			return iscpnodeissuer.ErrExpired
		default:
			return iscpnodeissuer.ErrUnavailable
		}
	}
	var xr iscpnodeissuer.ExchangeResponse
	if iscpnodeissuer.StrictDecode(b, &xr) != nil || xr.Version != 1 || xr.OperationID != operation || xr.Step != step {
		return iscpnodeissuer.ErrDenied
	}
	return iscpnodeissuer.StrictDecode(xr.Frame, out)
}
func (cl *Client) Enroll(ctx context.Context) (iscpnodeissuer.EnrollmentResult, error) {
	end := cl.beginAuthorityMutation()
	defer end()
	cl.mu.Lock()
	defer cl.mu.Unlock()
	var zero iscpnodeissuer.EnrollmentResult
	if cl.credential == nil {
		return zero, iscpnodeissuer.ErrInvalid
	}
	v := *cl.credential
	var p PendingEnrollment
	e := cl.read("enrollment.pending", &p)
	if errors.Is(e, os.ErrNotExist) {
		if !time.Now().Before(v.ExpiresAt) {
			return zero, iscpnodeissuer.ErrExpired
		}
		op := "enroll-" + c.Base64URL(c.RandomBytes(24))
		hello, priv, e := iscpnodeissuer.NewClientHello(v, cl.device, op, time.Now().UTC())
		if e != nil {
			return zero, e
		}
		installation := cl.installationID
		if installation == "" {
			installation = op
		}
		p = PendingEnrollment{InstallationID: installation, Version: 1, CredentialDigest: iscpnodeissuer.Digest(v), OperationID: op, Hello: hello, Private: priv}
		if e = cl.write("enrollment.pending", p); e != nil {
			return zero, e
		}
	} else if e != nil {
		return zero, e
	}
	if cl.installationID != "" && cl.installationID != p.InstallationID {
		return zero, iscpnodeissuer.ErrConflict
	}
	cl.installationID = p.InstallationID
	if p.Version != 1 || p.CredentialDigest != iscpnodeissuer.Digest(v) || p.Hello.Identity.PublicKey.KID != cl.device.Identity.PublicKey.KID {
		return zero, iscpnodeissuer.ErrConflict
	}
	if p.Result != nil {
		if e = cl.verifyResult(*p.Result); e != nil {
			return zero, e
		}
		return *p.Result, nil
	}
	if p.Channel == nil {
		var sh iscpnodeissuer.ServerHello
		if e = cl.exchange(ctx, p.OperationID, "hello", p.Hello, &sh); e != nil {
			return zero, e
		}
		channel, e := iscpnodeissuer.AcceptServerHello(v, p.Hello, sh, p.Private, time.Now().UTC())
		if e != nil {
			return zero, e
		}
		cf := channel.Finished("client", p.OperationID)
		var sf iscpnodeissuer.Finished
		if e = cl.exchange(ctx, p.OperationID, "finish", cf, &sf); e != nil {
			return zero, e
		}
		if e = channel.VerifyFinished(sf, "server", p.OperationID); e != nil {
			return zero, e
		}
		channel.Ready = true
		channel.ClientFinished = cf
		channel.ServerFinished = sf
		p.Channel = &channel
		if e = cl.write("enrollment.pending", p); e != nil {
			return zero, e
		}
	}
	if p.Redeem == nil {
		if cl.installationID == "" {
			cl.installationID = p.OperationID
		}
		proof, e := cl.device.CreateProof(c.NewProvider(), v.RelayID, v.InvitationID, c.Base64URL(c.RandomBytes(24)), time.Now().UTC())
		if e != nil {
			return zero, e
		}
		frame, e := iscpnodeissuer.SealFrame(*p.Channel, p.OperationID, "client", 1, iscpnodeissuer.RedeemRequest{IdentityProof: proof, InstallationID: cl.installationID})
		if e != nil {
			return zero, e
		}
		p.Redeem = &frame
		if e = cl.write("enrollment.pending", p); e != nil {
			return zero, e
		}
	}
	var sealed iscpnodeissuer.SealedFrame
	if e = cl.exchange(ctx, p.OperationID, "redeem", *p.Redeem, &sealed); e != nil {
		return zero, e
	}
	var result iscpnodeissuer.EnrollmentResult
	if e = iscpnodeissuer.OpenFrame(*p.Channel, sealed, p.OperationID, "server", 1, &result); e != nil {
		return zero, e
	}
	if e = cl.verifyResult(result); e != nil {
		return zero, e
	}
	p.Result = &result
	if e = cl.write("enrollment.pending", p); e != nil {
		return zero, e
	}
	cl.rememberPreviousGrantLocked(result.Grant)
	return result, nil
}
func (cl *Client) verifyResult(r iscpnodeissuer.EnrollmentResult) error {
	if r.Version != 1 || r.InvitationID != cl.cfg.InvitationID || iscpnodeissuer.Digest(r.Identity) != iscpnodeissuer.Digest(cl.device.Identity) || r.Binding != cl.cfg.Binding || r.AuthorizationRevision != cl.cfg.Revision || iscpnodeissuer.Digest(r.Scopes) != iscpnodeissuer.Digest(cl.cfg.Scopes) || r.Enrollment.RelayID != cl.cfg.RelayID || r.Enrollment.RelayBaseURL != cl.cfg.Origin || r.Enrollment.DeviceID != cl.device.Identity.DeviceID || r.Enrollment.Mode != iscpnodeissuer.NodeBundleMode || iscpnodeissuer.Digest(r.IssuerIdentity) != iscpnodeissuer.Digest(cl.cfg.IssuerIdentity) || iscpnodeissuer.Digest(r.ResponderIdentity) != iscpnodeissuer.Digest(cl.cfg.ResponderIdentity) || r.Enrollment.RelaySignerIdentity == nil || iscpnodeissuer.Digest(*r.Enrollment.RelaySignerIdentity) != iscpnodeissuer.Digest(cl.cfg.RelaySignerIdentity) {
		return iscpnodeissuer.ErrDenied
	}
	if r.Enrollment.DomainID != cl.device.Identity.DomainID || r.Enrollment.RelayWebSocketURL != "wss"+cl.cfg.Origin[5:]+"/v2/relay/duplex" || r.Enrollment.TLSCertificatePEM != cl.cfg.TLSCertificatePEM || r.Enrollment.InvitationSignerIdentity == nil {
		return iscpnodeissuer.ErrDenied
	}
	for _, token := range []iscpbridge.RelayCredential{r.Enrollment.Access, r.Enrollment.Refresh} {
		if token.DomainID != cl.device.Identity.DomainID || token.DeviceID != cl.device.Identity.DeviceID || len(token.Token) == 0 || len(token.Token) > 8192 || token.ExpiresAt.IsZero() {
			return iscpnodeissuer.ErrDenied
		}
	}
	if cl.credential != nil && (iscpnodeissuer.Digest(r.InvitationSignerIdentity) != iscpnodeissuer.Digest(cl.credential.InvitationSignerIdentity) || iscpnodeissuer.Digest(*r.Enrollment.InvitationSignerIdentity) != iscpnodeissuer.Digest(cl.credential.InvitationSignerIdentity)) {
		return iscpnodeissuer.ErrDenied
	}
	if e := iscpnodeissuer.VerifyObject("sparkclaw.iscp.enrollment-result.v1", r, cl.cfg.IssuerIdentity, r.Signature); e != nil {
		return e
	}
	return cl.verifyGrantAt(r.Grant, r.Grant.NotBefore)
}
func (cl *Client) verifyGrant(g trust.Grant) error { return cl.verifyGrantAt(g, time.Now().UTC()) }
func (cl *Client) verifyGrantAt(g trust.Grant, at time.Time) error {
	if g.RevocationEpoch != cl.cfg.Revision || len(g.Permissions) != 1 || g.Permissions[0] != iscpnodeissuer.Permission || len(g.RelayConstraints) != 1 || g.RelayConstraints[0] != cl.cfg.RelayID {
		return iscpnodeissuer.ErrDenied
	}
	return trust.VerifyGrant(c.NewProvider(), g, cl.cfg.IssuerIdentity, trust.VerifyOptions{Audience: cl.cfg.ResponderIdentity.DeviceID, SubjectDeviceID: cl.device.Identity.DeviceID, ConfirmationThumbprint: cl.device.Identity.PublicKey.KID, Permission: iscpnodeissuer.Permission, RelayID: cl.cfg.RelayID, Now: at})
}

// SetInstallationID binds enrollment to the existing desktop installation.
func (cl *Client) SetInstallationID(id string) error {
	end := cl.beginAuthorityMutation()
	defer end()
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if len(id) < 8 || len(id) > 200 {
		return iscpnodeissuer.ErrInvalid
	}
	cl.installationID = id
	return nil
}
