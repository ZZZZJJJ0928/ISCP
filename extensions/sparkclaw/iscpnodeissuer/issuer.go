package iscpnodeissuer

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Config struct {
	Template         Credential
	Issuer           identity.Device
	InvitationSigner identity.Device
	GrantTTL         time.Duration
	ApprovedScopes   []string
	RegistryPath     string
	// A root-configured existing Client may migrate through exactly one
	// operator-selected operation. Ordinary invitations always create a Client.
	MigrationClients map[string]string
}
type Issuer struct {
	cfg          Config
	store        Store
	management   Management
	relay        RelayRegistration
	Now          func() time.Time
	projectionMu sync.Mutex
}

func New(cfg Config, store Store, m Management, r RelayRegistration) (*Issuer, error) {
	if store == nil || m == nil || r == nil || cfg.GrantTTL < time.Second || cfg.GrantTTL > 30*time.Minute || cfg.GrantTTL%time.Second != 0 || ValidateIdentity(cfg.Issuer.Identity) != nil || ValidateIdentity(cfg.InvitationSigner.Identity) != nil || cfg.Issuer.Identity.PublicKey.KID == cfg.InvitationSigner.Identity.PublicKey.KID || cfg.Template.IssuerIdentity.PublicKey.KID != cfg.Issuer.Identity.PublicKey.KID || cfg.Template.InvitationSignerIdentity.PublicKey.KID != cfg.InvitationSigner.Identity.PublicKey.KID {
		return nil, ErrInvalid
	}
	pins := map[string]bool{}
	for _, id := range []identity.DeviceIdentity{cfg.Issuer.Identity, cfg.InvitationSigner.Identity, cfg.Template.RelaySignerIdentity, cfg.Template.ResponderIdentity} {
		if ValidateIdentity(id) != nil || pins[id.PublicKey.KID] {
			return nil, ErrInvalid
		}
		pins[id.PublicKey.KID] = true
	}
	if cfg.RegistryPath != "" && !filepath.IsAbs(cfg.RegistryPath) {
		return nil, ErrInvalid
	}
	seenMigration := map[string]bool{}
	for client, op := range cfg.MigrationClients {
		if !identifier.MatchString(client) || !identifier.MatchString(op) || len(op) < 8 || seenMigration[op] {
			return nil, ErrInvalid
		}
		seenMigration[op] = true
	}
	return &Issuer{cfg: cfg, store: store, management: m, relay: r, Now: time.Now}, nil
}

// CreateInvitation reserves its stable identifier before asking the existing
// Gateway to create a Client. A Gateway lost-response is reconciled by stable ID;
// the discarded HTTP Client token is never given to the desktop or Relay.
func (i *Issuer) CreateInvitation(ctx context.Context, name string, ttl time.Duration, scopes []string, key string) (string, error) {
	return i.createInvitation(ctx, name, ttl, scopes, key, "")
}

func (i *Issuer) CreateMigrationInvitation(ctx context.Context, name string, ttl time.Duration, scopes []string, key, clientID string) (string, error) {
	if clientID == "" || i.cfg.MigrationClients[clientID] != key {
		return "", ErrDenied
	}
	return i.createInvitation(ctx, name, ttl, scopes, key, clientID)
}

func (i *Issuer) createInvitation(ctx context.Context, name string, ttl time.Duration, scopes []string, key, existingClientID string) (string, error) {
	if len(i.cfg.ApprovedScopes) > 0 && Digest(scopes) != Digest(i.cfg.ApprovedScopes) {
		return "", ErrDenied
	}
	if !identifier.MatchString(key) || len(key) < 8 || ttl < time.Second || ttl > 30*time.Minute || name == "" || len([]rune(name)) > 80 {
		return "", ErrInvalid
	}
	actual, e := i.management.Identity(ctx)
	if e != nil {
		return "", e
	}
	if actual.OwnerID != i.cfg.Template.OwnerID || actual.DeploymentID != i.cfg.Template.DeploymentID {
		return "", ErrDenied
	}
	id := "invite-" + c.Base64URL(c.SHA256([]byte(actual.OwnerID + "\x00" + key)))[:32]
	v := i.cfg.Template
	v.InvitationID = id
	v.ClientID = StableClientID(actual.OwnerID, key)
	if existingClientID != "" {
		v.ClientID = existingClientID
	}
	v.IssuedAt = i.Now().UTC()
	v.ExpiresAt = v.IssuedAt.Add(ttl)
	v.Scopes = append([]string{}, scopes...)
	v.BootstrapSecret = c.Base64URL(c.RandomBytes(32))
	v, e = SignCredential(v, i.cfg.InvitationSigner)
	if e != nil || v.Validate(i.Now(), false) != nil {
		return "", ErrInvalid
	}
	st := &State{Credential: v, ClientName: name, State: "client_pending", Revision: 1, Operations: map[string]*Operation{}}
	e = i.store.Create(ctx, id, st)
	if errors.Is(e, ErrConflict) {
		st, e = i.store.Read(ctx, id)
		if e != nil {
			return "", e
		}
		if st.ClientName != name || st.Credential.ClientID != v.ClientID || Digest(st.Credential.Scopes) != Digest(scopes) || st.Credential.ExpiresAt.Sub(st.Credential.IssuedAt) != ttl {
			return "", ErrConflict
		}
		v = st.Credential
	} else if e != nil {
		return "", e
	}
	if st.State == "revoked" || !i.Now().Before(v.ExpiresAt) {
		return "", ErrExpired
	}
	active, e := i.management.Client(ctx, v.ClientID)
	if e != nil {
		return "", e
	}
	if !active {
		if existingClientID != "" {
			return "", ErrDenied
		}
		client, e := i.management.CreateClient(ctx, name, key)
		if e != nil {
			return "", e
		}
		if client != v.ClientID {
			return "", ErrDenied
		}
	}
	e = i.store.Update(ctx, id, func(s *State) error {
		if s.State == "client_pending" {
			s.State = "issued"
		}
		return nil
	})
	if e != nil {
		return "", e
	}
	return EncodeCredential(v)
}
func StableClientID(owner, key string) string {
	return "client_web_" + c.Base64URL(c.SHA256([]byte(owner + "\x00" + key))[:18])
}
func (i *Issuer) authorized(ctx context.Context, s *State) error {
	if s.State == "revoked" || !s.RevokedAt.IsZero() {
		return ErrDenied
	}
	actual, e := i.management.Identity(ctx)
	if e != nil {
		return ErrUnavailable
	}
	if actual.OwnerID != s.Credential.OwnerID || actual.DeploymentID != s.Credential.DeploymentID {
		return ErrDenied
	}
	ok, e := i.management.Client(ctx, s.Credential.ClientID)
	if e != nil {
		return ErrUnavailable
	}
	if !ok {
		return ErrDenied
	}
	return nil
}
func (i *Issuer) Exchange(ctx context.Context, x Exchange) (ExchangeResponse, error) {
	if x.Validate() != nil || x.IssuerRoute != i.cfg.Template.IssuerRoute {
		return ExchangeResponse{}, ErrInvalid
	}
	switch x.Step {
	case "hello":
		return i.hello(ctx, x)
	case "finish":
		return i.finish(ctx, x)
	case "redeem", "status":
		return i.redeem(ctx, x)
	case "applied":
		return i.applied(ctx, x)
	case "renew", "recover":
		return i.lifecycle(ctx, x)
	}
	return ExchangeResponse{}, ErrInvalid
}
func response(x Exchange, frame any) (ExchangeResponse, error) {
	b, e := json.Marshal(frame)
	return ExchangeResponse{1, x.OperationID, x.Step, b}, e
}
func (i *Issuer) hello(ctx context.Context, x Exchange) (ExchangeResponse, error) {
	var h ClientHello
	if StrictDecode(x.Frame, &h) != nil || h.OperationID != x.OperationID || h.InvitationID != x.InvitationID {
		return ExchangeResponse{}, ErrInvalid
	}
	st, e := i.store.Read(ctx, x.InvitationID)
	if e != nil {
		return ExchangeResponse{}, e
	}
	if e = i.authorized(ctx, st); e != nil {
		return ExchangeResponse{}, e
	}
	var out ServerHello
	e = i.store.Update(ctx, x.InvitationID, func(s *State) error {
		if s.State == "revoked" {
			return ErrDenied
		}
		old := s.Operations[x.OperationID]
		if old != nil {
			if old.InputDigest != Digest(h) || old.Hello == nil {
				return ErrConflict
			}
			out = *old.Server
			return nil
		}
		if !i.Now().Before(s.Credential.ExpiresAt) || s.BoundOperation != "" {
			return ErrExpired
		}
		if len(s.Operations) >= 8 {
			return ErrDenied
		}
		if VerifyClientHello(s.Credential, h, i.Now()) != nil {
			return ErrDenied
		}
		server, ch, e := NewServerHello(s.Credential, h, i.cfg.Issuer, i.Now())
		if e != nil {
			return e
		}
		out = server
		s.BoundOperation = x.OperationID
		device := h.Identity
		s.Device = &device
		s.State = "device_bound"
		s.Operations[x.OperationID] = &Operation{ID: x.OperationID, State: "device_bound", InputDigest: Digest(h), Hello: &h, Server: &server, Channel: &ch}
		return nil
	})
	if e != nil {
		return ExchangeResponse{}, e
	}
	return response(x, out)
}
func (i *Issuer) finish(ctx context.Context, x Exchange) (ExchangeResponse, error) {
	var f Finished
	if StrictDecode(x.Frame, &f) != nil {
		return ExchangeResponse{}, ErrInvalid
	}
	var out Finished
	e := i.store.Update(ctx, x.InvitationID, func(s *State) error {
		if s.State == "revoked" {
			return ErrDenied
		}
		op := s.Operations[x.OperationID]
		if op == nil || op.Channel == nil {
			return ErrDenied
		}
		if op.Channel.VerifyFinished(f, "client", x.OperationID) != nil {
			return ErrDenied
		}
		if !op.Channel.Ready && !i.Now().Before(op.Server.ExpiresAt) {
			return ErrExpired
		}
		op.Channel.ClientFinished = f
		out = op.Channel.Finished("server", x.OperationID)
		op.Channel.ServerFinished = out
		op.Channel.Ready = true
		op.State = "channel_ready"
		return nil
	})
	if e != nil {
		return ExchangeResponse{}, e
	}
	return response(x, out)
}
func (i *Issuer) signGrant(s *State, id identity.DeviceIdentity, now time.Time) (trust.Grant, error) {
	return trust.SignGrant(c.NewProvider(), i.cfg.Issuer, trust.Grant{GrantID: "grant-" + c.Base64URL(c.RandomBytes(18)), SubjectDeviceID: id.DeviceID, Audience: s.Credential.ResponderIdentity.DeviceID, ConfirmationThumbprint: id.PublicKey.KID, Permissions: []string{Permission}, RelayConstraints: []string{s.Credential.RelayID}, NotBefore: now, ExpiresAt: now.Add(i.cfg.GrantTTL), RevocationEpoch: s.Revision})
}
func (i *Issuer) redeem(ctx context.Context, x Exchange) (ExchangeResponse, error) {
	var f SealedFrame
	if StrictDecode(x.Frame, &f) != nil {
		return ExchangeResponse{}, ErrInvalid
	}
	st, e := i.store.Read(ctx, x.InvitationID)
	if e != nil {
		return ExchangeResponse{}, e
	}
	if e = i.authorized(ctx, st); e != nil {
		return ExchangeResponse{}, e
	}
	e = i.store.Update(ctx, x.InvitationID, func(s *State) error {
		if s.State == "revoked" {
			return ErrDenied
		}
		op := s.Operations[x.OperationID]
		if op == nil || op.Channel == nil || !op.Channel.Ready {
			return ErrDenied
		}
		if op.RedeemDigest != "" {
			if op.RedeemDigest != Digest(f) {
				return ErrConflict
			}
			return nil
		}
		var req RedeemRequest
		if OpenFrame(*op.Channel, f, x.OperationID, "client", 1, &req) != nil || !identifier.MatchString(req.InstallationID) || len(req.InstallationID) < 8 {
			return ErrDenied
		}
		if !i.Now().Before(op.Server.ExpiresAt) || !i.Now().Before(s.Credential.ExpiresAt) {
			return ErrExpired
		}
		if identity.VerifyProof(c.NewProvider(), *s.Device, req.IdentityProof, s.Credential.RelayID, s.Credential.InvitationID, i.Now(), 5*time.Minute) != nil {
			return ErrDenied
		}
		grant, e := i.signGrant(s, *s.Device, i.Now().UTC())
		if e != nil {
			return e
		}
		ticket, e := provisioning.SignTicketV3(c.NewProvider(), i.cfg.InvitationSigner, provisioning.PairingTicketV3{TicketID: s.Credential.InvitationID, DomainID: s.Credential.DomainID, RelayID: s.Credential.RelayID, TrustRootID: i.cfg.InvitationSigner.Identity.DeviceID, Purpose: provisioning.PurposeInvite, ConsumerRole: "sparkx_workbench_client", GrantAudience: s.Credential.ResponderIdentity.DeviceID, GrantPermissions: []string{Permission}, GrantTTLSeconds: int(i.cfg.GrantTTL / time.Second), MaxUses: 1, IssuedAt: s.Credential.IssuedAt, ExpiresAt: s.Credential.ExpiresAt})
		if e != nil {
			return e
		}
		priv, pub, e := NewWrapKey()
		if e != nil {
			return e
		}
		prep := RegistrationPreparation{OperationID: x.OperationID, InvitationID: s.Credential.InvitationID, Identity: *s.Device, Grant: grant, TicketV3: ticket, Binding: Binding{s.Credential.DeploymentID, s.Credential.OwnerID, s.Credential.ClientID}, ReceiptWrapPublicKey: pub}
		prep.BindingDigest = Digest(prep)
		op.InstallationID = req.InstallationID
		op.RedeemDigest = Digest(f)
		op.Preparation = &prep
		op.WrapPrivate = priv
		op.Commit = &RegistrationCommit{x.OperationID, prep.BindingDigest, req.IdentityProof, ticket}
		op.State = "grant_prepared"
		return nil
	})
	if e != nil {
		return ExchangeResponse{}, e
	}
	st, e = i.store.Read(ctx, x.InvitationID)
	if e != nil {
		return ExchangeResponse{}, e
	}
	op := st.Operations[x.OperationID]
	if op.ResultFrame != nil {
		if e = i.publishRegistry(ctx); e != nil {
			return ExchangeResponse{}, e
		}
		return response(x, *op.ResultFrame)
	}
	if op.Receipt == nil {
		if e = i.relay.Prepare(ctx, *op.Preparation); e != nil {
			return ExchangeResponse{}, e
		}
		// Commit is idempotent and status reconciles an unknown outcome. Neither path
		// retries a public proof nor allocates a different operation or wrap key.
		receipt, e := i.relay.Commit(ctx, *op.Commit)
		if e != nil {
			receipt, e = i.relay.Status(ctx, x.OperationID, op.Preparation.BindingDigest)
		}
		if e != nil {
			return ExchangeResponse{}, ErrUnknownOutcome
		}
		if receipt.OperationID != x.OperationID || receipt.BindingDigest != op.Preparation.BindingDigest {
			return ExchangeResponse{}, ErrDenied
		}
		tokens, e := OpenRegistrationReceipt(receipt, op.WrapPrivate, *st.Device)
		if e != nil {
			return ExchangeResponse{}, e
		}
		if e = i.authorized(ctx, st); e != nil {
			return ExchangeResponse{}, e
		}
		result := EnrollmentResult{Version: 1, OperationID: x.OperationID, InvitationID: x.InvitationID, Identity: *st.Device, Binding: op.Preparation.Binding, AuthorizationRevision: st.Revision, InstallationID: op.InstallationID, Scopes: st.Credential.Scopes, Grant: op.Preparation.Grant, IssuerIdentity: i.cfg.Issuer.Identity, InvitationSignerIdentity: i.cfg.InvitationSigner.Identity, ResponderIdentity: st.Credential.ResponderIdentity}
		signer := st.Credential.RelaySignerIdentity
		result.Enrollment = iscpbridge.EnrollmentBundle{Type: iscpbridge.EnrollmentBundleType, Mode: NodeBundleMode, DomainID: st.Credential.DomainID, DeviceID: st.Device.DeviceID, RelayID: st.Credential.RelayID, RelayBaseURL: st.Credential.Origin, RelayWebSocketURL: "wss" + st.Credential.Origin[5:] + "/v2/relay/connect", TrustRootIdentity: i.cfg.InvitationSigner.Identity, TLSCertificatePEM: st.Credential.TLSCertificatePEM, InvitationSignerIdentity: &st.Credential.InvitationSignerIdentity, RelaySignerIdentity: &signer, Access: tokens.Access, Refresh: tokens.Refresh, IssuedAt: i.Now().UTC(), ExpiresAt: tokens.Refresh.ExpiresAt}
		result.Signature, e = SignObject("sparkclaw.iscp.enrollment-result.v1", result, i.cfg.Issuer)
		if e != nil {
			return ExchangeResponse{}, e
		}
		sealed, e := SealFrame(*op.Channel, x.OperationID, "server", 1, result)
		if e != nil {
			return ExchangeResponse{}, e
		}
		e = i.store.Update(ctx, x.InvitationID, func(s *State) error {
			if s.State == "revoked" || s.Revision != result.AuthorizationRevision {
				return ErrDenied
			}
			o := s.Operations[x.OperationID]
			if o.ResultFrame == nil {
				o.Receipt = &receipt
				o.Result = &result
				o.ResultFrame = &sealed
				o.State = "bundle_ready"
				s.State = "active"
			}
			return nil
		})
		if e != nil {
			return ExchangeResponse{}, e
		}
	}
	if e = i.publishRegistry(ctx); e != nil {
		return ExchangeResponse{}, e
	}
	st, e = i.store.Read(ctx, x.InvitationID)
	if e != nil {
		return ExchangeResponse{}, e
	}
	return response(x, *st.Operations[x.OperationID].ResultFrame)
}

// Revoke first commits a tombstone. A failed Relay call is durably retried,
// never reported as a completed transport revocation or rolled back to active.
func (i *Issuer) Revoke(ctx context.Context, invitation, operation string, expected uint64) error {
	if !identifier.MatchString(operation) || len(operation) < 8 {
		return ErrInvalid
	}
	e := i.store.Update(ctx, invitation, func(s *State) error {
		if s.State == "revoked" {
			if s.RevocationOperation != operation || s.Revision != expected+1 {
				return ErrConflict
			}
			return nil
		}
		if s.Revision != expected {
			return ErrConflict
		}
		s.Revision++
		s.State = "revoked"
		s.RevokedAt = i.Now().UTC()
		s.RevocationOperation = operation
		return nil
	})
	if e != nil {
		return e
	}
	if e = i.publishRegistry(ctx); e != nil {
		return e
	}
	return i.reconcileRevocation(ctx, invitation)
}
func (i *Issuer) reconcileRevocation(ctx context.Context, id string) error {
	s, e := i.store.Read(ctx, id)
	if e != nil {
		return e
	}
	if s.State != "revoked" || s.RelayRevoked {
		return nil
	}
	if e = i.management.RevokeManagedClient(ctx, s.Credential.ClientID); e != nil {
		return ErrUnavailable
	}
	if s.Device != nil {
		if e = i.relay.Revoke(ctx, s.RevocationOperation, s.Device.DeviceID, s.Revision); e != nil {
			return ErrUnavailable
		}
	}
	return i.store.Update(ctx, id, func(v *State) error { v.RelayRevoked = true; return nil })
}
func (i *Issuer) Reconcile(ctx context.Context) error {
	rows, e := i.store.List(ctx)
	if e != nil {
		return e
	}
	for _, s := range rows {
		if s.State == "revoked" && !s.RelayRevoked {
			if e = i.reconcileRevocation(ctx, s.Credential.InvitationID); e != nil {
				return e
			}
		}
	}
	return i.publishRegistry(ctx)
}

type RegistryPeer struct {
	Identity              identity.DeviceIdentity `json:"identity"`
	Grant                 trust.Grant             `json:"grant"`
	Binding               Binding                 `json:"binding"`
	Scopes                []string                `json:"scopes"`
	InstallationID        string                  `json:"installation_id"`
	AuthorizationRevision uint64                  `json:"authorization_revision"`
	Revoked               bool                    `json:"revoked"`
}
type PeerRegistry struct {
	SchemaVersion int            `json:"schema_version"`
	DeploymentID  string         `json:"deployment_id"`
	Peers         []RegistryPeer `json:"peers"`
}

func (i *Issuer) Registry(ctx context.Context) (PeerRegistry, error) {
	rows, e := i.store.List(ctx)
	out := PeerRegistry{1, i.cfg.Template.DeploymentID, []RegistryPeer{}}
	if e != nil {
		return out, e
	}
	for _, s := range rows {
		if s.Device == nil {
			continue
		}
		op := s.Operations[s.BoundOperation]
		if op == nil || op.Result == nil {
			continue
		}
		result := op.Result
		grant := result.Grant
		for _, o := range s.Operations {
			if o.Grant != nil && o.Grant.NotBefore.After(grant.NotBefore) {
				grant = *o.Grant
			}
		}
		out.Peers = append(out.Peers, RegistryPeer{*s.Device, grant, result.Binding, result.Scopes, result.InstallationID, s.Revision, s.State == "revoked"})
	}
	sort.Slice(out.Peers, func(a, b int) bool { return out.Peers[a].Identity.DeviceID < out.Peers[b].Identity.DeviceID })
	return out, nil
}
func (i *Issuer) publishRegistry(ctx context.Context) error {
	if i.cfg.RegistryPath == "" {
		return nil
	}
	i.projectionMu.Lock()
	defer i.projectionMu.Unlock()
	out, e := i.Registry(ctx)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(out)
	if e != nil {
		return e
	}
	return WritePrivateAtomic(i.cfg.RegistryPath, raw)
}
func WritePrivateAtomic(path string, raw []byte) error {
	if !filepath.IsAbs(path) || len(raw) > 4<<20 {
		return ErrInvalid
	}
	dir := filepath.Dir(path)
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return ErrInvalid
	}
	if info, e := os.Lstat(path); e == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return ErrInvalid
	}
	f, e := os.CreateTemp(dir, ".iscp-node-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
