package iscpworkbench

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/appstream"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

const MaxNodePeers = 256

// PeerRegistry is an issuer projection of actual Client authority. It is not
// an account store. Every business operation reloads the projection, while the
// Gateway independently verifies its live Client ownership/revocation state.
type PeerRegistry struct {
	SchemaVersion int           `json:"schema_version"`
	DeploymentID  string        `json:"deployment_id"`
	Peers         []ManagedPeer `json:"peers"`
}
type ManagedPeer struct {
	Identity              identity.DeviceIdentity `json:"identity"`
	Grant                 trust.Grant             `json:"grant"`
	Binding               Binding                 `json:"binding"`
	InstallationID        string                  `json:"installation_id"`
	AuthorizationRevision uint64                  `json:"authorization_revision"`
	Scopes                []string                `json:"scopes"`
	Revoked               bool                    `json:"revoked"`
}
type NodeHandlerFactory func(Config) (Handler, error)
type NodePeerValidator func(context.Context, ManagedPeer) error

type nodePeer struct {
	peer     ManagedPeer
	endpoint *Endpoint
	cancel   context.CancelFunc
	done     chan struct{}
}
type NodeResponder struct {
	syncMu          sync.Mutex
	config          Config
	material        material
	relay           RelayTransport
	factory         NodeHandlerFactory
	validate        NodePeerValidator
	onState         func(string)
	verifyDiscovery func(context.Context) error
	mu              sync.Mutex
	peers           map[string]*nodePeer
	closed          bool
	cancel          context.CancelFunc
}

// submitOnlyTransport starts an Endpoint's session monitor but cannot drain
// the shared device queue. NodeResponder is the sole actual receive owner.
type submitOnlyTransport struct{ relay RelayTransport }

type asyncSubmitOnlyTransport struct{ submitOnlyTransport }

func wrapSubmitOnlyTransport(relay RelayTransport) RelayTransport {
	base := submitOnlyTransport{relay}
	if _, ok := relay.(interface {
		Enqueue(context.Context, any) (*iscpbridge.ReceiptFuture, error)
	}); ok {
		return asyncSubmitOnlyTransport{base}
	}
	return base
}
func (t asyncSubmitOnlyTransport) Enqueue(ctx context.Context, v any) (*iscpbridge.ReceiptFuture, error) {
	if sender, ok := t.relay.(interface {
		Enqueue(context.Context, any) (*iscpbridge.ReceiptFuture, error)
	}); ok {
		return sender.Enqueue(ctx, v)
	}
	return nil, errors.New("duplex asynchronous sender unavailable")
}
func (t submitOnlyTransport) Submit(ctx context.Context, v any) error { return t.relay.Submit(ctx, v) }
func (t submitOnlyTransport) RunOnceReady(ctx context.Context, _ func(context.Context, json.RawMessage) error, ready func()) error {
	if ready != nil {
		ready()
	}
	<-ctx.Done()
	return ctx.Err()
}

func NewNodeResponder(cfg Config, factory NodeHandlerFactory, validate NodePeerValidator, onState func(string)) (*NodeResponder, error) {
	m, err := loadMaterial(cfg)
	if err != nil {
		return nil, err
	}
	r, err := iscpbridge.NewRelayCredentialClient(cfg.EffectiveRelayProfile(), cfg.EnrollmentFile, m.enrollment, m.device, requestTimeout)
	if err != nil {
		return nil, err
	}
	return newNodeResponder(cfg, m, r, factory, validate, onState)
}
func NewNodeResponderWithRelay(cfg Config, relay RelayTransport, factory NodeHandlerFactory, validate NodePeerValidator, onState func(string)) (*NodeResponder, error) {
	m, err := loadMaterial(cfg)
	if err != nil {
		return nil, err
	}
	return newNodeResponder(cfg, m, relay, factory, validate, onState)
}
func newNodeResponder(cfg Config, m material, relay RelayTransport, factory NodeHandlerFactory, validate NodePeerValidator, onState func(string)) (*NodeResponder, error) {
	if cfg.Mode != "node-managed" || cfg.SchemaVersion != 2 || cfg.Role != RoleResponder || cfg.PeerRegistryFile == "" || relay == nil || factory == nil || validate == nil {
		return nil, errors.New("node responder requires explicit authority, registry and live Client validation")
	}
	n := &NodeResponder{config: cfg, material: m, relay: relay, factory: factory, validate: validate, onState: onState, peers: map[string]*nodePeer{}}
	if sender, ok := relay.(interface{ SetSessionUsable(func(string) bool) }); ok {
		sender.SetSessionUsable(func(id string) bool {
			n.mu.Lock()
			peers := make([]*Endpoint, 0, len(n.peers))
			for _, peer := range n.peers {
				peers = append(peers, peer.endpoint)
			}
			closed := n.closed
			n.mu.Unlock()
			if closed {
				return false
			}
			for _, e := range peers {
				e.mu.Lock()
				valid := !e.closed && e.session != nil && e.session.id == id && e.session.state != nil && e.session.state.Ready() && e.session.ctx.Err() == nil
				e.mu.Unlock()
				if valid {
					return true
				}
			}
			return false
		})
	}
	n.verifyDiscovery = func(ctx context.Context) error {
		return iscpbridge.VerifyWorkbenchRelayDiscovery(ctx, cfg.EffectiveRelayProfile(), m.enrollment)
	}
	if _, err := n.registry(); err != nil {
		return nil, err
	}
	return n, nil
}
func (n *NodeResponder) registry() (PeerRegistry, error) {
	var r PeerRegistry
	if err := readJSONFile(n.config.PeerRegistryFile, &r, true); err != nil {
		return r, errors.New("node peer registry unavailable")
	}
	if r.SchemaVersion != 1 || r.DeploymentID == "" || len(r.Peers) > MaxNodePeers {
		return r, errors.New("invalid node peer registry")
	}
	seen := map[string]bool{}
	for _, p := range r.Peers {
		if p.Identity.DomainID != n.material.device.Identity.DomainID || p.Identity.DeviceID == n.material.device.Identity.DeviceID || iscpbridge.ValidateLocalRelaySigner(p.Identity) != nil || seen[p.Identity.DeviceID] || p.Binding.DeploymentID != r.DeploymentID || p.Binding.OwnerID == "" || p.Binding.ClientID == "" || p.AuthorizationRevision == 0 || (!p.Revoked && p.Grant.RevocationEpoch != p.AuthorizationRevision || p.Revoked && p.Grant.RevocationEpoch >= p.AuthorizationRevision) || !uuidPattern.MatchString(p.InstallationID) || len(p.Scopes) == 0 || len(p.Scopes) > 32 {
			return r, errors.New("invalid node peer authority binding")
		}
		seen[p.Identity.DeviceID] = true
		m := n.material
		m.peer = p.Identity
		m.grant = p.Grant
		c := n.config
		c.Binding = &p.Binding
		// Revoked and expired peers remain durable deny records. Verify their
		// original signed binding without treating the old Grant as live.
		check := time.Now().UTC()
		if !check.Before(m.grant.ExpiresAt) {
			check = m.grant.ExpiresAt.Add(-time.Nanosecond)
		}
		if err := verifyGrant(c, m, check); err != nil {
			return r, err
		}
	}
	return r, nil
}
func (n *NodeResponder) current(ctx context.Context, id string) (ManagedPeer, error) {
	r, err := n.registry()
	if err != nil {
		return ManagedPeer{}, err
	}
	for _, p := range r.Peers {
		if p.Identity.DeviceID == id {
			if p.Revoked {
				return p, iscpbridge.ErrAuthorizationRevoked
			}
			if err := n.validate(ctx, p); err != nil {
				return p, err
			}
			return p, nil
		}
	}
	return ManagedPeer{}, iscpbridge.ErrAuthorizationRevoked
}
func (n *NodeResponder) policy(ctx context.Context, id string, e *Endpoint) (iscpauth.Policy, error) {
	p, err := n.current(ctx, id)
	if err != nil {
		return iscpauth.Policy{}, err
	}
	m := e.grantMaterial()
	if p.Identity.PublicKey.Public != m.peer.PublicKey.Public || p.Binding != *e.config.Binding || p.InstallationID != e.config.ExpectedInstallationID || p.AuthorizationRevision < m.grant.RevocationEpoch {
		return iscpauth.Policy{}, errors.New("node peer identity or authorization regressed")
	}
	m.grant = p.Grant
	if err := verifyGrant(e.config, m, time.Now().UTC()); err != nil {
		return iscpauth.Policy{}, err
	}
	e.grantMu.Lock()
	e.material.grant = p.Grant
	e.grantMu.Unlock()
	return iscpauth.Policy{Version: 2, Lifetime: iscpauth.UntilRevoked, Revision: p.AuthorizationRevision, State: iscpauth.Active, Scopes: slices.Clone(p.Scopes)}, nil
}
func (n *NodeResponder) syncPeers(ctx context.Context) error {
	n.syncMu.Lock()
	defer n.syncMu.Unlock()
	r, err := n.registry()
	if err != nil {
		n.resetAll()
		return err
	}
	wanted := map[string]bool{}
	for _, p := range r.Peers {
		if p.Revoked {
			continue
		}
		wanted[p.Identity.DeviceID] = true
		n.mu.Lock()
		old := n.peers[p.Identity.DeviceID]
		n.mu.Unlock()
		if old != nil {
			if old.peer.Identity.PublicKey.Public != p.Identity.PublicKey.Public || old.peer.Binding != p.Binding || old.peer.InstallationID != p.InstallationID {
				n.remove(p.Identity.DeviceID)
				return errors.New("node peer identity cannot be replaced")
			}
			continue
		}
		if err := n.validate(ctx, p); err != nil {
			continue
		}
		m := n.material
		m.peer = p.Identity
		m.grant = p.Grant
		cfg := n.config
		cfg.Binding = &p.Binding
		cfg.ExpectedInstallationID = p.InstallationID
		cfg.PeerIdentityFile = ""
		cfg.GrantFile = ""
		if verifyGrant(cfg, m, time.Now().UTC()) != nil {
			continue
		}
		handler, err := n.factory(cfg)
		if err != nil {
			return err
		}
		e, err := newEndpoint(cfg, m, wrapSubmitOnlyTransport(n.relay), handler, nil)
		if err != nil {
			return err
		}
		e.authorityPolicy = func(callCtx context.Context) (iscpauth.Policy, error) {
			return n.policy(callCtx, p.Identity.DeviceID, e)
		}
		e.lastHelloAt = time.Now().UTC().Add(-time.Second)
		peerCtx, cancel := context.WithCancel(ctx)
		np := &nodePeer{peer: p, endpoint: e, cancel: cancel, done: make(chan struct{})}
		n.mu.Lock()
		if n.closed {
			n.mu.Unlock()
			cancel()
			return context.Canceled
		}
		n.peers[p.Identity.DeviceID] = np
		n.mu.Unlock()
		go func() { defer close(np.done); defer e.Close(); _ = e.Run(peerCtx) }()
	}
	n.mu.Lock()
	var remove []string
	for id := range n.peers {
		if !wanted[id] {
			remove = append(remove, id)
		}
	}
	n.mu.Unlock()
	for _, id := range remove {
		n.remove(id)
	}
	return nil
}
func (n *NodeResponder) remove(id string) {
	n.mu.Lock()
	p := n.peers[id]
	delete(n.peers, id)
	n.mu.Unlock()
	if p != nil {
		p.cancel()
		_ = p.endpoint.Close()
		<-p.done
	}
}
func (n *NodeResponder) resetAll() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, p := range n.peers {
		p.endpoint.mu.Lock()
		p.endpoint.resetLocked()
		p.endpoint.mu.Unlock()
	}
}
func (n *NodeResponder) receive(ctx context.Context, raw json.RawMessage) error {
	var env envelope.SecureEnvelope
	if len(raw) > 100<<10 || strictDecode(raw, &env) != nil {
		return nil
	}
	// Stream data/control authenticate inside the Endpoint and use its local
	// snapshot. Registry/Client refresh is independent; it cannot stall batches.
	if env.PayloadType == appstream.Type || env.PayloadType == appstream.ControlType {
		n.mu.Lock()
		peer := n.peers[env.SenderDeviceID]
		n.mu.Unlock()
		if peer != nil {
			_ = peer.endpoint.receive(ctx, raw)
		}
		return nil
	}
	if err := n.syncPeers(ctx); err != nil {
		return err
	}
	n.mu.Lock()
	p := n.peers[env.SenderDeviceID]
	n.mu.Unlock()
	if p == nil {
		return nil
	}
	if _, err := n.policy(ctx, env.SenderDeviceID, p.endpoint); err != nil {
		if errors.Is(err, iscpbridge.ErrAuthorizationRevoked) {
			n.remove(env.SenderDeviceID)
		}
		return nil
	}
	_ = p.endpoint.receive(ctx, raw)
	// An unauthenticated header may name another peer. Rejected signatures,
	// routes or ciphertext cannot cancel that peer's valid encrypted session.
	return nil
}
func (n *NodeResponder) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	n.mu.Lock()
	if n.cancel != nil || n.closed {
		n.mu.Unlock()
		cancel()
		return errors.New("node responder already running or closed")
	}
	n.cancel = cancel
	n.mu.Unlock()
	defer cancel()
	defer n.closePeers()
	if err := n.syncPeers(ctx); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = n.syncPeers(ctx)
			}
		}
	}()
	defer func() { cancel(); <-done }()
	backoff := time.Second
	for ctx.Err() == nil {
		var err error
		if n.verifyDiscovery != nil {
			err = n.verifyDiscovery(ctx)
		}
		if err == nil {
			if n.onState != nil {
				n.onState("connecting")
			}
			err = n.relay.RunOnceReady(ctx, n.receive, func() {
				if n.onState != nil {
					n.onState("relay_ready")
				}
			})
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err == nil {
				backoff = time.Second
			}
		}
		if relay, ok := n.relay.(*iscpbridge.RelayClient); ok {
			bundle := relay.Enrollment()
			if !time.Now().Before(bundle.Refresh.ExpiresAt) || !time.Now().Before(bundle.ExpiresAt) {
				pending := n.config.EnrollmentFile + ".service-recovery.pending"
				if updated, recoveryErr := iscpbridge.RecoverNodeServiceCredentials(ctx, bundle, n.material.device, pending); recoveryErr == nil {
					if err := relay.UpdateEnrollment(func(b *iscpbridge.EnrollmentBundle) { *b = updated }); err == nil {
						_ = iscpbridge.CommitNodeServiceRecovery(pending)
					}
				}
			}
		}
		n.resetAll()
		if n.onState != nil {
			n.onState("disconnected")
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		backoff = min(backoff*2, 15*time.Second)
	}
	return ctx.Err()
}
func (n *NodeResponder) closePeers() {
	n.mu.Lock()
	ids := make([]string, 0, len(n.peers))
	for id := range n.peers {
		ids = append(ids, id)
	}
	n.mu.Unlock()
	for _, id := range ids {
		n.remove(id)
	}
}
func (n *NodeResponder) Close() error {
	n.mu.Lock()
	n.closed = true
	cancel := n.cancel
	n.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	n.closePeers()
	return nil
}
