package iscprelayadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"time"

	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const MaxAuthorities = 16

var routePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)

type NodeConfig struct {
	IssuerRoute      string                    `json:"issuer_route"`
	ManagedSocket    string                    `json:"managed_socket"`
	InvitationSigner identity.DeviceIdentity   `json:"invitation_signer"`
	GrantSigner      identity.DeviceIdentity   `json:"grant_signer"`
	Responder        identity.DeviceIdentity   `json:"responder"`
	ServicePeers     []identity.DeviceIdentity `json:"service_peers,omitempty"`
}
type MultiConfig struct {
	SchemaVersion     int          `json:"schema_version"`
	DomainID          string       `json:"domain_id"`
	RelayID           string       `json:"relay_id"`
	LegacyIssuerRoute string       `json:"legacy_issuer_route,omitempty"`
	Nodes             []NodeConfig `json:"nodes"`
}
type ScopedNode struct {
	IssuerRoute   string
	ManagedSocket string
	Adapter       *Adapter
}
type Manager struct {
	domain      string
	db          *pgxpool.Pool
	nodes       []ScopedNode
	ticket      map[string]*Adapter
	service     map[string]*Adapter
	authorities map[string]*Adapter
}

func ValidateMultiConfig(cfg MultiConfig) error {
	if cfg.SchemaVersion != 2 || cfg.DomainID == "" || cfg.RelayID == "" || len(cfg.Nodes) == 0 || len(cfg.Nodes) > MaxAuthorities {
		return invalid("invalid_multi_authority_config")
	}
	routes, sockets := map[string]bool{}, map[string]bool{}
	type owner struct {
		node     int
		identity string
		device   string
	}
	devices, keys := map[string]owner{}, map[string]owner{}
	legacyFound := cfg.LegacyIssuerRoute == ""
	for i, n := range cfg.Nodes {
		if !routePattern.MatchString(n.IssuerRoute) || routes[n.IssuerRoute] || !filepath.IsAbs(n.ManagedSocket) || filepath.Clean(n.ManagedSocket) != n.ManagedSocket || len(n.ManagedSocket) > 100 || sockets[n.ManagedSocket] {
			return invalid("duplicate_or_invalid_authority_route_socket")
		}
		routes[n.IssuerRoute] = true
		sockets[n.ManagedSocket] = true
		legacyFound = legacyFound || cfg.LegacyIssuerRoute == n.IssuerRoute
		c := Config{DomainID: cfg.DomainID, RelayID: cfg.RelayID, InvitationSigner: n.InvitationSigner, GrantSigner: n.GrantSigner, Responder: n.Responder, ServicePeers: n.ServicePeers}
		if e := validateConfig(c); e != nil {
			return e
		}
		for _, id := range append([]identity.DeviceIdentity{n.InvitationSigner, n.GrantSigner, n.Responder}, n.ServicePeers...) {
			same := owner{i, node.Digest(id), id.DeviceID}
			if old, ok := devices[id.DeviceID]; ok && old != same {
				return invalid("duplicate_authority_identity")
			}
			if old, ok := keys[id.PublicKey.Public]; ok && old != same {
				return invalid("duplicate_authority_key")
			}
			devices[id.DeviceID] = same
			keys[id.PublicKey.Public] = same
		}
	}
	if !legacyFound {
		return invalid("unknown_legacy_authority_route")
	}
	return nil
}
func NewManager(ctx context.Context, pool *pgxpool.Pool, cfg MultiConfig) (*Manager, error) {
	if pool == nil {
		return nil, invalid("persistent_database_required")
	}
	if e := ValidateMultiConfig(cfg); e != nil {
		return nil, e
	}
	m := &Manager{domain: cfg.DomainID, db: pool, ticket: map[string]*Adapter{}, service: map[string]*Adapter{}, authorities: map[string]*Adapter{}}
	tx, e := pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	nodes := append([]NodeConfig(nil), cfg.Nodes...)
	if cfg.LegacyIssuerRoute != "" {
		for i, n := range nodes {
			if n.IssuerRoute == cfg.LegacyIssuerRoute {
				nodes[0], nodes[i] = nodes[i], nodes[0]
				break
			}
		}
	}
	for _, n := range nodes {
		c := Config{DomainID: cfg.DomainID, RelayID: cfg.RelayID, InvitationSigner: n.InvitationSigner, GrantSigner: n.GrantSigner, Responder: n.Responder, ServicePeers: n.ServicePeers, issuerRoute: n.IssuerRoute}
		a := &Adapter{cfg: c, db: pool, Now: time.Now, authority: authorityID(c)}
		if e = a.initializeTx(ctx, tx, n.IssuerRoute == cfg.LegacyIssuerRoute); e != nil {
			return nil, e
		}
		m.nodes = append(m.nodes, ScopedNode{n.IssuerRoute, n.ManagedSocket, a})
		m.authorities[a.authority] = a
		m.ticket[n.InvitationSigner.DeviceID] = a
		for _, id := range n.ServicePeers {
			m.service[id.DeviceID] = a
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return m, nil
}
func (m *Manager) Nodes() []ScopedNode { return append([]ScopedNode(nil), m.nodes...) }
func (m *Manager) SetInvalidators(invalidate, revoked func(string)) {
	for _, n := range m.nodes {
		n.Adapter.Invalidate = invalidate
		n.Adapter.MarkRevoked = revoked
	}
}
func (m *Manager) Metadata() map[string]string {
	out := map[string]string{"sparkclaw_refresh_receipts": "v1"}
	if len(m.service) > 0 {
		out["sparkclaw_service_peer_recovery"] = "v1"
	}
	return out
}

func (m *Manager) OperatorBind(ctx context.Context, id identity.DeviceIdentity) error {
	a := m.service[id.DeviceID]
	if a == nil {
		return nil
	} // Preserve unrelated operator transport test identities.
	if !a.servicePeer(id) {
		return denied("service_peer_identity_conflict")
	}
	return a.OperatorBind(ctx, id)
}
func (m *Manager) Register(ctx context.Context, id identity.DeviceIdentity, proof identity.DeviceProof, ticket provisioning.PairingTicketV3) (json.RawMessage, error) {
	a := m.ticket[ticket.TrustRootID]
	if a == nil {
		return nil, denied("ticket_authority_unknown")
	}
	return a.Register(ctx, id, proof, ticket)
}
func (m *Manager) Refresh(r *http.Request) (json.RawMessage, error) {
	raw, e := io.ReadAll(io.LimitReader(r.Body, 16385))
	if e != nil {
		return nil, invalid("decode_failed")
	}
	var p struct {
		Refresh string `json:"refresh"`
	}
	if len(raw) > 16384 || node.StrictDecode(raw, &p) != nil || len(p.Refresh) < 32 || len(p.Refresh) > 512 {
		return nil, invalid("decode_failed")
	}
	var authority string
	// Revoked/expired token rows still locate the same authority for an exact
	// sealed receipt retry. The selected adapter then applies current liveness.
	e = m.db.QueryRow(r.Context(), `SELECT o.authority_id FROM iscp_relay.refresh_tokens t JOIN iscp_relay.node_device_ownership o ON o.domain_id=t.domain_id AND o.device_id=t.device_id WHERE t.domain_id=$1 AND t.refresh_hash=$2`, m.domain, c.SHA256([]byte(p.Refresh))).Scan(&authority)
	if e == pgx.ErrNoRows {
		return nil, Error{"refresh_credential_invalid", 401}
	}
	if e != nil {
		return nil, unavailable()
	}
	a := m.authorities[authority]
	if a == nil {
		return nil, denied("device_authority_unknown")
	}
	r = r.Clone(r.Context())
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return a.Refresh(r)
}
func (m *Manager) ServiceRecover(r *http.Request) (json.RawMessage, error) {
	raw, e := io.ReadAll(io.LimitReader(r.Body, node.MaxFrameBytes+1))
	if e != nil {
		return nil, invalid("decode_failed")
	}
	var p ServiceRecovery
	if node.StrictDecode(raw, &p) != nil {
		return nil, invalid("decode_failed")
	}
	a := m.service[p.Identity.DeviceID]
	if a == nil || !a.servicePeer(p.Identity) {
		return nil, denied("service_peer_not_approved")
	}
	r = r.Clone(r.Context())
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return a.ServiceRecover(r)
}
