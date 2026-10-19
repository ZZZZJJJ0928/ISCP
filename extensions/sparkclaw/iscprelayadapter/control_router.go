package iscprelayadapter

import (
	"context"
	"encoding/json"
	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"io"
	"net/http"
	"sync"
	"time"
)

// ControlService chooses only a durable ownership binding. JSON fields cannot
// select a verifier, issuer authority, arbitrary origin or service credential.
type ControlService struct {
	nodes  []*ControlBackend
	signer identity.Device
	mu     sync.Mutex
	nonces map[string]time.Time
}

func NewControlService(ctx context.Context, nodes []ScopedNode, signer identity.Device, epoch string) (*ControlService, error) {
	service := &ControlService{signer: signer, nonces: map[string]time.Time{}}
	for _, n := range nodes {
		b, e := n.Adapter.EnableControlV2(ctx, signer, epoch)
		if e != nil {
			return nil, e
		}
		service.nodes = append(service.nodes, b)
	}
	if len(service.nodes) == 0 {
		return nil, node.ErrInvalid
	}
	return service, nil
}
func (s *ControlService) owner(ctx context.Context, domain, device string) (*ControlBackend, error) {
	var authority string
	if err := s.nodes[0].adapter.db.QueryRow(ctx, "SELECT authority_id FROM iscp_relay.node_device_ownership WHERE domain_id=$1 AND device_id=$2", domain, device).Scan(&authority); err != nil {
		return nil, control.ErrAuthentication
	}
	for _, b := range s.nodes {
		if b.adapter.authority == authority {
			return b, nil
		}
	}
	return nil, control.ErrAuthentication
}
func (s *ControlService) ResolveActor(ctx context.Context, domain, device string) (identity.DeviceIdentity, error) {
	b, e := s.owner(ctx, domain, device)
	if e != nil {
		return identity.DeviceIdentity{}, e
	}
	return b.ResolveActor(ctx, domain, device)
}
func (s *ControlService) Execute(ctx context.Context, r control.Request, id identity.DeviceIdentity, token string) (control.Outcome, error) {
	b, e := s.owner(ctx, id.DomainID, id.DeviceID)
	if e != nil {
		return control.Outcome{}, e
	}
	return b.Execute(ctx, r, id, token)
}
func (s *ControlService) Disclose(ctx context.Context, r control.Request, id identity.DeviceIdentity, emit func() error) error {
	b, e := s.owner(ctx, id.DomainID, id.DeviceID)
	if e != nil {
		return e
	}
	return b.Disclose(ctx, r, id, emit)
}
func (s *ControlService) Handler() http.Handler {
	operations := control.NewHandler(s.nodes[0].adapter.cfg.RelayID, s.signer, s)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == node.ControlAuthorityPath {
			s.authorityHTTP(w, r)
			return
		}
		operations.ServeHTTP(w, r)
	})
}
func (s *ControlService) authorityHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.RawPath != "" {
		http.NotFound(w, r)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, control.MaxBody+1))
	if e != nil || len(raw) > control.MaxBody {
		http.Error(w, "invalid request", 400)
		return
	}
	var q node.ControlAuthorityRequest
	if node.StrictDecode(raw, &q) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	actor, e := s.ResolveActor(r.Context(), q.Actor.DomainID, q.Actor.DeviceID)
	if e != nil || q.Verify(actor, time.Now()) != nil {
		http.Error(w, "authentication failed", 401)
		return
	}
	s.mu.Lock()
	now := time.Now()
	for key, expiry := range s.nonces {
		if !now.Before(expiry) {
			delete(s.nonces, key)
		}
	}
	_, seen := s.nonces[q.Nonce]
	if seen || len(s.nonces) >= 4096 {
		s.mu.Unlock()
		http.Error(w, "authentication failed", 401)
		return
	}
	s.nonces[q.Nonce] = now.Add(15 * time.Second)
	s.mu.Unlock()
	backend, e := s.owner(r.Context(), actor.DomainID, actor.DeviceID)
	if e != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	authority, e := backend.Authority(r.Context(), actor, q.Subject, q.Target)
	if e != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	out, e := node.NewControlAuthorityResponse(q, authority, s.signer)
	if e != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}
func (a *Adapter) DiscloseRegistration(ctx context.Context, id identity.DeviceIdentity, emit func() error) error {
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	if e = a.lockLifecycle(ctx, tx, id.DeviceID, "", false, false); e != nil {
		return e
	}
	if e = a.owned(ctx, tx, id.DeviceID); e != nil {
		return e
	}
	if e = a.active(ctx, tx, id.DeviceID); e != nil {
		return e
	}
	return emit()
}
func (m *Manager) DiscloseRegistration(ctx context.Context, id identity.DeviceIdentity, emit func() error) error {
	var owner string
	if err := m.db.QueryRow(ctx, "SELECT authority_id FROM iscp_relay.node_device_ownership WHERE domain_id=$1 AND device_id=$2", id.DomainID, id.DeviceID).Scan(&owner); err != nil {
		return err
	}
	a := m.authorities[owner]
	if a == nil {
		return control.ErrAuthentication
	}
	return a.DiscloseRegistration(ctx, id, emit)
}
