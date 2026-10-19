// Derived from ISCP v0.2.0-rc.1 reference Relay; see UPSTREAM_LICENSE.txt.
// Deployment adapters preserve its public protocol and persisted signer.
package iscprelayreference

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/Infinimesh-ai/ISCP/pkg/server/httpx"
	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	"github.com/Infinimesh-ai/ISCP/pkg/server/queue"
	"github.com/Infinimesh-ai/ISCP/pkg/server/replay"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
)

type Config struct {
	SignerFile     string
	DomainID       string
	RelayID        string
	BaseURL        string
	WebSocketURL   string
	ProfileGate    config.Gate
	DB             *pgxpool.Pool
	AdminToken     string
	AllowedOrigins []string
	Managed        ManagedAdapter
	// TicketIssuer is the Trust Root signer identity used to verify
	// iscp.pairing_ticket.v3 signatures on register-with-ticket. Production
	// profile refuses ticketed registration without it.
	TicketIssuer *identity.DeviceIdentity
}

const accessProofHeader = "X-ISCP-Access-Proof"
const relayMaxQueuedBytes = 1 << 20

// ManagedAdapter is the deployment-owned transaction plane. It adds no public
// request fields to the reference registration interface.
type ManagedAdapter interface {
	Register(context.Context, identity.DeviceIdentity, identity.DeviceProof, provisioning.PairingTicketV3) (json.RawMessage, error)
	Refresh(*http.Request) (json.RawMessage, error)
	ServiceRecover(*http.Request) (json.RawMessage, error)
	Metadata() map[string]string
}

type Server struct {
	duplexMu        sync.Mutex
	duplexOwners    map[string]*duplexConnection
	duplexAll       map[*duplexConnection]struct{}
	duplexClosed    bool
	duplexWG        sync.WaitGroup
	admissionCommit func(context.Context, pgx.Tx) error
	cfg             Config
	provider        crypto.Provider
	signer          identity.Device
	mux             *http.ServeMux
	replay          *replay.Cache
	queue           *queue.Queue
	repo            *repository.RelayRepository
	upgrader        websocket.Upgrader
	mu              sync.RWMutex
	devices         map[string]identity.DeviceIdentity
	access          map[string]credential
	refresh         map[string]credential
	revoked         map[string]struct{}
	tickets         map[string]ticketState
	connections     map[string]connectionState
	startedAt       time.Time
	receiveMu       sync.Mutex
	receivers       map[string]*receiveSlot
	receiveClosed   bool
	queueMu         sync.Mutex
	reservedBytes   int
}

type credential struct {
	DomainID  string    `json:"domain_id"`
	DeviceID  string    `json:"device_id"`
	Token     string    `json:"token,omitempty"`
	Hash      []byte    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

type ticketState struct {
	MaxUses int
	Uses    int
}

type connectionState struct {
	ConnectionID string    `json:"connection_id"`
	DomainID     string    `json:"domain_id"`
	DeviceID     string    `json:"device_id"`
	State        string    `json:"state"`
	ConnectedAt  time.Time `json:"connected_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	ClosedAt     time.Time `json:"closed_at,omitempty"`
}

func New(cfg Config) (*Server, error) {
	provider := crypto.NewProvider()
	now := time.Now().UTC()
	signer, err := persistentSigner(provider, cfg, now)
	if err != nil {
		return nil, err
	}
	if cfg.ProfileGate.Profile == "" {
		cfg.ProfileGate = config.DefaultGate(config.ProfileLocalLab)
	}
	if err := config.ValidateGate(cfg.ProfileGate); err != nil {
		return nil, err
	}
	if cfg.ProfileGate.Profile == config.ProfileProduction && strings.TrimSpace(cfg.AdminToken) == "" {
		return nil, iscperrors.New(iscperrors.CodeConfigInvalid, "production relay requires ISCP_ADMIN_TOKEN")
	}
	if cfg.ProfileGate.Profile == config.ProfileProduction && len(cfg.AllowedOrigins) == 0 {
		return nil, iscperrors.New(iscperrors.CodeConfigInvalid, "production relay requires allowed WebSocket origins")
	}
	var repo *repository.RelayRepository
	if cfg.DB != nil {
		r := repository.NewRelayRepository(cfg.DB)
		repo = &r
	}
	s := &Server{
		cfg:         cfg,
		provider:    provider,
		signer:      signer,
		mux:         http.NewServeMux(),
		replay:      replay.NewCache(),
		queue:       queue.New(relayMaxQueuedBytes),
		repo:        repo,
		upgrader:    websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return originAllowed(r, cfg.AllowedOrigins, cfg.BaseURL, cfg.WebSocketURL) }},
		devices:     map[string]identity.DeviceIdentity{},
		access:      map[string]credential{},
		refresh:     map[string]credential{},
		revoked:     map[string]struct{}{},
		tickets:     map[string]ticketState{},
		connections: map[string]connectionState{},
		startedAt:   now,
		receivers:   map[string]*receiveSlot{},
	}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.health)
	s.mux.HandleFunc("/readyz", s.health)
	s.mux.HandleFunc("/livez", s.health)
	s.mux.HandleFunc("/metrics", s.metrics)
	s.mux.HandleFunc("/version", s.version)
	s.mux.HandleFunc("/.well-known/iscp/relay", s.wellKnown)
	s.mux.HandleFunc("/v2/relay/devices/bind-self", s.bindSelf)
	s.mux.HandleFunc("/v2/relay/devices/register-with-ticket", s.registerWithTicket)
	s.mux.HandleFunc("/v2/relay/devices/refresh-access", s.refreshAccess)
	s.mux.HandleFunc("/api/sparkclaw/iscp-control/v1/service-recover", s.serviceRecover)
	s.mux.HandleFunc("/v2/relay/devices/revoke-access", s.revokeAccess)
	s.mux.HandleFunc("/v2/relay/envelopes", s.retiredTransport)
	s.mux.HandleFunc("/v2/relay/connect", s.retiredTransport)
	s.mux.HandleFunc(duplex.Path, s.duplexConnect)
	s.mux.HandleFunc("/v2/relay/admin/devices", s.adminDevices)
	s.mux.HandleFunc("/v2/relay/admin/connections", s.adminConnections)
	s.mux.HandleFunc("/v2/relay/admin/messages", s.adminMessages)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte("# HELP iscp_relay_up Relay process status\n# TYPE iscp_relay_up gauge\niscp_relay_up 1\n"))
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"version": "0.2.0-dev", "protocol": "v2"})
}

func (s *Server) wellKnown(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	relayDesc := descriptor.RelayDescriptor{
		Type:         "iscp.relay.descriptor.v2",
		RelayID:      s.cfg.RelayID,
		DomainID:     s.cfg.DomainID,
		BaseURL:      s.cfg.BaseURL,
		WebSocketURL: strings.TrimRight(strings.Replace(strings.Replace(s.cfg.BaseURL, "https://", "wss://", 1), "http://", "ws://", 1), "/") + duplex.Path,
		SigningKeys: []descriptor.PublicKey{{
			KTY:    "Ed25519",
			Use:    "descriptor-signature",
			KID:    s.signer.Identity.PublicKey.KID,
			Public: s.signer.Identity.PublicKey.Public,
		}},
		IssuedAt:  now,
		ExpiresAt: now.Add(24 * time.Hour),
	}
	if s.cfg.Managed != nil {
		relayDesc.Metadata = s.cfg.Managed.Metadata()
	}
	if relayDesc.Metadata == nil {
		relayDesc.Metadata = map[string]string{}
	}
	relayDesc.Metadata["duplex_protocol"] = duplex.Protocol
	relayDesc.Metadata["duplex_path"] = duplex.Path
	relayDesc.Metadata["duplex_limits_sha256"], _ = duplex.Digest(duplex.DefaultLimits())
	signed, err := descriptor.Sign(s.provider, s.signer, relayDesc.Type, relayDesc, now)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	pin, _ := descriptor.Pin(signed)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"descriptor": signed, "pin": pin})
}

type bindSelfRequest struct {
	Identity identity.DeviceIdentity `json:"identity"`
	Proof    identity.DeviceProof    `json:"proof"`
}

func (s *Server) bindSelf(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req bindSelfRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	// Bootstrap is actor-authorized (spec/provisioning.md). The reference
	// stands in the external actor assertion with the operator admin token.
	if s.cfg.ProfileGate.Profile == config.ProfileProduction && !s.adminAuthorized(r) {
		httpx.WriteError(w, http.StatusUnauthorized, iscperrors.New(iscperrors.CodeAccessInvalid, "production bind-self requires an actor authorization"))
		return
	}
	if err := s.verifyProof(r.Context(), req.Identity, req.Proof, s.cfg.RelayID, req.Proof.Challenge, 5*time.Minute); err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, err)
		return
	}
	if binder, ok := s.cfg.Managed.(interface {
		OperatorBind(context.Context, identity.DeviceIdentity) error
	}); ok {
		if err := binder.OperatorBind(r.Context(), req.Identity); err != nil {
			httpx.WriteError(w, managedStatus(err), err)
			return
		}
	}
	s.bindIdentity(w, r, req.Identity)
}

type registerTicketRequest struct {
	TicketID string                        `json:"ticket_id,omitempty"`
	MaxUses  int                           `json:"max_uses,omitempty"`
	Ticket   *provisioning.PairingTicketV3 `json:"ticket,omitempty"`
	Identity identity.DeviceIdentity       `json:"identity"`
	Proof    identity.DeviceProof          `json:"proof"`
}

func (s *Server) registerWithTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req registerTicketRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if req.Ticket != nil {
		s.registerWithSignedTicket(w, r, req)
		return
	}
	// Legacy ticket_id-only registration never verified a ticket signature
	// and is a local-lab behavior.
	if s.cfg.ProfileGate.Profile == config.ProfileProduction {
		httpx.WriteError(w, http.StatusBadRequest, iscperrors.New(iscperrors.CodeProvisionInvalid, "production registration requires a signed pairing ticket"))
		return
	}
	if err := s.verifyProof(r.Context(), req.Identity, req.Proof, s.cfg.RelayID, req.Proof.Challenge, 5*time.Minute); err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, err)
		return
	}
	if err := s.consumeTicket(req.TicketID, req.MaxUses); err != nil {
		httpx.WriteError(w, http.StatusConflict, err)
		return
	}
	s.bindIdentity(w, r, req.Identity)
}

func (s *Server) registerWithSignedTicket(w http.ResponseWriter, r *http.Request, req registerTicketRequest) {
	if s.cfg.Managed != nil {
		raw, err := s.cfg.Managed.Register(r.Context(), req.Identity, req.Proof, *req.Ticket)
		if err != nil {
			httpx.WriteError(w, managedStatus(err), err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
		return
	}
	if s.cfg.TicketIssuer == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, iscperrors.New(iscperrors.CodeConfigInvalid, "relay has no configured ticket issuer"))
		return
	}
	ticket := *req.Ticket
	now := time.Now().UTC()
	if err := provisioning.VerifyTicketV3(s.provider, ticket, *s.cfg.TicketIssuer, now); err != nil {
		httpx.WriteError(w, http.StatusForbidden, err)
		return
	}
	if ticket.DomainID != s.cfg.DomainID || ticket.RelayID != s.cfg.RelayID {
		httpx.WriteError(w, http.StatusForbidden, iscperrors.New(iscperrors.CodeProvisionInvalid, "pairing ticket is not bound to this relay"))
		return
	}
	// The proof challenge is the ticket ID, binding possession to this exact
	// consumption; self-reported challenges are rejected.
	if req.Proof.Challenge != ticket.TicketID {
		httpx.WriteError(w, http.StatusUnauthorized, iscperrors.New(iscperrors.CodeProvisionInvalid, "proof challenge must be the ticket id"))
		return
	}
	if err := s.verifyProof(r.Context(), req.Identity, req.Proof, s.cfg.RelayID, ticket.TicketID, 5*time.Minute); err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, err)
		return
	}
	if _, err := provisioning.BindGrantRoles(ticket, req.Identity); err != nil {
		httpx.WriteError(w, http.StatusForbidden, err)
		return
	}
	if err := s.consumeTicket(ticket.TicketID, ticket.MaxUses); err != nil {
		httpx.WriteError(w, http.StatusConflict, err)
		return
	}
	s.bindIdentity(w, r, req.Identity)
}

func (s *Server) consumeTicket(ticketID string, maxUses int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.tickets[ticketID]
	if state.MaxUses == 0 {
		state.MaxUses = maxUses
	}
	if state.MaxUses <= 0 || state.Uses >= state.MaxUses {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "pairing ticket already consumed")
	}
	state.Uses++
	s.tickets[ticketID] = state
	return nil
}

func (s *Server) refreshAccess(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Managed != nil {
		raw, err := s.cfg.Managed.Refresh(r)
		if err != nil {
			httpx.WriteError(w, managedStatus(err), err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(raw)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Refresh string `json:"refresh"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	hash := string(crypto.SHA256([]byte(req.Refresh)))
	s.mu.Lock()
	cred, ok := s.refresh[hash]
	if ok && !cred.Revoked && time.Now().After(cred.ExpiresAt) {
		ok = false
	}
	s.mu.Unlock()
	if !ok && s.repo != nil {
		dbCred, err := s.repo.GetRefreshByHash(r.Context(), repository.DomainID(s.cfg.DomainID), crypto.SHA256([]byte(req.Refresh)), time.Now().UTC())
		if err == nil {
			cred = credential{DomainID: string(dbCred.DomainID), DeviceID: dbCred.DeviceID, Hash: dbCred.Hash, ExpiresAt: dbCred.ExpiresAt}
			ok = true
		} else if err != pgx.ErrNoRows {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if !ok || cred.Revoked || time.Now().After(cred.ExpiresAt) {
		httpx.WriteError(w, http.StatusUnauthorized, iscperrors.New(iscperrors.CodeAccessInvalid, "refresh credential invalid"))
		return
	}
	if err := s.revokeRefreshCredential(r.Context(), req.Refresh); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	access, refresh, err := s.issueCredentials(r.Context(), cred.DomainID, cred.DeviceID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"access": access, "refresh": refresh})
}

func (s *Server) revokeAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	cred, err := s.authenticateAccess(r)
	if err != nil {
		if !s.adminAuthorized(r) {
			httpx.WriteError(w, http.StatusUnauthorized, err)
			return
		}
	} else if cred.DeviceID != req.DeviceID {
		httpx.WriteError(w, http.StatusForbidden, iscperrors.New(iscperrors.CodeAccessInvalid, "access credential cannot revoke another device"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[req.DeviceID] = struct{}{}
	for k, cred := range s.access {
		if cred.DeviceID == req.DeviceID {
			cred.Revoked = true
			s.access[k] = cred
		}
	}
	for k, cred := range s.refresh {
		if cred.DeviceID == req.DeviceID {
			cred.Revoked = true
			s.refresh[k] = cred
		}
	}
	s.stopReceiver(s.cfg.DomainID, req.DeviceID)
	if s.repo != nil {
		now := time.Now().UTC()
		if err := s.repo.RevokeDevice(r.Context(), repository.DomainID(s.cfg.DomainID), req.DeviceID, now); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		if err := s.repo.RevokeDeviceCredentials(r.Context(), repository.DomainID(s.cfg.DomainID), req.DeviceID, now); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) envelopes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cred, err := s.authenticateAccess(r)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, err)
		return
	}
	var raw json.RawMessage
	if err := httpx.DecodeJSON(r, &raw); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	var meta struct {
		DomainID          string `json:"domain_id"`
		MessageID         string `json:"message_id"`
		SenderDeviceID    string `json:"sender_device_id"`
		RecipientDeviceID string `json:"recipient_device_id"`
		Route             struct {
			TTLSeconds int `json:"ttl_seconds"`
			Priority   int `json:"priority"`
		} `json:"route"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.validateEnvelopeMeta(meta.DomainID, meta.MessageID, meta.SenderDeviceID, meta.RecipientDeviceID, meta.Route.TTLSeconds, meta.Route.Priority); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if cred.DomainID != meta.DomainID || cred.DeviceID != meta.SenderDeviceID {
		httpx.WriteError(w, http.StatusForbidden, iscperrors.New(iscperrors.CodeAccessInvalid, "access credential does not match envelope sender"))
		return
	}
	canon, err := canonical.Marshal(raw)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(meta.Route.TTLSeconds) * time.Second)
	receiptID := "receipt-" + meta.MessageID
	receipt := map[string]any{
		"type":       "iscp.delivery_receipt.v2",
		"receipt_id": receiptID,
		"message_id": meta.MessageID,
		"domain_id":  meta.DomainID,
		"relay_id":   s.cfg.RelayID,
		"status":     "queued",
		"issued_at":  now,
	}
	if s.repo != nil {
		if len(raw) > relayMaxQueuedBytes {
			httpx.WriteError(w, http.StatusRequestEntityTooLarge, iscperrors.New(iscperrors.CodeEnvelopeInvalid, "message too large"))
			return
		}
		routeRaw, _ := json.Marshal(meta.Route)
		msgID, err := postgres.NewUUIDv7Like(now)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		if err := s.repo.StoreMessage(r.Context(), repository.RelayMessage{
			ID:                postgres.UUIDString(msgID),
			DomainID:          repository.DomainID(meta.DomainID),
			MessageID:         meta.MessageID,
			SenderDeviceID:    meta.SenderDeviceID,
			RecipientDeviceID: meta.RecipientDeviceID,
			SessionID:         envelopeStringField(raw, "session_id"),
			PayloadType:       envelopeStringField(raw, "payload_type"),
			RouteMetadata:     routeRaw,
			EnvelopeRaw:       raw,
			EnvelopeCanonical: canon,
			Priority:          meta.Route.Priority,
			QueuedAt:          now,
			ExpiresAt:         expiresAt,
		}); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		receiptRaw, _ := json.Marshal(receipt)
		receiptCanon, err := canonical.Marshal(receiptRaw)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		receiptUUID, err := postgres.NewUUIDv7Like(now)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		if err := s.repo.StoreReceipt(r.Context(), repository.RelayReceipt{
			ID:               postgres.UUIDString(receiptUUID),
			DomainID:         repository.DomainID(meta.DomainID),
			ReceiptID:        receiptID,
			MessageID:        meta.MessageID,
			RelayID:          s.cfg.RelayID,
			Status:           "queued",
			ReceiptRaw:       receiptRaw,
			ReceiptCanonical: receiptCanon,
			IssuedAt:         now,
		}); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
	} else if !s.enqueueMemory(queue.Message{
		DomainID:          meta.DomainID,
		MessageID:         meta.MessageID,
		SenderDeviceID:    meta.SenderDeviceID,
		RecipientDeviceID: meta.RecipientDeviceID,
		Envelope:          raw,
		Priority:          meta.Route.Priority,
		ExpiresAt:         expiresAt,
	}, now) {
		httpx.WriteError(w, http.StatusRequestEntityTooLarge, iscperrors.New(iscperrors.CodeEnvelopeInvalid, "message too large"))
		return
	}
	s.wakeReceiver(meta.DomainID, meta.RecipientDeviceID)
	httpx.WriteJSON(w, http.StatusAccepted, receipt)
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	c, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
	c.SetReadLimit(64 << 10)
	_ = c.SetReadDeadline(time.Now().Add(receiveIOTimeout))
	_ = c.SetWriteDeadline(time.Now().Add(receiveIOTimeout))
	challenge := randomToken()
	if err := c.WriteJSON(map[string]string{"state": "challenge", "challenge": challenge}); err != nil {
		return
	}
	var proof identity.DeviceProof
	if err := c.ReadJSON(&proof); err != nil {
		return
	}
	s.mu.RLock()
	id, ok := s.devices[proof.DeviceID]
	_, revoked := s.revoked[proof.DeviceID]
	s.mu.RUnlock()
	if !ok && s.repo != nil {
		dbDevice, err := s.repo.GetDevice(r.Context(), repository.DomainID(s.cfg.DomainID), proof.DeviceID)
		if err == nil {
			if dbDevice.Status == "revoked" {
				revoked = true
			} else {
				if err := json.Unmarshal(dbDevice.IdentityRaw, &id); err == nil {
					ok = true
				}
			}
		}
	}
	if !ok || revoked {
		_ = c.WriteJSON(map[string]string{"state": "closed", "error": "access revoked or unknown"})
		return
	}
	if err := s.verifyProof(r.Context(), id, proof, s.cfg.RelayID, challenge, time.Minute); err != nil {
		_ = c.WriteJSON(map[string]string{"state": "closed", "error": "proof failed"})
		return
	}
	connectionID := "conn-" + randomToken()[:16]
	now := time.Now().UTC()
	s.recordConnection(connectionState{
		ConnectionID: connectionID,
		DomainID:     id.DomainID,
		DeviceID:     id.DeviceID,
		State:        "ready",
		ConnectedAt:  now,
		LastSeenAt:   now,
	})
	defer s.closeConnection(connectionID)
	s.receiveStream(r.Context(), c, id)
}

func (s *Server) adminDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	httpx.WriteJSON(w, http.StatusOK, s.devices)
}

func (s *Server) adminConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	httpx.WriteJSON(w, http.StatusOK, s.connections)
}

func (s *Server) adminMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	now := time.Now().UTC()
	if s.repo != nil {
		messages, err := s.repo.ListPendingMessages(r.Context(), repository.DomainID(s.cfg.DomainID), now, 500)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, relayMessageMetadata(messages))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s.queue.SnapshotMetadata(now))
}

func relayMessageMetadata(messages []repository.RelayMessage) []queue.MessageMetadata {
	out := make([]queue.MessageMetadata, 0, len(messages))
	for _, msg := range messages {
		out = append(out, queue.MessageMetadata{
			DomainID:          string(msg.DomainID),
			MessageID:         msg.MessageID,
			SenderDeviceID:    msg.SenderDeviceID,
			RecipientDeviceID: msg.RecipientDeviceID,
			Priority:          msg.Priority,
			QueuedAt:          msg.QueuedAt,
			ExpiresAt:         msg.ExpiresAt,
		})
	}
	return out
}

func (s *Server) issueCredentials(ctx context.Context, domainID, deviceID string) (credential, credential, error) {
	now := time.Now().UTC()
	accessToken := randomToken()
	refreshToken := randomToken()
	access := credential{DomainID: domainID, DeviceID: deviceID, Token: accessToken, Hash: crypto.SHA256([]byte(accessToken)), ExpiresAt: now.Add(15 * time.Minute)}
	refresh := credential{DomainID: domainID, DeviceID: deviceID, Token: refreshToken, Hash: crypto.SHA256([]byte(refreshToken)), ExpiresAt: now.Add(24 * time.Hour)}
	if s.repo != nil {
		accessID, err := postgres.NewUUIDv7Like(now)
		if err != nil {
			return credential{}, credential{}, err
		}
		refreshID, err := postgres.NewUUIDv7Like(now)
		if err != nil {
			return credential{}, credential{}, err
		}
		if err := s.repo.StoreAccessHash(ctx, postgres.UUIDString(accessID), repository.DomainID(domainID), deviceID, access.Hash, now, access.ExpiresAt); err != nil {
			return credential{}, credential{}, err
		}
		if err := s.repo.StoreRefreshHash(ctx, postgres.UUIDString(refreshID), repository.DomainID(domainID), deviceID, refresh.Hash, now, refresh.ExpiresAt); err != nil {
			return credential{}, credential{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.access[string(access.Hash)] = access
	s.refresh[string(refresh.Hash)] = refresh
	return access, refresh, nil
}

func (s *Server) bindIdentity(w http.ResponseWriter, r *http.Request, id identity.DeviceIdentity) {
	if err := s.persistDevice(r.Context(), id, "active"); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	access, refresh, err := s.issueCredentials(r.Context(), id.DomainID, id.DeviceID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	s.mu.Lock()
	s.devices[id.DeviceID] = id
	s.mu.Unlock()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"access": access, "refresh": refresh})
}

func (s *Server) verifyProof(ctx context.Context, id identity.DeviceIdentity, proof identity.DeviceProof, audience, challenge string, ttl time.Duration) error {
	if strings.TrimSpace(proof.Nonce) == "" {
		return iscperrors.New(iscperrors.CodeReplayDetected, "proof nonce is required")
	}
	now := time.Now().UTC()
	if err := identity.VerifyProof(s.provider, id, proof, audience, challenge, now, ttl); err != nil {
		return err
	}
	key := strings.Join([]string{proof.DomainID, proof.DeviceID, proof.Audience, proof.Nonce}, "\x00")
	expiresAt := proof.IssuedAt.Add(ttl)
	if s.repo != nil {
		used, err := s.repo.UseProofNonce(ctx, repository.DomainID(proof.DomainID), proof.DeviceID, proof.Audience, proof.Nonce, expiresAt, now)
		if err != nil {
			return err
		}
		if !used {
			return iscperrors.New(iscperrors.CodeReplayDetected, "proof nonce replay detected")
		}
		return nil
	}
	if !s.replay.Use(key, expiresAt, now) {
		return iscperrors.New(iscperrors.CodeReplayDetected, "proof nonce replay detected")
	}
	return nil
}

func (s *Server) authenticateAccess(r *http.Request) (credential, error) {
	token := bearerToken(r)
	if token == "" {
		return credential{}, iscperrors.New(iscperrors.CodeAccessInvalid, "access credential is required")
	}
	hash := crypto.SHA256([]byte(token))
	hashKey := string(hash)
	now := time.Now().UTC()
	s.mu.Lock()
	cred, ok := s.access[hashKey]
	if ok && !cred.Revoked && now.After(cred.ExpiresAt) {
		cred.Revoked = true
		s.access[hashKey] = cred
	}
	s.mu.Unlock()
	if ok && !cred.Revoked && now.Before(cred.ExpiresAt) {
		if err := s.verifyAccessProof(r, cred, hash); err != nil {
			return credential{}, err
		}
		return cred, nil
	}
	if s.repo != nil {
		dbCred, err := s.repo.GetAccessByHash(r.Context(), repository.DomainID(s.cfg.DomainID), hash, now)
		if err == nil {
			cred := credential{DomainID: string(dbCred.DomainID), DeviceID: dbCred.DeviceID, Hash: dbCred.Hash, ExpiresAt: dbCred.ExpiresAt}
			if err := s.verifyAccessProof(r, cred, hash); err != nil {
				return credential{}, err
			}
			return cred, nil
		}
		if err != pgx.ErrNoRows {
			return credential{}, err
		}
	}
	return credential{}, iscperrors.New(iscperrors.CodeAccessInvalid, "access credential invalid")
}

func (s *Server) verifyAccessProof(r *http.Request, cred credential, accessHash []byte) error {
	if s.cfg.ProfileGate.Profile != config.ProfileProduction {
		return nil
	}
	value := strings.TrimSpace(r.Header.Get(accessProofHeader))
	if value == "" {
		return iscperrors.New(iscperrors.CodeAccessInvalid, "production relay access requires proof of possession")
	}
	raw, err := crypto.DecodeBase64URL(value)
	if err != nil {
		return err
	}
	var proof identity.DeviceProof
	if err := json.Unmarshal(raw, &proof); err != nil {
		return iscperrors.New(iscperrors.CodeAccessInvalid, "invalid relay access proof")
	}
	id, ok, err := s.lookupIdentity(r.Context(), cred.DomainID, cred.DeviceID)
	if err != nil {
		return err
	}
	if !ok {
		return iscperrors.New(iscperrors.CodeAccessInvalid, "access proof identity is unknown")
	}
	challenge := accessProofChallenge(r.Method, r.URL.Path, accessHash)
	return s.verifyProof(r.Context(), id, proof, s.cfg.RelayID, challenge, time.Minute)
}

func (s *Server) lookupIdentity(ctx context.Context, domainID, deviceID string) (identity.DeviceIdentity, bool, error) {
	s.mu.RLock()
	id, ok := s.devices[deviceID]
	_, revoked := s.revoked[deviceID]
	s.mu.RUnlock()
	if ok && !revoked && id.DomainID == domainID {
		return id, true, nil
	}
	if s.repo == nil {
		return identity.DeviceIdentity{}, false, nil
	}
	dbDevice, err := s.repo.GetDevice(ctx, repository.DomainID(domainID), deviceID)
	if err == pgx.ErrNoRows {
		return identity.DeviceIdentity{}, false, nil
	}
	if err != nil {
		return identity.DeviceIdentity{}, false, err
	}
	if dbDevice.Status == "revoked" {
		return identity.DeviceIdentity{}, false, nil
	}
	if err := json.Unmarshal(dbDevice.IdentityRaw, &id); err != nil {
		return identity.DeviceIdentity{}, false, err
	}
	return id, true, nil
}

func accessProofChallenge(method, path string, accessHash []byte) string {
	return strings.Join([]string{
		"iscp/v2/relay/access-proof",
		strings.ToUpper(method),
		path,
		crypto.Base64URL(accessHash),
	}, "\x00")
}

func (s *Server) revokeRefreshCredential(ctx context.Context, token string) error {
	hash := crypto.SHA256([]byte(token))
	hashKey := string(hash)
	s.mu.Lock()
	if cred, ok := s.refresh[hashKey]; ok {
		cred.Revoked = true
		s.refresh[hashKey] = cred
	}
	s.mu.Unlock()
	if s.repo != nil {
		return s.repo.RevokeRefreshByHash(ctx, repository.DomainID(s.cfg.DomainID), hash, time.Now().UTC())
	}
	return nil
}

func (s *Server) validateEnvelopeMeta(domainID, messageID, senderDeviceID, recipientDeviceID string, ttlSeconds, priority int) error {
	if domainID != s.cfg.DomainID {
		return iscperrors.New(iscperrors.CodeEnvelopeInvalid, "envelope domain does not match relay domain")
	}
	if strings.TrimSpace(messageID) == "" || strings.TrimSpace(senderDeviceID) == "" || strings.TrimSpace(recipientDeviceID) == "" {
		return iscperrors.New(iscperrors.CodeEnvelopeInvalid, "envelope routing identifiers are required")
	}
	if ttlSeconds <= 0 || ttlSeconds > int((24*time.Hour)/time.Second) {
		return iscperrors.New(iscperrors.CodeEnvelopeInvalid, "envelope ttl must be between 1 second and 24 hours")
	}
	if priority < 0 || priority > 9 {
		return iscperrors.New(iscperrors.CodeEnvelopeInvalid, "envelope priority must be between 0 and 9")
	}
	return nil
}

func (s *Server) recordConnection(state connectionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connections[state.ConnectionID] = state
}

func (s *Server) closeConnection(connectionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.connections[connectionID]
	state.State = "closed"
	state.ClosedAt = time.Now().UTC()
	state.LastSeenAt = state.ClosedAt
	s.connections[connectionID] = state
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.adminAuthorized(r) {
		return true
	}
	httpx.WriteError(w, http.StatusUnauthorized, iscperrors.New(iscperrors.CodeAccessInvalid, "admin credential is required"))
	return false
}

func (s *Server) adminAuthorized(r *http.Request) bool {
	expected := strings.TrimSpace(s.cfg.AdminToken)
	if expected == "" {
		return true
	}
	token := bearerToken(r)
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-ISCP-Admin-Token"))
	}
	if token == "" || len(token) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

func bearerToken(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if value == "" {
		return ""
	}
	prefix := "Bearer "
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(value[len(prefix):])
}

func originAllowed(r *http.Request, allowed []string, fallbackURLs ...string) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	allowedSet := map[string]struct{}{}
	for _, item := range allowed {
		if normalized := normalizedOrigin(item); normalized != "" {
			allowedSet[normalized] = struct{}{}
		}
	}
	for _, item := range fallbackURLs {
		if normalized := normalizedOrigin(item); normalized != "" {
			allowedSet[normalized] = struct{}{}
		}
	}
	_, ok := allowedSet[normalizedOrigin(origin)]
	return ok
}

func normalizedOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	scheme := u.Scheme
	if scheme == "ws" {
		scheme = "http"
	} else if scheme == "wss" {
		scheme = "https"
	}
	return scheme + "://" + strings.ToLower(u.Host)
}

func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return crypto.Base64URL(b[:])
}

func (s *Server) persistDevice(ctx context.Context, id identity.DeviceIdentity, status string) error {
	if s.repo == nil {
		return nil
	}
	raw, err := json.Marshal(id)
	if err != nil {
		return err
	}
	canon, err := canonical.Marshal(raw)
	if err != nil {
		return err
	}
	tp, err := identity.Thumbprint(id)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	uuid, err := postgres.NewUUIDv7Like(now)
	if err != nil {
		return err
	}
	return s.repo.InsertDevice(ctx, repository.RelayDevice{
		ID:                  postgres.UUIDString(uuid),
		DomainID:            repository.DomainID(id.DomainID),
		DeviceID:            id.DeviceID,
		IdentityRaw:         raw,
		IdentityCanonical:   canon,
		PublicKeyThumbprint: tp,
		Status:              status,
		CreatedAt:           now,
		UpdatedAt:           now,
	})
}

func envelopeStringField(raw json.RawMessage, key string) string {
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil {
		return ""
	}
	value, _ := meta[key].(string)
	return value
}
