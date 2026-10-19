// Package iscprelayadapter implements a deployment-private transaction plane
// around the pinned ISCP Relay. Its Unix API is never a public admin endpoint.
package iscprelayadapter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
	ControlIssuerActor *identity.DeviceIdentity  `json:"control_issuer_actor,omitempty"`
	SchemaVersion      int                       `json:"schema_version,omitempty"`
	DomainID           string                    `json:"domain_id"`
	RelayID            string                    `json:"relay_id"`
	InvitationSigner   identity.DeviceIdentity   `json:"invitation_signer"`
	GrantSigner        identity.DeviceIdentity   `json:"grant_signer"`
	Responder          identity.DeviceIdentity   `json:"responder"`
	ServicePeers       []identity.DeviceIdentity `json:"service_peers,omitempty"`
	issuerRoute        string
}

type Adapter struct {
	controlEpoch   string
	controlBackend *ControlBackend
	cfg            Config
	db             *pgxpool.Pool
	Invalidate     func(string)
	MarkRevoked    func(string)
	Now            func() time.Time
	authority      string
}

type Error struct {
	Reason string
	Status int
}

func (e Error) Error() string      { return e.Reason }
func (e Error) StatusCode() int    { return e.Status }
func invalid(reason string) error  { return Error{reason, http.StatusBadRequest} }
func denied(reason string) error   { return Error{reason, http.StatusForbidden} }
func conflict(reason string) error { return Error{reason, http.StatusConflict} }
func unavailable() error           { return Error{"temporarily_unavailable", http.StatusServiceUnavailable} }

var operationPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{7,199}$`)

func New(ctx context.Context, pool *pgxpool.Pool, cfg Config) (*Adapter, error) {
	return newAdapter(ctx, pool, cfg, true)
}
func validateConfig(cfg Config) error {
	if cfg.SchemaVersion < 0 || cfg.SchemaVersion > 1 {
		return invalid("invalid_authority_version")
	}
	if cfg.DomainID == "" || cfg.RelayID == "" {
		return invalid("database_and_identity_required")
	}
	for _, id := range []identity.DeviceIdentity{cfg.InvitationSigner, cfg.GrantSigner, cfg.Responder} {
		if iscpnodeissuer.ValidateIdentity(id) != nil || id.DomainID != cfg.DomainID {
			return invalid("invalid_authority")
		}
	}
	if cfg.InvitationSigner.PublicKey.Public == cfg.GrantSigner.PublicKey.Public {
		return invalid("signing_purposes_must_be_separate")
	}
	roles := []identity.DeviceIdentity{cfg.InvitationSigner, cfg.GrantSigner, cfg.Responder}
	for i, id := range roles {
		for j := 0; j < i; j++ {
			if roles[j].DeviceID == id.DeviceID || roles[j].PublicKey.Public == id.PublicKey.Public {
				return invalid("authority_roles_must_be_separate")
			}
		}
	}
	seen := map[string]bool{}
	keyOwners := map[string]string{}
	identityOwners := map[string]string{}
	for _, id := range roles {
		keyOwners[id.PublicKey.Public] = id.DeviceID
		identityOwners[id.DeviceID] = iscpnodeissuer.Digest(id)
	}
	for _, id := range cfg.ServicePeers {
		if iscpnodeissuer.ValidateIdentity(id) != nil || id.DomainID != cfg.DomainID || seen[id.DeviceID] {
			return invalid("invalid_service_peer")
		}
		if owner, ok := keyOwners[id.PublicKey.Public]; ok && owner != id.DeviceID {
			return invalid("duplicate_service_key")
		}
		if digest, ok := identityOwners[id.DeviceID]; ok && digest != iscpnodeissuer.Digest(id) {
			return invalid("duplicate_service_identity")
		}
		if id.DeviceID == cfg.InvitationSigner.DeviceID || id.DeviceID == cfg.GrantSigner.DeviceID {
			return invalid("signer_cannot_be_service_peer")
		}
		keyOwners[id.PublicKey.Public] = id.DeviceID
		identityOwners[id.DeviceID] = iscpnodeissuer.Digest(id)
		seen[id.DeviceID] = true
	}
	return nil
}
func newAdapter(ctx context.Context, pool *pgxpool.Pool, cfg Config, allowLegacy bool) (*Adapter, error) {
	if pool == nil || cfg.DomainID == "" || cfg.RelayID == "" {
		return nil, invalid("database_and_identity_required")
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	a := &Adapter{cfg: cfg, db: pool, Now: time.Now, authority: authorityID(cfg)}
	if err := a.initialize(ctx, allowLegacy); err != nil {
		return nil, err
	}
	return a, nil
}
func (a *Adapter) Metadata() map[string]string {
	if a.controlEpoch != "" {
		return map[string]string{"iscp_control": "v2"}
	}
	out := map[string]string{"sparkclaw_refresh_receipts": "v1"}
	if len(a.cfg.ServicePeers) > 0 {
		out["sparkclaw_service_peer_recovery"] = "v1"
	}
	return out
}
func (a *Adapter) now() time.Time { return a.Now().UTC() }
func (a *Adapter) invalidated(id string) {
	if a.Invalidate != nil {
		a.Invalidate(id)
	}
}

func (a *Adapter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/registrations/prepare", func(w http.ResponseWriter, r *http.Request) {
		var p iscpnodeissuer.RegistrationPreparation
		if read(r, &p) != nil {
			write(w, nil, invalid("decode_failed"))
			return
		}
		write(w, map[string]any{"state": "prepared"}, a.Prepare(r.Context(), p))
	})
	mux.HandleFunc("POST /v1/registrations/commit", func(w http.ResponseWriter, r *http.Request) {
		var p iscpnodeissuer.RegistrationCommit
		if read(r, &p) != nil {
			write(w, nil, invalid("decode_failed"))
			return
		}
		v, e := a.Commit(r.Context(), p)
		a.writeRegistrationReceipt(w, r, v, e)
	})
	mux.HandleFunc("POST /v1/registrations/status", func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			OperationID   string `json:"operation_id"`
			BindingDigest string `json:"binding_digest"`
		}
		if read(r, &p) != nil {
			write(w, nil, invalid("decode_failed"))
			return
		}
		v, e := a.Status(r.Context(), p.OperationID, p.BindingDigest)
		a.writeRegistrationReceipt(w, r, v, e)
	})
	mux.HandleFunc("POST /v1/registrations/revoke", func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			OperationID string `json:"operation_id"`
			DeviceID    string `json:"device_id"`
			Revision    uint64 `json:"revision"`
		}
		if read(r, &p) != nil {
			write(w, nil, invalid("decode_failed"))
			return
		}
		e := a.Revoke(r.Context(), p.OperationID, p.DeviceID, p.Revision)
		write(w, map[string]any{"state": "revoked", "operation_id": p.OperationID, "device_id": p.DeviceID, "revision": p.Revision}, e)
	})
	mux.HandleFunc("POST /v1/registrations/recover", func(w http.ResponseWriter, r *http.Request) {
		if a.controlEpoch != "" {
			write(w, nil, Error{"protocol_incompatible", http.StatusGone})
			return
		}
		var p iscpnodeissuer.RegistrationRecovery
		if read(r, &p) != nil {
			write(w, nil, invalid("decode_failed"))
			return
		}
		v, e := a.Recover(r.Context(), p)
		write(w, v, e)
	})
	mux.HandleFunc("POST /v1/service-peers/verify", func(w http.ResponseWriter, r *http.Request) {
		var p ServiceVerification
		if read(r, &p) != nil {
			write(w, nil, invalid("decode_failed"))
			return
		}
		e := a.VerifyServicePeer(r.Context(), p)
		write(w, map[string]string{"state": "active", "device_id": p.Identity.DeviceID}, e)
	})
	return a.bounded(mux)
}

// Registration remains a separate authenticated enrollment protocol. Its
// sealed response is disclosed under the same current authority guard as v2.
func (a *Adapter) writeRegistrationReceipt(w http.ResponseWriter, r *http.Request, receipt iscpnodeissuer.RegistrationReceipt, err error) {
	if err != nil || a.controlEpoch == "" {
		write(w, receipt, err)
		return
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		write(w, nil, unavailable())
		return
	}
	defer tx.Rollback(r.Context())
	if err = a.lockLifecycle(r.Context(), tx, receipt.DeviceID, "", false, false); err == nil {
		err = a.active(r.Context(), tx, receipt.DeviceID)
	}
	if err != nil {
		write(w, nil, err)
		return
	}
	controller := http.NewResponseController(w)
	// Production net/http supports deadlines; recorder-only writers may not.
	if err = controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		write(w, nil, unavailable())
		return
	}
	write(w, receipt, nil)
	_ = controller.Flush()
}

func read(r *http.Request, out any) error {
	raw, e := io.ReadAll(io.LimitReader(r.Body, (128<<10)+1))
	if e != nil {
		return e
	}
	return iscpnodeissuer.StrictDecode(raw, out)
}
func write(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		var typed Error
		if !errors.As(err, &typed) {
			typed = Error{"temporarily_unavailable", 503}
		}
		w.WriteHeader(typed.Status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"reason": typed.Reason, "temporary": typed.Status == 503}})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func lock(ctx context.Context, tx pgx.Tx, key string) error {
	_, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", key)
	return e
}
func canonical(v any) []byte { b, _ := iscpnodeissuer.Canonical(v); return b }
func (a *Adapter) receipt(ctx context.Context, tx pgx.Tx, op, digest, kind string) (iscpnodeissuer.RegistrationReceipt, bool, error) {
	var raw []byte
	var stored, storedKind string
	e := tx.QueryRow(ctx, "SELECT binding_digest,kind,response FROM iscp_relay.node_receipts WHERE operation_id=$1 AND authority_id=$2", op, a.authority).Scan(&stored, &storedKind, &raw)
	if e == pgx.ErrNoRows {
		return iscpnodeissuer.RegistrationReceipt{}, false, nil
	}
	if e != nil {
		return iscpnodeissuer.RegistrationReceipt{}, false, e
	}
	if digest != stored || kind != storedKind {
		return iscpnodeissuer.RegistrationReceipt{}, false, conflict("operation_binding_conflict")
	}
	var out iscpnodeissuer.RegistrationReceipt
	if json.Unmarshal(raw, &out) != nil {
		return out, false, unavailable()
	}
	if out.OperationID != op || out.BindingDigest != digest || out.DomainID != a.cfg.DomainID {
		return out, false, unavailable()
	}
	if e = a.owned(ctx, tx, out.DeviceID); e != nil {
		return out, false, e
	}
	return out, true, nil
}
func (a *Adapter) saveReceipt(ctx context.Context, tx pgx.Tx, kind string, r iscpnodeissuer.RegistrationReceipt) error {
	if err := a.owned(ctx, tx, r.DeviceID); err != nil {
		return err
	}
	raw, _ := json.Marshal(r)
	_, e := tx.Exec(ctx, "INSERT INTO iscp_relay.node_receipts(operation_id,binding_digest,kind,domain_id,device_id,response,created_at,authority_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", r.OperationID, r.BindingDigest, kind, r.DomainID, r.DeviceID, raw, a.now(), a.authority)
	return e
}

func (a *Adapter) Register(ctx context.Context, id identity.DeviceIdentity, proof identity.DeviceProof, ticket provisioning.PairingTicketV3) (json.RawMessage, error) {
	var raw []byte
	e := a.db.QueryRow(ctx, "SELECT preparation FROM iscp_relay.node_preparations WHERE ticket_id=$1 AND authority_id=$2", ticket.TicketID, a.authority).Scan(&raw)
	if e == pgx.ErrNoRows {
		return nil, denied("prepared_grant_required")
	}
	if e != nil {
		return nil, unavailable()
	}
	var p iscpnodeissuer.RegistrationPreparation
	if json.Unmarshal(raw, &p) != nil || iscpnodeissuer.Digest(id) != iscpnodeissuer.Digest(p.Identity) {
		return nil, denied("device_binding_conflict")
	}
	_, tokens, created, e := a.commit(ctx, iscpnodeissuer.RegistrationCommit{OperationID: p.OperationID, BindingDigest: p.BindingDigest, IdentityProof: proof, TicketV3: ticket})
	if e != nil {
		return nil, e
	}
	if !created {
		return nil, conflict("ticket_already_consumed")
	}
	return standardTokens(tokens), nil
}

const schema = `
CREATE TABLE IF NOT EXISTS iscp_relay.node_preparations (
 operation_id text PRIMARY KEY, binding_digest text NOT NULL, ticket_id text NOT NULL UNIQUE,
 domain_id text NOT NULL, device_id text NOT NULL, preparation bytea NOT NULL, expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS iscp_relay.node_ticket_uses (
 ticket_id text PRIMARY KEY, operation_id text NOT NULL UNIQUE, domain_id text NOT NULL, device_id text NOT NULL, used_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS iscp_relay.node_receipts (
 operation_id text PRIMARY KEY, binding_digest text NOT NULL, kind text NOT NULL,
 domain_id text NOT NULL, device_id text NOT NULL, response bytea NOT NULL, created_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS iscp_relay.node_grants (
 domain_id text NOT NULL, device_id text NOT NULL, revision bigint NOT NULL, grant_raw bytea NOT NULL, updated_at timestamptz NOT NULL, PRIMARY KEY(domain_id,device_id));
CREATE TABLE IF NOT EXISTS iscp_relay.node_revocations (
 domain_id text NOT NULL, device_id text NOT NULL, revision bigint NOT NULL, operation_id text NOT NULL, revoked_at timestamptz NOT NULL, PRIMARY KEY(domain_id,device_id));
CREATE UNIQUE INDEX IF NOT EXISTS node_revocations_operation ON iscp_relay.node_revocations(operation_id);
CREATE TABLE IF NOT EXISTS iscp_relay.node_service_proofs (
 domain_id text NOT NULL, device_id text NOT NULL, nonce text NOT NULL, binding_digest text NOT NULL, created_at timestamptz NOT NULL, PRIMARY KEY(domain_id,device_id,nonce));
`

func standardTokens(t iscpnodeissuer.RelayCredentials) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"access": map[string]any{"domain_id": t.Access.DomainID, "device_id": t.Access.DeviceID, "token": t.Access.Token, "expires_at": t.Access.ExpiresAt, "revoked": false}, "refresh": map[string]any{"domain_id": t.Refresh.DomainID, "device_id": t.Refresh.DeviceID, "token": t.Refresh.Token, "expires_at": t.Refresh.ExpiresAt, "revoked": false}})
	return raw
}
func requireOperation(op, digest string) error {
	if !operationPattern.MatchString(op) || len(digest) < 20 || len(digest) > 128 || strings.ContainsAny(digest, "\x00\r\n") {
		return invalid("operation_required")
	}
	return nil
}
