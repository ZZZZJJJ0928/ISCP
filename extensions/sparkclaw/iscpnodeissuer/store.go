package iscpnodeissuer

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"sync"
	"time"
)

// State is one encrypted aggregate, locked in PostgreSQL for every transition.
// Invitation binding and operation receipts therefore cannot race consumption.
type State struct {
	Control             *ControlState            `json:"control_v2,omitempty"`
	Credential          Credential               `json:"credential"`
	ClientName          string                   `json:"client_name"`
	State               string                   `json:"state"`
	Revision            uint64                   `json:"revision"`
	Device              *identity.DeviceIdentity `json:"device,omitempty"`
	BoundOperation      string                   `json:"bound_operation,omitempty"`
	Operations          map[string]*Operation    `json:"operations"`
	RevocationOperation string                   `json:"revocation_operation,omitempty"`
	RevokedAt           time.Time                `json:"revoked_at,omitempty"`
	RelayRevoked        bool                     `json:"relay_revoked"`
}

// ControlState is never inferred from a missing legacy record. New bindings
// create a fresh namespace; restore/import requires an explicit history gate.
type ControlState struct {
	ActivationEvidence string                     `json:"activation_evidence_sha256,omitempty"`
	HistoryID          string                     `json:"history_id"`
	HistoryComplete    bool                       `json:"history_complete"`
	Closed             bool                       `json:"closed"`
	Generation         control.Counter            `json:"credential_generation"`
	Records            map[string]*control.Record `json:"records"`
	Parents            map[string]*ControlParent  `json:"parents"`
}
type ControlParent struct {
	ChildAck         *control.Ack         `json:"child_ack,omitempty"`
	Grant            *trust.Grant         `json:"grant,omitempty"`
	ChildIntent      *control.Intent      `json:"child_intent,omitempty"`
	ChildResult      *control.Result      `json:"child_result,omitempty"`
	ChildDisposition *control.Disposition `json:"child_disposition,omitempty"`
	ChildIndex       control.Counter      `json:"child_index"`
}
type Operation struct {
	AppliedAt         time.Time                `json:"applied_at,omitempty"`
	CreatedAt         time.Time                `json:"created_at"`
	InstallationID    string                   `json:"installation_id,omitempty"`
	ID                string                   `json:"id"`
	State             string                   `json:"state"`
	InputDigest       string                   `json:"input_digest"`
	Hello             *ClientHello             `json:"hello,omitempty"`
	Server            *ServerHello             `json:"server,omitempty"`
	Channel           *Channel                 `json:"channel,omitempty"`
	RedeemDigest      string                   `json:"redeem_digest,omitempty"`
	Preparation       *RegistrationPreparation `json:"preparation,omitempty"`
	Commit            *RegistrationCommit      `json:"commit,omitempty"`
	WrapPrivate       []byte                   `json:"wrap_private,omitempty"`
	Receipt           *RegistrationReceipt     `json:"receipt,omitempty"`
	Result            *EnrollmentResult        `json:"result,omitempty"`
	ResultFrame       *SealedFrame             `json:"result_frame,omitempty"`
	LifecycleResponse *LifecycleResponse       `json:"lifecycle_response,omitempty"`
	Renew             *LifecycleRequest        `json:"renew,omitempty"`
	Grant             *trust.Grant             `json:"grant,omitempty"`
}
type Store interface {
	RequireControlWriter(context.Context) error
	Create(context.Context, string, *State) error
	Update(context.Context, string, func(*State) error) error
	Read(context.Context, string) (*State, error)
	List(context.Context) ([]*State, error)
	Close()
}

// PostgresStore keeps all private channel/secret/receipt material encrypted.
// A separate 32-byte protected storage key must accompany a paired DB backup.
type PostgresStore struct {
	writerEpoch string
	pool        *pgxpool.Pool
	key         []byte
}

func NewPostgresStore(ctx context.Context, dsn string, key []byte) (*PostgresStore, error) {
	if len(key) != 32 {
		return nil, ErrInvalid
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		return nil, ErrInvalid
	}
	cfg.MaxConns = 8
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		return nil, e
	}
	s := &PostgresStore{pool: pool, key: append([]byte{}, key...)}
	_, e = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS sparkclaw_iscp_issuer_state (id text PRIMARY KEY, ciphertext bytea NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(), CONSTRAINT bounded_id CHECK(length(id)<=200), CONSTRAINT bounded_ciphertext CHECK(octet_length(ciphertext)<=4194304))`)
	if e != nil {
		pool.Close()
		return nil, e
	}
	if _, e = pool.Exec(ctx, issuerWriterSchema); e != nil {
		pool.Close()
		return nil, e
	}
	return s, nil
}
func (s *PostgresStore) Close() { s.pool.Close() }
func (s *PostgresStore) seal(id string, v *State) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil || len(b) > 4<<20 {
		return nil, ErrInvalid
	}
	n := make([]byte, 12)
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	ct, e := c.NewProvider().Seal(s.key, n, b, []byte("sparkclaw/iscp-node/storage/v1\x00"+id))
	return append(n, ct...), e
}
func (s *PostgresStore) open(id string, b []byte) (*State, error) {
	if len(b) < 28 || len(b) > 4<<20 {
		return nil, ErrInvalid
	}
	raw, e := c.NewProvider().Open(s.key, b[:12], b[12:], []byte("sparkclaw/iscp-node/storage/v1\x00"+id))
	if e != nil {
		return nil, ErrDenied
	}
	var out State
	if e = json.Unmarshal(raw, &out); e != nil || out.Credential.InvitationID != id {
		return nil, ErrInvalid
	}
	return &out, nil
}
func (s *PostgresStore) Create(ctx context.Context, id string, v *State) error {
	b, e := s.seal(id, v)
	if e != nil {
		return e
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = s.lockWriter(ctx, tx); e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `INSERT INTO sparkclaw_iscp_issuer_state(id,ciphertext) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, b)
	if e != nil {
		return ErrUnavailable
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return tx.Commit(ctx)
}
func (s *PostgresStore) Read(ctx context.Context, id string) (*State, error) {
	var b []byte
	e := s.pool.QueryRow(ctx, `SELECT ciphertext FROM sparkclaw_iscp_issuer_state WHERE id=$1`, id).Scan(&b)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, ErrDenied
	}
	if e != nil {
		return nil, ErrUnavailable
	}
	return s.open(id, b)
}
func (s *PostgresStore) Update(ctx context.Context, id string, fn func(*State) error) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(ctx)
	if e = s.lockWriter(ctx, tx); e != nil {
		return e
	}
	var b []byte
	e = tx.QueryRow(ctx, `SELECT ciphertext FROM sparkclaw_iscp_issuer_state WHERE id=$1 FOR UPDATE`, id).Scan(&b)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrDenied
	}
	if e != nil {
		return ErrUnavailable
	}
	v, e := s.open(id, b)
	if e != nil {
		return e
	}
	if e = fn(v); e != nil {
		return e
	}
	b, e = s.seal(id, v)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE sparkclaw_iscp_issuer_state SET ciphertext=$2,updated_at=now() WHERE id=$1`, id, b); e != nil {
		return ErrUnavailable
	}
	if e = tx.Commit(ctx); e != nil {
		return ErrUnknownOutcome
	}
	return nil
}
func (s *PostgresStore) List(ctx context.Context) ([]*State, error) {
	rows, e := s.pool.Query(ctx, `SELECT id,ciphertext FROM sparkclaw_iscp_issuer_state ORDER BY id LIMIT 4097`)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	out := []*State{}
	for rows.Next() {
		var id string
		var b []byte
		if rows.Scan(&id, &b) != nil {
			return nil, ErrUnavailable
		}
		v, e := s.open(id, b)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
		if len(out) > 4096 {
			return nil, ErrUnavailable
		}
	}
	return out, rows.Err()
}

// MemoryStore is an in-process test adapter; production entrypoint never uses it.
type MemoryStore struct {
	mu   sync.Mutex
	rows map[string][]byte
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{rows: map[string][]byte{}} }
func (s *MemoryStore) Close()      {}

func (s *MemoryStore) RequireControlWriter(context.Context) error { return nil }
func (s *MemoryStore) Create(_ context.Context, id string, v *State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows[id] != nil {
		return ErrConflict
	}
	b, e := json.Marshal(v)
	if e == nil {
		s.rows[id] = b
	}
	return e
}
func (s *MemoryStore) Read(_ context.Context, id string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read(id)
}
func (s *MemoryStore) read(id string) (*State, error) {
	b := s.rows[id]
	if b == nil {
		return nil, ErrDenied
	}
	var v State
	e := json.Unmarshal(b, &v)
	return &v, e
}
func (s *MemoryStore) Update(_ context.Context, id string, fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, e := s.read(id)
	if e != nil {
		return e
	}
	if e = fn(v); e != nil {
		return e
	}
	b, e := json.Marshal(v)
	if e == nil {
		s.rows[id] = b
	}
	return e
}
func (s *MemoryStore) List(_ context.Context) ([]*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []*State{}
	for id := range s.rows {
		v, e := s.read(id)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
