// Package authority supplies the common database fence for Relay data and
// credential control. Callers retain its transaction until commit/rollback;
// no network operation may occur inside this cross-service transaction.
package authority

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrUnavailable        = errors.New("authority unavailable")
	ErrWriterFenced       = errors.New("writer fenced")
	ErrHistoryUnavailable = errors.New("history unavailable")
	ErrRevoked            = errors.New("authority revoked or closing")
)

type DeviceLock struct {
	ID        string
	Exclusive bool
}
type Key struct{ Namespace, ID string }
type Request struct {
	ScopeID, DomainID, ExpectedWriterEpoch string
	Devices                                []DeviceLock
	Owners                                 []DeviceLock
	Keys                                   []Key
	RequireContinuousHistory               bool
	// AllowInactiveDevices is for authenticated revocation reconciliation only;
	// it never grants admission or disclosure permission.
	AllowInactiveDevices bool
}
type DeviceState struct{ CredentialGeneration, AuthorizationRevision, StateVersion, State string }
type OwnerState struct {
	Generation, ConnectionID, CredentialGeneration, AuthorizationRevision string
	ExpiresAt                                                             time.Time
}
type Snapshot struct {
	WriterEpoch, HistoryID, HistoryState string
	Devices                              map[string]DeviceState
	Owners                               map[string]OwnerState
}

// Lock acquires scope -> domain -> sorted devices -> sorted owners -> sorted
// (namespace,id) keys. Authority readers use SHARE; transitions use UPDATE on
// the SAME rows. Missing rows fail closed: ordinary traffic cannot create its
// own authority, history, owner or writer epoch.
func Lock(ctx context.Context, tx pgx.Tx, r Request) (Snapshot, error) {
	s := Snapshot{Devices: map[string]DeviceState{}, Owners: map[string]OwnerState{}}
	if !validID(r.ScopeID) || !validID(r.DomainID) || !validCounter(r.ExpectedWriterEpoch, false) {
		return s, ErrUnavailable
	}
	var role string
	var enabled bool
	var format int
	e := tx.QueryRow(ctx, `SELECT writer_epoch::text,writer_role::text,writes_enabled,writer_format FROM iscp_relay.writer_scopes WHERE scope_id=$1 FOR SHARE`, r.ScopeID).Scan(&s.WriterEpoch, &role, &enabled, &format)
	if e != nil {
		return s, fmt.Errorf("%w: scope: %v", ErrUnavailable, e)
	}
	var caller string
	if e = tx.QueryRow(ctx, `SELECT current_user`).Scan(&caller); e != nil {
		return s, e
	}
	if !enabled || format != 1 || s.WriterEpoch != r.ExpectedWriterEpoch || role != caller {
		return s, ErrWriterFenced
	}
	var history *string
	if e = tx.QueryRow(ctx, `SELECT history_id,history_state FROM iscp_relay.domain_authority WHERE scope_id=$1 AND domain_id=$2 FOR SHARE`, r.ScopeID, r.DomainID).Scan(&history, &s.HistoryState); e != nil {
		return s, fmt.Errorf("%w: domain: %v", ErrUnavailable, e)
	}
	if history != nil {
		s.HistoryID = *history
	}
	if s.HistoryState == "closed" || r.RequireContinuousHistory && s.HistoryState != "continuous" {
		return s, ErrHistoryUnavailable
	}
	devices, e := sortedLocks(r.Devices)
	if e != nil {
		return s, e
	}
	for _, d := range devices {
		q := `SELECT credential_generation::text,authorization_revision::text,state_version::text,state FROM iscp_relay.device_authority WHERE scope_id=$1 AND domain_id=$2 AND device_id=$3 FOR SHARE`
		if d.Exclusive {
			q = strings.TrimSuffix(q, "SHARE") + "UPDATE"
		}
		var state DeviceState
		if e = tx.QueryRow(ctx, q, r.ScopeID, r.DomainID, d.ID).Scan(&state.CredentialGeneration, &state.AuthorizationRevision, &state.StateVersion, &state.State); e != nil {
			return s, fmt.Errorf("%w: device: %v", ErrUnavailable, e)
		}
		if state.State != "active" && !r.AllowInactiveDevices {
			return s, ErrRevoked
		}
		s.Devices[d.ID] = state
	}
	owners, e := sortedLocks(r.Owners)
	if e != nil {
		return s, e
	}
	for _, d := range owners {
		if _, ok := s.Devices[d.ID]; !ok {
			return s, fmt.Errorf("owner requires device lock")
		}
		q := `SELECT owner_generation::text,connection_id,authority_expires_at,credential_generation::text,authorization_revision::text FROM iscp_relay.connection_owners WHERE scope_id=$1 AND domain_id=$2 AND device_id=$3 FOR SHARE`
		if d.Exclusive {
			q = strings.TrimSuffix(q, "SHARE") + "UPDATE"
		}
		var o OwnerState
		var conn, gen, rev *string
		var expiry *time.Time
		if e = tx.QueryRow(ctx, q, r.ScopeID, r.DomainID, d.ID).Scan(&o.Generation, &conn, &expiry, &gen, &rev); e != nil {
			return s, fmt.Errorf("%w: owner: %v", ErrUnavailable, e)
		}
		if conn != nil {
			o.ConnectionID = *conn
		}
		if gen != nil {
			o.CredentialGeneration = *gen
		}
		if rev != nil {
			o.AuthorizationRevision = *rev
		}
		if expiry != nil {
			o.ExpiresAt = *expiry
		}
		s.Owners[d.ID] = o
	}
	keys := append([]Key(nil), r.Keys...)
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Namespace == keys[j].Namespace {
			return keys[i].ID < keys[j].ID
		}
		return keys[i].Namespace < keys[j].Namespace
	})
	for i, k := range keys {
		if !validID(k.Namespace) || !validID(k.ID) {
			return s, ErrUnavailable
		}
		if i > 0 && k == keys[i-1] {
			continue
		}
		name := fmt.Sprintf("iscp-authority-v1:%d:%s:%d:%s:%d:%s:%s", len(r.ScopeID), r.ScopeID, len(r.DomainID), r.DomainID, len(k.Namespace), k.Namespace, k.ID)
		if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, name); e != nil {
			return s, e
		}
	}
	// Database triggers also check the epoch/role for every protected write.
	// Transaction-local settings cannot leak into the next pooled borrower.
	if _, e = tx.Exec(ctx, `SELECT set_config('iscp.writer_scope',$1,true),set_config('iscp.writer_epoch',$2,true),set_config('iscp.writer_format','1',true)`, r.ScopeID, s.WriterEpoch); e != nil {
		return s, e
	}
	return s, nil
}
func sortedLocks(input []DeviceLock) ([]DeviceLock, error) {
	byID := map[string]bool{}
	for _, x := range input {
		if !validID(x.ID) {
			return nil, ErrUnavailable
		}
		byID[x.ID] = byID[x.ID] || x.Exclusive
	}
	out := make([]DeviceLock, 0, len(byID))
	for id, exclusive := range byID {
		out = append(out, DeviceLock{id, exclusive})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func validID(s string) bool { return s != "" && len(s) <= 256 && !strings.ContainsRune(s, 0) }
func validCounter(s string, zero bool) bool {
	if s == "0" {
		return zero
	}
	if s == "" || s[0] == '0' {
		return false
	}
	_, e := strconv.ParseUint(s, 10, 64)
	return e == nil
}

// ReadEpoch is a startup snapshot only. Lock rechecks it on every transaction.
func ReadEpoch(ctx context.Context, tx pgx.Tx, scope string) (string, error) {
	var epoch string
	e := tx.QueryRow(ctx, `SELECT writer_epoch::text FROM iscp_relay.writer_scopes WHERE scope_id=$1`, scope).Scan(&epoch)
	return epoch, e
}
