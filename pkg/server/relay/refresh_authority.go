package iscprelayreference

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"github.com/Infinimesh-ai/ISCP/pkg/server/httpx"
	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
)

// refreshDuplexCredentials handles only the existing unmanaged HTTP refresh
// path after explicit authority activation. Managed control has its own ledger.
// Legacy NULL generations never authorize a rotation or data connection.
func (s *Server) refreshDuplexCredentials(w http.ResponseWriter, r *http.Request, token string) bool {
	if s.cfg.DB == nil {
		return false
	}
	var active bool
	if err := s.cfg.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM iscp_relay.domain_authority WHERE scope_id=$1 AND domain_id=$2)`, s.cfg.RelayID, s.cfg.DomainID).Scan(&active); err != nil {
		httpx.WriteError(w, 503, err)
		return true
	}
	if !active {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := s.cfg.DB.Begin(ctx)
	if err != nil {
		httpx.WriteError(w, 503, err)
		return true
	}
	defer tx.Rollback(context.Background())
	hash := crypto.SHA256([]byte(token))
	var device string
	if err = tx.QueryRow(ctx, `SELECT device_id FROM iscp_relay.refresh_tokens WHERE domain_id=$1 AND refresh_hash=$2`, s.cfg.DomainID, hash).Scan(&device); err != nil {
		httpx.WriteError(w, 401, errors.New("refresh credential invalid"))
		return true
	}
	snap, err := authority.Lock(ctx, tx, authority.Request{ScopeID: s.cfg.RelayID, DomainID: s.cfg.DomainID, ExpectedWriterEpoch: s.writerEpoch, Devices: []authority.DeviceLock{{ID: device, Exclusive: true}}, Owners: []authority.DeviceLock{{ID: device, Exclusive: true}}})
	if err != nil {
		httpx.WriteError(w, 401, errors.New("refresh authority unavailable"))
		return true
	}
	current := snap.Devices[device].CredentialGeneration
	var generation *string
	var status string
	err = tx.QueryRow(ctx, `SELECT t.credential_generation::text,d.status FROM iscp_relay.refresh_tokens t JOIN iscp_relay.devices d USING(domain_id,device_id) WHERE t.domain_id=$1 AND t.device_id=$2 AND t.refresh_hash=$3 AND t.revoked_at IS NULL AND t.expires_at>now()`, s.cfg.DomainID, device, hash).Scan(&generation, &status)
	if err != nil || generation == nil || *generation != current || status != "active" {
		httpx.WriteError(w, 401, errors.New("refresh credential invalid"))
		return true
	}
	next, err := duplex.Next(current)
	if err != nil {
		httpx.WriteError(w, 503, err)
		return true
	}
	now := time.Now().UTC()
	accessToken, refreshToken := randomToken(), randomToken()
	access := credential{DomainID: s.cfg.DomainID, DeviceID: device, Token: accessToken, Hash: crypto.SHA256([]byte(accessToken)), ExpiresAt: now.Add(15 * time.Minute)}
	refresh := credential{DomainID: s.cfg.DomainID, DeviceID: device, Token: refreshToken, Hash: crypto.SHA256([]byte(refreshToken)), ExpiresAt: now.Add(24 * time.Hour)}
	repo := repository.NewRelayRepository(tx)
	if err = repo.RevokeDeviceCredentials(ctx, repository.DomainID(s.cfg.DomainID), device, now); err != nil {
		httpx.WriteError(w, 503, err)
		return true
	}
	for _, value := range []struct {
		table, column string
		credential    credential
	}{{"access_tokens", "token_hash", access}, {"refresh_tokens", "refresh_hash", refresh}} {
		id, e := postgres.NewUUIDv7Like(now)
		if e != nil {
			httpx.WriteError(w, 503, e)
			return true
		}
		_, e = tx.Exec(ctx, "INSERT INTO iscp_relay."+value.table+"(id,domain_id,device_id,"+value.column+",issued_at,expires_at,credential_generation) VALUES($1,$2,$3,$4,$5,$6,$7)", postgres.UUIDString(id), s.cfg.DomainID, device, value.credential.Hash, now, value.credential.ExpiresAt, next)
		if e != nil {
			httpx.WriteError(w, 503, e)
			return true
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE iscp_relay.device_authority SET credential_generation=$4,state_version=state_version+1 WHERE scope_id=$1 AND domain_id=$2 AND device_id=$3 AND credential_generation=$5 AND state='active'`, s.cfg.RelayID, s.cfg.DomainID, device, next, current)
	if err != nil || tag.RowsAffected() != 1 {
		httpx.WriteError(w, 503, errors.New("credential generation changed"))
		return true
	}
	if err = tx.Commit(ctx); err != nil {
		httpx.WriteError(w, 503, errors.New("credential rotation outcome unknown"))
		return true
	}
	// Never cache unversioned authority after activation; every HTTP lookup falls
	// back to the committed database. Do not resurrect memory after a revoke race.
	s.mu.Lock()
	for key, c := range s.access {
		if c.DeviceID == device {
			delete(s.access, key)
		}
	}
	for key, c := range s.refresh {
		if c.DeviceID == device {
			delete(s.refresh, key)
		}
	}
	s.mu.Unlock()
	disclosure, err := s.cfg.DB.Begin(ctx)
	if err != nil {
		httpx.WriteError(w, 503, err)
		return true
	}
	defer disclosure.Rollback(context.Background())
	latest, err := authority.Lock(ctx, disclosure, authority.Request{ScopeID: s.cfg.RelayID, DomainID: s.cfg.DomainID, ExpectedWriterEpoch: s.writerEpoch, Devices: []authority.DeviceLock{{ID: device}}, Owners: []authority.DeviceLock{{ID: device}}})
	if err != nil || latest.Devices[device].CredentialGeneration != next {
		httpx.WriteError(w, 401, errors.New("credential disclosure authority changed"))
		return true
	}
	var valid bool
	err = disclosure.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iscp_relay.access_tokens WHERE domain_id=$1 AND device_id=$2 AND token_hash=$3 AND credential_generation=$5 AND revoked_at IS NULL AND expires_at>now()) AND EXISTS(SELECT 1 FROM iscp_relay.refresh_tokens WHERE domain_id=$1 AND device_id=$2 AND refresh_hash=$4 AND credential_generation=$5 AND revoked_at IS NULL AND expires_at>now())`, s.cfg.DomainID, device, access.Hash, refresh.Hash, next).Scan(&valid)
	if err != nil || !valid {
		httpx.WriteError(w, 401, errors.New("credential disclosure unavailable"))
		return true
	}
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Now().Add(5 * time.Second))
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"access": access, "refresh": refresh})
	_ = controller.Flush()
	return true
}
