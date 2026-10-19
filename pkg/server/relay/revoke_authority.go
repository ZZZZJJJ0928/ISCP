package iscprelayreference

import (
	"context"
	"errors"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
	"time"
)

// Operator and self revocation use the same authority rows as control rotation
// and every admitted/disclosed frame. No in-memory revocation precedes COMMIT.
func (s *Server) revokePersistentDevice(ctx context.Context, device, token string, admin bool) error {
	tx, err := s.cfg.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	var activated bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iscp_relay.writer_scopes WHERE scope_id=$1)`, s.cfg.RelayID).Scan(&activated); err != nil {
		return err
	}
	if activated {
		snapshot, err := authority.Lock(ctx, tx, authority.Request{ScopeID: s.cfg.RelayID, DomainID: s.cfg.DomainID, ExpectedWriterEpoch: s.writerEpoch, Devices: []authority.DeviceLock{{ID: device, Exclusive: true}}, Owners: []authority.DeviceLock{{ID: device, Exclusive: true}}, AllowInactiveDevices: true})
		if err != nil {
			return err
		}
		state := snapshot.Devices[device]
		if !admin {
			var generation string
			if err = tx.QueryRow(ctx, `SELECT credential_generation::text FROM iscp_relay.access_tokens WHERE domain_id=$1 AND device_id=$2 AND token_hash=$3 AND revoked_at IS NULL AND expires_at>now()`, s.cfg.DomainID, device, crypto.SHA256([]byte(token))).Scan(&generation); err != nil || generation != state.CredentialGeneration {
				return errors.New("revocation authority changed")
			}
		}
		if state.State != "revoked" {
			if _, err = tx.Exec(ctx, `UPDATE iscp_relay.device_authority SET state='revoked',authorization_revision=authorization_revision+1,state_version=state_version+1 WHERE scope_id=$1 AND domain_id=$2 AND device_id=$3`, s.cfg.RelayID, s.cfg.DomainID, device); err != nil {
				return err
			}
		}
	}
	repo := repository.NewRelayRepository(tx)
	now := time.Now().UTC()
	if err = repo.RevokeDevice(ctx, repository.DomainID(s.cfg.DomainID), device, now); err != nil {
		return err
	}
	if err = repo.RevokeDeviceCredentials(ctx, repository.DomainID(s.cfg.DomainID), device, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
