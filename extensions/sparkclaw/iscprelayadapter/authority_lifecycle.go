package iscprelayadapter

import (
	"context"
	"fmt"
	"strconv"

	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"github.com/jackc/pgx/v5"
)

// A running legacy adapter must never discover and adopt an activated writer's
// epoch. EnableControlV2 supplies the immutable startup snapshot. Before an
// explicit cutover, databases without a writer scope keep their legacy behavior.
func (a *Adapter) lifecycleActivated(ctx context.Context, tx pgx.Tx) (bool, error) {
	if a.controlEpoch != "" {
		return true, nil
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iscp_relay.writer_scopes WHERE scope_id=$1)`, a.cfg.RelayID).Scan(&exists); err != nil {
		return false, unavailable()
	}
	if exists {
		return false, unavailable()
	}
	return false, nil
}
func (a *Adapter) lifecycleRequest(dev, op string, exclusive, inactive bool) authority.Request {
	r := authority.Request{ScopeID: a.cfg.RelayID, DomainID: a.cfg.DomainID, ExpectedWriterEpoch: a.controlEpoch, AllowInactiveDevices: inactive}
	if dev != "" {
		r.Devices = []authority.DeviceLock{{ID: dev, Exclusive: exclusive}}
	}
	if op != "" {
		r.Keys = []authority.Key{{Namespace: "node-lifecycle:" + a.authority, ID: op}}
	}
	return r
}
func lifecycleError(err error) error {
	if err == authority.ErrRevoked {
		return denied("device_revoked")
	}
	return unavailable()
}
func (a *Adapter) lockLifecycle(ctx context.Context, tx pgx.Tx, dev, op string, exclusive, inactive bool) error {
	enabled, err := a.lifecycleActivated(ctx, tx)
	if err != nil {
		return err
	}
	if enabled {
		_, err = authority.Lock(ctx, tx, a.lifecycleRequest(dev, op, exclusive, inactive))
		if err != nil {
			return lifecycleError(err)
		}
		return nil
	}
	// The pre-cutover path uses the same device-before-operation ordering.
	if dev != "" {
		if err = lock(ctx, tx, "device:"+a.cfg.DomainID+":"+dev); err != nil {
			return unavailable()
		}
	}
	if op != "" {
		if err = lock(ctx, tx, "operation:"+a.authority+":"+op); err != nil {
			return unavailable()
		}
	}
	return nil
}

// Preparation may reserve ownership, but cannot enroll an active device. The
// creation guard is the same device-layer guard used by RegisterDevice. Only a
// verified enrollment/PoP caller supplies a revision to create an authority row.
func (a *Adapter) lockEnrollment(ctx context.Context, tx pgx.Tx, dev, op, revision string) error {
	enabled, err := a.lifecycleActivated(ctx, tx)
	if err != nil {
		return err
	}
	if !enabled {
		return a.lockLifecycle(ctx, tx, dev, op, true, false)
	}
	base := a.lifecycleRequest("", "", false, false)
	if _, err = authority.Lock(ctx, tx, base); err != nil {
		return lifecycleError(err)
	}
	key := fmt.Sprintf("iscp-authority-device-create-v1:%d:%s:%d:%s:%s", len(base.ScopeID), base.ScopeID, len(base.DomainID), base.DomainID, dev)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key); err != nil {
		return unavailable()
	}
	if revision != "" {
		if err = authority.RegisterDevice(ctx, tx, base, dev, revision); err != nil {
			return lifecycleError(err)
		}
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iscp_relay.device_authority WHERE scope_id=$1 AND domain_id=$2 AND device_id=$3)`, a.cfg.RelayID, a.cfg.DomainID, dev).Scan(&exists); err != nil {
		return unavailable()
	}
	if !exists {
		dev = ""
	}
	_, err = authority.Lock(ctx, tx, a.lifecycleRequest(dev, op, true, false))
	if err != nil {
		return lifecycleError(err)
	}
	return nil
}

// Callers hold the exclusive device authority row for the whole transaction.
// Control v2 has its own explicit CAS and uses issueGeneration directly.
func (a *Adapter) issueLifecycle(ctx context.Context, tx pgx.Tx, dev string, rotate bool) (node.RelayCredentials, error) {
	if a.controlEpoch == "" {
		return a.issue(ctx, tx, dev)
	}
	var generation string
	if rotate {
		err := tx.QueryRow(ctx, `UPDATE iscp_relay.device_authority SET credential_generation=credential_generation+1,state_version=state_version+1 WHERE scope_id=$1 AND domain_id=$2 AND device_id=$3 AND state='active' AND credential_generation<18446744073709551615 AND state_version<18446744073709551615 RETURNING credential_generation::text`, a.cfg.RelayID, a.cfg.DomainID, dev).Scan(&generation)
		if err != nil {
			return node.RelayCredentials{}, unavailable()
		}
	} else if err := tx.QueryRow(ctx, `SELECT credential_generation::text FROM iscp_relay.device_authority WHERE scope_id=$1 AND domain_id=$2 AND device_id=$3 AND state='active'`, a.cfg.RelayID, a.cfg.DomainID, dev).Scan(&generation); err != nil {
		return node.RelayCredentials{}, unavailable()
	}
	return a.issueGeneration(ctx, tx, dev, generation)
}
func (a *Adapter) syncGrantRevision(ctx context.Context, tx pgx.Tx, dev string, revision uint64) error {
	if a.controlEpoch == "" {
		return nil
	}
	tag, err := tx.Exec(ctx, `UPDATE iscp_relay.device_authority SET authorization_revision=$4,state_version=state_version+CASE WHEN authorization_revision<$4 THEN 1 ELSE 0 END WHERE scope_id=$1 AND domain_id=$2 AND device_id=$3 AND state='active' AND authorization_revision<=$4 AND (authorization_revision=$4 OR state_version<18446744073709551615)`, a.cfg.RelayID, a.cfg.DomainID, dev, strconv.FormatUint(revision, 10))
	if err != nil {
		return unavailable()
	}
	if tag.RowsAffected() != 1 {
		return denied("stale_authorization_revision")
	}
	return nil
}
func (a *Adapter) revokeAuthority(ctx context.Context, tx pgx.Tx, dev string, revision uint64) error {
	if a.controlEpoch == "" {
		return nil
	}
	tag, err := tx.Exec(ctx, `UPDATE iscp_relay.device_authority SET authorization_revision=$4,state='revoked',state_version=state_version+1 WHERE scope_id=$1 AND domain_id=$2 AND device_id=$3 AND authorization_revision<$4 AND state_version<18446744073709551615`, a.cfg.RelayID, a.cfg.DomainID, dev, strconv.FormatUint(revision, 10))
	if err != nil {
		return unavailable()
	}
	if tag.RowsAffected() != 1 {
		return conflict("revocation_revision_conflict")
	}
	return nil
}
