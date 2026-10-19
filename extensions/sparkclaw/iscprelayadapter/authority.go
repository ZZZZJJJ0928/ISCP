package iscprelayadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"github.com/jackc/pgx/v5"
)

// An authority is fixed by its complete public trust roles, never a request
// header or a mutable display name. Adding operator-approved service peers does
// not change the existing authority's business ownership.
func authorityBinding(cfg Config) any {
	return struct {
		Domain     string                  `json:"domain_id"`
		Relay      string                  `json:"relay_id"`
		Invitation identity.DeviceIdentity `json:"invitation_signer"`
		Grant      identity.DeviceIdentity `json:"grant_signer"`
		Responder  identity.DeviceIdentity `json:"responder"`
	}{cfg.DomainID, cfg.RelayID, cfg.InvitationSigner, cfg.GrantSigner, cfg.Responder}
}
func authorityID(cfg Config) string { return node.Digest(authorityBinding(cfg)) }

func (a *Adapter) owned(ctx context.Context, tx pgx.Tx, device string) error {
	var owner string
	e := tx.QueryRow(ctx, "SELECT authority_id FROM iscp_relay.node_device_ownership WHERE domain_id=$1 AND device_id=$2", a.cfg.DomainID, device).Scan(&owner)
	if e == pgx.ErrNoRows || e == nil && owner != a.authority {
		return denied("device_not_owned")
	}
	if e != nil {
		return unavailable()
	}
	return nil
}

// OperatorBind is called only by the Relay's existing actor-authorized
// bind-self path after PoP verification. It does not authorize enrollment.
func (a *Adapter) OperatorBind(ctx context.Context, id identity.DeviceIdentity) error {
	if !a.servicePeer(id) {
		return nil
	}
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return unavailable()
	}
	defer tx.Rollback(ctx)
	if e = lock(ctx, tx, "device:"+id.DomainID+":"+id.DeviceID); e != nil {
		return unavailable()
	}
	var status string
	e = tx.QueryRow(ctx, "SELECT status FROM iscp_relay.devices WHERE domain_id=$1 AND device_id=$2", id.DomainID, id.DeviceID).Scan(&status)
	if e == nil && status != "active" {
		return denied("service_peer_revoked")
	}
	if e != nil && e != pgx.ErrNoRows {
		return unavailable()
	}
	if e = a.claim(ctx, tx, id, false); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (a *Adapter) claim(ctx context.Context, tx pgx.Tx, id identity.DeviceIdentity, historical bool) error {
	if node.ValidateIdentity(id) != nil || id.DomainID != a.cfg.DomainID {
		return denied("identity_invalid")
	}
	if lock(ctx, tx, "device:"+id.DomainID+":"+id.DeviceID) != nil {
		return unavailable()
	}
	var owner, thumb string
	e := tx.QueryRow(ctx, "SELECT authority_id,public_key_thumbprint FROM iscp_relay.node_device_ownership WHERE domain_id=$1 AND device_id=$2 FOR UPDATE", id.DomainID, id.DeviceID).Scan(&owner, &thumb)
	tp, _ := identity.Thumbprint(id)
	if e == nil {
		if owner != a.authority || thumb != tp {
			return denied("device_authority_conflict")
		}
		return nil
	}
	if e != pgx.ErrNoRows {
		return unavailable()
	}
	var raw []byte
	e = tx.QueryRow(ctx, "SELECT identity_raw FROM iscp_relay.devices WHERE domain_id=$1 AND device_id=$2 FOR UPDATE", id.DomainID, id.DeviceID).Scan(&raw)
	if e == nil {
		var stored identity.DeviceIdentity
		if json.Unmarshal(raw, &stored) != nil || node.Digest(stored) != node.Digest(id) {
			return denied("identity_key_conflict")
		}
		// Only the one-time cryptographically proved migration, or the explicit
		// operator service allowlist, can adopt a pre-existing unowned device.
		if !historical && !a.servicePeer(id) {
			return denied("existing_device_not_owned")
		}
	} else if e != pgx.ErrNoRows {
		return unavailable()
	}
	_, e = tx.Exec(ctx, "INSERT INTO iscp_relay.node_device_ownership(domain_id,device_id,authority_id,public_key_thumbprint,created_at) VALUES($1,$2,$3,$4,$5)", id.DomainID, id.DeviceID, a.authority, tp, a.now())
	if e != nil {
		return unavailable()
	}
	return nil
}

func (a *Adapter) claimService(ctx context.Context, tx pgx.Tx, id identity.DeviceIdentity) error {
	if !a.servicePeer(id) {
		return denied("service_peer_not_approved")
	}
	// Approval is not enrollment and never resurrects an operator-revoked peer.
	var raw []byte
	var status string
	e := tx.QueryRow(ctx, "SELECT identity_raw,status FROM iscp_relay.devices WHERE domain_id=$1 AND device_id=$2", id.DomainID, id.DeviceID).Scan(&raw, &status)
	if e == pgx.ErrNoRows {
		return denied("service_peer_not_enrolled")
	}
	if e != nil {
		return unavailable()
	}
	var stored identity.DeviceIdentity
	if status != "active" || json.Unmarshal(raw, &stored) != nil || node.Digest(stored) != node.Digest(id) {
		return denied("service_peer_not_active")
	}
	return a.claim(ctx, tx, id, false)
}

const scopeSchema = `
CREATE TABLE IF NOT EXISTS iscp_relay.node_authorities (
 authority_id text PRIMARY KEY, public_binding bytea NOT NULL, issuer_route text NOT NULL DEFAULT '');
CREATE UNIQUE INDEX IF NOT EXISTS node_authority_route ON iscp_relay.node_authorities(issuer_route) WHERE issuer_route<>'';
CREATE TABLE IF NOT EXISTS iscp_relay.node_device_ownership (
 domain_id text NOT NULL, device_id text NOT NULL, authority_id text NOT NULL REFERENCES iscp_relay.node_authorities(authority_id),
 public_key_thumbprint text NOT NULL, created_at timestamptz NOT NULL, PRIMARY KEY(domain_id,device_id));
CREATE TABLE IF NOT EXISTS iscp_relay.node_scope_migration (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), legacy_authority_id text NOT NULL);
`

var scopedTables = []string{"node_preparations", "node_ticket_uses", "node_receipts", "node_grants", "node_revocations", "node_service_proofs"}

func (a *Adapter) initialize(ctx context.Context, allowLegacy bool) error {
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = a.initializeTx(ctx, tx, allowLegacy); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (a *Adapter) initializeTx(ctx context.Context, tx pgx.Tx, allowLegacy bool) error {
	var e error
	if e = lock(ctx, tx, "sparkclaw-node-authority-schema-v2"); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, schema+scopeSchema); e != nil {
		return e
	}
	for _, table := range scopedTables {
		if _, e = tx.Exec(ctx, "ALTER TABLE iscp_relay."+table+" ADD COLUMN IF NOT EXISTS authority_id text"); e != nil {
			return e
		}
	}
	binding := canonical(authorityBinding(a.cfg))
	var stored []byte
	var route string
	e = tx.QueryRow(ctx, "SELECT public_binding,issuer_route FROM iscp_relay.node_authorities WHERE authority_id=$1", a.authority).Scan(&stored, &route)
	if e == nil {
		if !bytes.Equal(binding, stored) || a.cfg.issuerRoute != "" && route != "" && route != a.cfg.issuerRoute {
			return denied("authority_binding_conflict")
		}
		if route == "" && a.cfg.issuerRoute != "" {
			if _, e = tx.Exec(ctx, "UPDATE iscp_relay.node_authorities SET issuer_route=$2 WHERE authority_id=$1", a.authority, a.cfg.issuerRoute); e != nil {
				return e
			}
		}
	} else if e == pgx.ErrNoRows {
		if _, e = tx.Exec(ctx, "INSERT INTO iscp_relay.node_authorities(authority_id,public_binding,issuer_route) VALUES($1,$2,$3)", a.authority, binding, a.cfg.issuerRoute); e != nil {
			return e
		}
	} else {
		return e
	}
	var legacyRows int64
	for _, table := range scopedTables {
		var n int64
		if e = tx.QueryRow(ctx, "SELECT count(*) FROM iscp_relay."+table+" WHERE authority_id IS NULL").Scan(&n); e != nil {
			return e
		}
		legacyRows += n
	}
	var migrated bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM iscp_relay.node_scope_migration)").Scan(&migrated); e != nil {
		return e
	}
	if migrated && allowLegacy {
		var legacyID string
		if e = tx.QueryRow(ctx, "SELECT legacy_authority_id FROM iscp_relay.node_scope_migration").Scan(&legacyID); e != nil {
			return e
		}
		if legacyID != "" && legacyID != a.authority {
			return denied("legacy_authority_binding_conflict")
		}
	}
	if legacyRows > 0 {
		if !allowLegacy || migrated {
			return denied("explicit_legacy_authority_required")
		}
		if e = a.backfillLegacy(ctx, tx); e != nil {
			return e
		}
	}
	if !migrated {
		legacyID := ""
		if legacyRows > 0 {
			legacyID = a.authority
		}
		if _, e = tx.Exec(ctx, "INSERT INTO iscp_relay.node_scope_migration(singleton,legacy_authority_id) VALUES(true,$1)", legacyID); e != nil {
			return e
		}
	}
	for _, table := range scopedTables {
		if _, e = tx.Exec(ctx, "ALTER TABLE iscp_relay."+table+" ALTER COLUMN authority_id SET NOT NULL"); e != nil {
			return e
		}
	}
	// Device identity is already globally unique in ISCP's domain. Operations and
	// receipts, in contrast, belong to their private authority and can share IDs.
	for _, table := range []string{"node_preparations", "node_ticket_uses", "node_receipts"} {
		var scoped bool
		if e = tx.QueryRow(ctx, "SELECT position('authority_id' in pg_get_constraintdef(oid))>0 FROM pg_constraint WHERE conrelid=$1::regclass AND contype='p'", "iscp_relay."+table).Scan(&scoped); e != nil {
			return e
		}
		if !scoped {
			key := "operation_id"
			if table == "node_ticket_uses" {
				key = "ticket_id"
			}
			if _, e = tx.Exec(ctx, "ALTER TABLE iscp_relay."+table+" DROP CONSTRAINT "+table+"_pkey, ADD PRIMARY KEY(authority_id,"+key+")"); e != nil {
				return e
			}
		}
	}
	if _, e = tx.Exec(ctx, `ALTER TABLE iscp_relay.node_preparations DROP CONSTRAINT IF EXISTS node_preparations_ticket_id_key;
ALTER TABLE iscp_relay.node_ticket_uses DROP CONSTRAINT IF EXISTS node_ticket_uses_operation_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS node_preparation_ticket_scope ON iscp_relay.node_preparations(authority_id,ticket_id);
CREATE UNIQUE INDEX IF NOT EXISTS node_ticket_operation_scope ON iscp_relay.node_ticket_uses(authority_id,operation_id);
DROP INDEX IF EXISTS iscp_relay.node_revocations_operation;
CREATE UNIQUE INDEX node_revocations_operation ON iscp_relay.node_revocations(authority_id,operation_id);`); e != nil {
		return e
	}
	for _, id := range a.cfg.ServicePeers {
		var exists bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM iscp_relay.devices WHERE domain_id=$1 AND device_id=$2)", id.DomainID, id.DeviceID).Scan(&exists); e != nil {
			return e
		}
		if exists {
			if e = a.claim(ctx, tx, id, false); e != nil {
				return e
			}
		}
	}
	return nil
}

func (a *Adapter) backfillLegacy(ctx context.Context, tx pgx.Tx) error {
	// Prove every managed historical subject with its original signed preparation
	// or Grant. Unmanaged operator test devices stay unowned and unchanged.
	ids := map[string]identity.DeviceIdentity{}
	add := func(id identity.DeviceIdentity) error {
		if prior, ok := ids[id.DeviceID]; ok && node.Digest(prior) != node.Digest(id) {
			return denied("legacy_identity_conflict")
		}
		ids[id.DeviceID] = id
		return nil
	}
	rows, e := tx.Query(ctx, "SELECT preparation FROM iscp_relay.node_preparations WHERE authority_id IS NULL")
	if e != nil {
		return e
	}
	preparations := [][]byte{}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			rows.Close()
			return e
		}
		preparations = append(preparations, raw)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, raw := range preparations {
		var p node.RegistrationPreparation
		if node.StrictDecode(raw, &p) != nil {
			return denied("legacy_preparation_invalid")
		}
		at := p.TicketV3.IssuedAt
		if p.Grant.NotBefore.After(at) {
			at = p.Grant.NotBefore
		}
		at = at.Add(time.Nanosecond)
		historical := Adapter{cfg: a.cfg, authority: a.authority, Now: func() time.Time { return at }}
		if e = historical.validatePreparation(p); e != nil {
			return denied("legacy_authority_mismatch")
		}
		if e = add(p.Identity); e != nil {
			return e
		}
	}
	rows, e = tx.Query(ctx, "SELECT device_id,grant_raw FROM iscp_relay.node_grants WHERE authority_id IS NULL")
	if e != nil {
		return e
	}
	type oldGrant struct {
		device string
		raw    []byte
	}
	grants := []oldGrant{}
	for rows.Next() {
		var g oldGrant
		if e = rows.Scan(&g.device, &g.raw); e != nil {
			rows.Close()
			return e
		}
		grants = append(grants, g)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, old := range grants {
		var id identity.DeviceIdentity
		var raw []byte
		var g trust.Grant
		if tx.QueryRow(ctx, "SELECT identity_raw FROM iscp_relay.devices WHERE domain_id=$1 AND device_id=$2", a.cfg.DomainID, old.device).Scan(&raw) != nil || json.Unmarshal(raw, &id) != nil || node.StrictDecode(old.raw, &g) != nil || len(g.Permissions) != 1 {
			return denied("legacy_grant_invalid")
		}
		permission := g.Permissions[0]
		audience := a.cfg.Responder.DeviceID
		if permission != node.Permission {
			if !a.servicePeer(id) || permission != "relay.recovery" && permission != "sparkclaw.issuer.control.v1" {
				return denied("legacy_service_grant_invalid")
			}
			audience = g.Audience
			approved := audience == id.DeviceID
			for _, p := range a.cfg.ServicePeers {
				approved = approved || p.DeviceID == audience
			}
			if !approved {
				return denied("legacy_service_audience_invalid")
			}
		}
		historical := Adapter{cfg: a.cfg, authority: a.authority, Now: func() time.Time { return g.NotBefore.Add(time.Nanosecond) }}
		if e = historical.validateGrant(id, g, permission, audience); e != nil {
			return denied("legacy_authority_mismatch")
		}
		if e = add(id); e != nil {
			return e
		}
	}
	for _, id := range a.cfg.ServicePeers {
		var raw []byte
		e = tx.QueryRow(ctx, "SELECT identity_raw FROM iscp_relay.devices WHERE domain_id=$1 AND device_id=$2", id.DomainID, id.DeviceID).Scan(&raw)
		if e == pgx.ErrNoRows {
			continue
		}
		if e != nil {
			return e
		}
		var stored identity.DeviceIdentity
		if json.Unmarshal(raw, &stored) != nil || node.Digest(id) != node.Digest(stored) {
			return denied("legacy_service_key_conflict")
		}
		if e = add(id); e != nil {
			return e
		}
	}
	// Every managed row must have a proved owner. This does not scan or adopt the
	// unrelated transport devices table, and can never be used as a future fallback.
	for _, table := range scopedTables {
		rows, e = tx.Query(ctx, "SELECT domain_id,device_id FROM iscp_relay."+table+" WHERE authority_id IS NULL")
		if e != nil {
			return e
		}
		for rows.Next() {
			var domain, dev string
			if e = rows.Scan(&domain, &dev); e != nil {
				rows.Close()
				return e
			}
			if domain != a.cfg.DomainID || ids[dev].DeviceID == "" {
				rows.Close()
				return denied("legacy_owner_unproved")
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
	}
	for _, id := range ids {
		if e = a.claim(ctx, tx, id, true); e != nil {
			return e
		}
	}
	for _, table := range scopedTables {
		if _, e = tx.Exec(ctx, "UPDATE iscp_relay."+table+" SET authority_id=$1 WHERE authority_id IS NULL", a.authority); e != nil {
			return e
		}
	}
	return nil
}

func (a *Adapter) bounded(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
