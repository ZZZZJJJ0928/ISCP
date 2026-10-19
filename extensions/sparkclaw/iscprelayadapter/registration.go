package iscprelayadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
	"github.com/jackc/pgx/v5"
)

func (a *Adapter) validatePreparation(p node.RegistrationPreparation) error {
	if requireOperation(p.OperationID, p.BindingDigest) != nil || p.InvitationID == "" || node.ValidateIdentity(p.Identity) != nil || p.Identity.DomainID != a.cfg.DomainID || len(p.Binding.OwnerID) == 0 || len(p.Binding.ClientID) == 0 || len(p.Binding.DeploymentID) == 0 {
		return invalid("invalid_preparation")
	}
	w := p
	w.BindingDigest = ""
	if node.Digest(w) != p.BindingDigest {
		return conflict("preparation_digest_conflict")
	}
	wrap, e := c.DecodeBase64URL(p.ReceiptWrapPublicKey)
	if e != nil || len(wrap) != 32 {
		return invalid("invalid_wrap_key")
	}
	t := p.TicketV3
	if provisioning.VerifyTicketV3(c.NewProvider(), t, a.cfg.InvitationSigner, a.now()) != nil || t.DomainID != a.cfg.DomainID || t.RelayID != a.cfg.RelayID || t.TrustRootID != a.cfg.InvitationSigner.DeviceID || t.MaxUses != 1 {
		return denied("ticket_binding_invalid")
	}
	if t.ConsumerRole != "sparkx_workbench_client" && !a.servicePeer(p.Identity) {
		return denied("consumer_role_invalid")
	}
	bindings, e := provisioning.BindGrantRoles(t, p.Identity)
	if e != nil {
		return denied("grant_role_invalid")
	}
	if bindings.Audience != a.cfg.Responder.DeviceID || len(bindings.Permissions) != 1 || node.Digest(bindings.Permissions) != node.Digest(p.Grant.Permissions) {
		return denied("grant_scope_invalid")
	}
	if bindings.Permissions[0] != node.Permission && (!a.servicePeer(p.Identity) || bindings.Permissions[0] != "sparkclaw.issuer.control.v1") {
		return denied("grant_permission_invalid")
	}
	return a.validateGrant(p.Identity, p.Grant, bindings.Permissions[0], bindings.Audience)
}
func (a *Adapter) servicePeer(id identity.DeviceIdentity) bool {
	for _, p := range a.cfg.ServicePeers {
		if p.DeviceID == id.DeviceID && node.Digest(p) == node.Digest(id) {
			return true
		}
	}
	return false
}
func (a *Adapter) validateGrant(id identity.DeviceIdentity, g trust.Grant, permission, audience string) error {
	if id.DomainID != a.cfg.DomainID || g.Issuer != a.cfg.GrantSigner.DeviceID || len(g.Permissions) != 1 || g.Permissions[0] != permission || len(g.RelayConstraints) != 1 || g.RelayConstraints[0] != a.cfg.RelayID || g.RevocationEpoch < 1 {
		return denied("grant_binding_invalid")
	}
	tp, e := identity.Thumbprint(id)
	if e != nil {
		return denied("identity_invalid")
	}
	if trust.VerifyGrant(c.NewProvider(), g, a.cfg.GrantSigner, trust.VerifyOptions{Audience: audience, SubjectDeviceID: id.DeviceID, ConfirmationThumbprint: tp, Permission: permission, RelayID: a.cfg.RelayID, Now: a.now()}) != nil {
		return denied("grant_invalid")
	}
	return nil
}

func (a *Adapter) Prepare(ctx context.Context, p node.RegistrationPreparation) error {
	if e := a.validatePreparation(p); e != nil {
		return e
	}
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return unavailable()
	}
	defer tx.Rollback(ctx)
	if e = a.lockEnrollment(ctx, tx, p.Identity.DeviceID, p.OperationID, ""); e != nil {
		return e
	}
	if e = a.claim(ctx, tx, p.Identity, false); e != nil {
		return e
	}
	var revoked bool
	if tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM iscp_relay.node_revocations WHERE domain_id=$1 AND device_id=$2)", a.cfg.DomainID, p.Identity.DeviceID).Scan(&revoked) != nil {
		return unavailable()
	}
	if revoked {
		return denied("device_revoked")
	}
	var digest string
	e = tx.QueryRow(ctx, "SELECT binding_digest FROM iscp_relay.node_preparations WHERE operation_id=$1 AND authority_id=$2", p.OperationID, a.authority).Scan(&digest)
	if e == nil {
		if digest != p.BindingDigest {
			return conflict("operation_binding_conflict")
		}
		return tx.Commit(ctx)
	}
	if e != pgx.ErrNoRows {
		return unavailable()
	}
	raw, _ := json.Marshal(p)
	_, e = tx.Exec(ctx, "INSERT INTO iscp_relay.node_preparations(operation_id,binding_digest,ticket_id,domain_id,device_id,preparation,expires_at,created_at,authority_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", p.OperationID, p.BindingDigest, p.TicketV3.TicketID, a.cfg.DomainID, p.Identity.DeviceID, raw, p.TicketV3.ExpiresAt, a.now(), a.authority)
	if e != nil {
		return conflict("ticket_preparation_conflict")
	}
	if tx.Commit(ctx) != nil {
		return unavailable()
	}
	return nil
}

func (a *Adapter) Commit(ctx context.Context, r node.RegistrationCommit) (node.RegistrationReceipt, error) {
	v, _, _, e := a.commit(ctx, r)
	return v, e
}
func (a *Adapter) commit(ctx context.Context, r node.RegistrationCommit) (node.RegistrationReceipt, node.RelayCredentials, bool, error) {
	var zero node.RegistrationReceipt
	var empty node.RelayCredentials
	if requireOperation(r.OperationID, r.BindingDigest) != nil {
		return zero, empty, false, invalid("invalid_operation")
	}
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return zero, empty, false, unavailable()
	}
	defer tx.Rollback(ctx)
	// Read immutable bindings to discover the device, acquire authority before
	// the operation key, and reread under the lock. An existing receipt remains
	// recoverable even after its enrollment ticket or proof expires.
	prior, found, e := a.receipt(ctx, tx, r.OperationID, r.BindingDigest, "registration")
	if e != nil {
		return zero, empty, false, e
	}
	if found {
		if e = a.lockLifecycle(ctx, tx, prior.DeviceID, r.OperationID, true, false); e != nil {
			return zero, empty, false, e
		}
		prior, found, e = a.receipt(ctx, tx, r.OperationID, r.BindingDigest, "registration")
		if e != nil || !found {
			return zero, empty, false, unavailable()
		}
		if e = a.active(ctx, tx, prior.DeviceID); e != nil {
			return zero, empty, false, e
		}
		return prior, empty, false, nil
	}
	var raw []byte
	e = tx.QueryRow(ctx, "SELECT preparation FROM iscp_relay.node_preparations WHERE operation_id=$1 AND authority_id=$2", r.OperationID, a.authority).Scan(&raw)
	if e == pgx.ErrNoRows {
		return zero, empty, false, denied("preparation_required")
	}
	if e != nil {
		return zero, empty, false, unavailable()
	}
	var p node.RegistrationPreparation
	if json.Unmarshal(raw, &p) != nil {
		return zero, empty, false, unavailable()
	}
	if p.BindingDigest != r.BindingDigest || node.Digest(p.TicketV3) != node.Digest(r.TicketV3) {
		return zero, empty, false, conflict("registration_input_conflict")
	}
	if e = a.validatePreparation(p); e != nil {
		return zero, empty, false, e
	}
	if e = a.verifyProof(p.Identity, r.IdentityProof, p.TicketV3.TicketID, 5*time.Minute); e != nil {
		return zero, empty, false, e
	}
	if e = a.lockEnrollment(ctx, tx, p.Identity.DeviceID, r.OperationID, strconv.FormatUint(p.Grant.RevocationEpoch, 10)); e != nil {
		return zero, empty, false, e
	}
	if e = a.owned(ctx, tx, p.Identity.DeviceID); e != nil {
		return zero, empty, false, e
	}
	prior, found, e = a.receipt(ctx, tx, r.OperationID, r.BindingDigest, "registration")
	if e != nil {
		return zero, empty, false, e
	}
	if found {
		if prior.DeviceID != p.Identity.DeviceID {
			return zero, empty, false, conflict("operation_binding_conflict")
		}
		if e = a.active(ctx, tx, prior.DeviceID); e != nil {
			return zero, empty, false, e
		}
		return prior, empty, false, nil
	}
	if e = a.useProof(ctx, tx, p.Identity, r.IdentityProof, p.TicketV3.TicketID, 5*time.Minute); e != nil {
		return zero, empty, false, e
	}
	if e = a.createDevice(ctx, tx, p.Identity); e != nil {
		return zero, empty, false, e
	}
	if e = a.storeGrant(ctx, tx, p.Identity, p.Grant); e != nil {
		return zero, empty, false, e
	}
	cmd, e := tx.Exec(ctx, "INSERT INTO iscp_relay.node_ticket_uses(ticket_id,operation_id,domain_id,device_id,used_at,authority_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(authority_id,ticket_id) DO NOTHING", p.TicketV3.TicketID, r.OperationID, a.cfg.DomainID, p.Identity.DeviceID, a.now(), a.authority)
	if e != nil {
		return zero, empty, false, unavailable()
	}
	if cmd.RowsAffected() != 1 {
		return zero, empty, false, conflict("ticket_already_consumed")
	}
	var previouslyIssued bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iscp_relay.access_tokens WHERE domain_id=$1 AND device_id=$2)`, a.cfg.DomainID, p.Identity.DeviceID).Scan(&previouslyIssued); e != nil {
		return zero, empty, false, unavailable()
	}
	tokens, e := a.issueLifecycle(ctx, tx, p.Identity.DeviceID, previouslyIssued)
	if e != nil {
		return zero, empty, false, unavailable()
	}
	receipt, e := node.SealRegistrationReceipt(node.RegistrationReceipt{OperationID: r.OperationID, BindingDigest: r.BindingDigest, IssuedAt: a.now()}, p.ReceiptWrapPublicKey, p.Identity, tokens)
	if e != nil {
		return zero, empty, false, invalid("invalid_wrap_key")
	}
	if a.saveReceipt(ctx, tx, "registration", receipt) != nil || tx.Commit(ctx) != nil {
		return zero, empty, false, unavailable()
	}
	a.invalidated(p.Identity.DeviceID)
	return receipt, tokens, true, nil
}
func (a *Adapter) Status(ctx context.Context, op, digest string) (node.RegistrationReceipt, error) {
	var z node.RegistrationReceipt
	if requireOperation(op, digest) != nil {
		return z, invalid("invalid_operation")
	}
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return z, unavailable()
	}
	defer tx.Rollback(ctx)
	r, found, e := a.receipt(ctx, tx, op, digest, "registration")
	if e != nil {
		return z, e
	}
	if !found {
		return z, Error{"operation_not_committed", http.StatusNotFound}
	}
	if e = a.lockLifecycle(ctx, tx, r.DeviceID, op, false, false); e != nil {
		return z, e
	}
	r, found, e = a.receipt(ctx, tx, op, digest, "registration")
	if e != nil || !found {
		return z, unavailable()
	}
	if e = a.active(ctx, tx, r.DeviceID); e != nil {
		return z, e
	}
	return r, nil
}

func (a *Adapter) createDevice(ctx context.Context, tx pgx.Tx, id identity.DeviceIdentity) error {
	if e := a.owned(ctx, tx, id.DeviceID); e != nil {
		return e
	}
	var thumb, status string
	e := tx.QueryRow(ctx, "SELECT public_key_thumbprint,status FROM iscp_relay.devices WHERE domain_id=$1 AND device_id=$2 FOR UPDATE", a.cfg.DomainID, id.DeviceID).Scan(&thumb, &status)
	tp, e2 := identity.Thumbprint(id)
	if e2 != nil {
		return denied("identity_invalid")
	}
	if e == nil {
		if status != "active" {
			return denied("device_revoked")
		}
		if thumb != tp {
			return conflict("identity_key_conflict")
		}
		return nil
	}
	if e != pgx.ErrNoRows {
		return unavailable()
	}
	raw, _ := json.Marshal(id)
	canon, _ := node.Canonical(id)
	uid, _ := postgres.NewUUIDv7Like(a.now())
	_, e = tx.Exec(ctx, "INSERT INTO iscp_relay.devices(id,domain_id,device_id,identity_raw,identity_canonical,public_key_thumbprint,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'active',$7,$7)", postgres.UUIDString(uid), a.cfg.DomainID, id.DeviceID, raw, canon, tp, a.now())
	if e != nil {
		return unavailable()
	}
	return nil
}
func (a *Adapter) active(ctx context.Context, tx pgx.Tx, dev string) error {
	if e := a.owned(ctx, tx, dev); e != nil {
		return e
	}
	var status string
	var revoked bool
	e := tx.QueryRow(ctx, "SELECT status,EXISTS(SELECT 1 FROM iscp_relay.node_revocations v WHERE v.domain_id=d.domain_id AND v.device_id=d.device_id) FROM iscp_relay.devices d WHERE domain_id=$1 AND device_id=$2", a.cfg.DomainID, dev).Scan(&status, &revoked)
	if e == pgx.ErrNoRows {
		return Error{"device_proof_invalid", 401}
	}
	if e != nil {
		return unavailable()
	}
	if status != "active" || revoked {
		return denied("device_revoked")
	}
	return nil
}
func (a *Adapter) verifyProof(id identity.DeviceIdentity, p identity.DeviceProof, challenge string, ttl time.Duration) error {
	if id.DomainID != a.cfg.DomainID || p.DomainID != id.DomainID || p.DeviceID != id.DeviceID || identity.VerifyProof(c.NewProvider(), id, p, a.cfg.RelayID, challenge, a.now(), ttl) != nil || p.Nonce == "" {
		return Error{"device_proof_invalid", 401}
	}
	return nil
}
func (a *Adapter) useProof(ctx context.Context, tx pgx.Tx, id identity.DeviceIdentity, p identity.DeviceProof, challenge string, ttl time.Duration) error {
	if e := a.verifyProof(id, p, challenge, ttl); e != nil {
		return e
	}
	cmd, e := tx.Exec(ctx, "INSERT INTO iscp_relay.pop_replay_cache(domain_id,device_id,nonce,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(domain_id,device_id,nonce) DO UPDATE SET expires_at=EXCLUDED.expires_at WHERE iscp_relay.pop_replay_cache.expires_at<=$5", id.DomainID, id.DeviceID, p.Nonce, p.IssuedAt.Add(ttl), a.now())
	if e != nil {
		return unavailable()
	}
	if cmd.RowsAffected() != 1 {
		return conflict("proof_replay_detected")
	}
	return nil
}
func (a *Adapter) storeGrant(ctx context.Context, tx pgx.Tx, id identity.DeviceIdentity, g trust.Grant) error {
	if e := a.owned(ctx, tx, id.DeviceID); e != nil {
		return e
	}
	var old uint64
	e := tx.QueryRow(ctx, "SELECT revision FROM iscp_relay.node_grants WHERE domain_id=$1 AND device_id=$2 AND authority_id=$3 FOR UPDATE", a.cfg.DomainID, id.DeviceID, a.authority).Scan(&old)
	if e != nil && e != pgx.ErrNoRows {
		return unavailable()
	}
	if e == nil && old > g.RevocationEpoch {
		return denied("stale_authorization_revision")
	}
	if e = a.syncGrantRevision(ctx, tx, id.DeviceID, g.RevocationEpoch); e != nil {
		return e
	}
	raw, _ := json.Marshal(g)
	_, e = tx.Exec(ctx, "INSERT INTO iscp_relay.node_grants(domain_id,device_id,revision,grant_raw,updated_at,authority_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(domain_id,device_id) DO UPDATE SET revision=EXCLUDED.revision,grant_raw=EXCLUDED.grant_raw,updated_at=EXCLUDED.updated_at WHERE iscp_relay.node_grants.revision<=EXCLUDED.revision AND iscp_relay.node_grants.authority_id=EXCLUDED.authority_id", a.cfg.DomainID, id.DeviceID, g.RevocationEpoch, raw, a.now(), a.authority)
	if e != nil {
		return unavailable()
	}
	return nil
}
func (a *Adapter) issueGeneration(ctx context.Context, tx pgx.Tx, dev, generation string) (node.RelayCredentials, error) {
	tokens, e := a.issue(ctx, tx, dev)
	if e != nil {
		return tokens, e
	}
	tag, e := tx.Exec(ctx, "UPDATE iscp_relay.access_tokens SET credential_generation=$4 WHERE domain_id=$1 AND device_id=$2 AND token_hash=$3", a.cfg.DomainID, dev, c.SHA256([]byte(tokens.Access.Token)), generation)
	if e != nil || tag.RowsAffected() != 1 {
		return node.RelayCredentials{}, unavailable()
	}
	tag, e = tx.Exec(ctx, "UPDATE iscp_relay.refresh_tokens SET credential_generation=$4 WHERE domain_id=$1 AND device_id=$2 AND refresh_hash=$3", a.cfg.DomainID, dev, c.SHA256([]byte(tokens.Refresh.Token)), generation)
	if e != nil || tag.RowsAffected() != 1 {
		return node.RelayCredentials{}, unavailable()
	}
	return tokens, nil
}
func (a *Adapter) issue(ctx context.Context, tx pgx.Tx, dev string) (node.RelayCredentials, error) {
	if e := a.owned(ctx, tx, dev); e != nil {
		return node.RelayCredentials{}, e
	}
	now := a.now()
	access := iscpbridge.RelayCredential{DomainID: a.cfg.DomainID, DeviceID: dev, Token: c.Base64URL(c.RandomBytes(32)), ExpiresAt: now.Add(15 * time.Minute)}
	refresh := iscpbridge.RelayCredential{DomainID: a.cfg.DomainID, DeviceID: dev, Token: c.Base64URL(c.RandomBytes(32)), ExpiresAt: now.Add(24 * time.Hour)}
	repo := repository.NewRelayRepository(tx)
	uid, _ := postgres.NewUUIDv7Like(now)
	if repo.StoreAccessHash(ctx, postgres.UUIDString(uid), repository.DomainID(a.cfg.DomainID), dev, c.SHA256([]byte(access.Token)), now, access.ExpiresAt) != nil {
		return node.RelayCredentials{}, unavailable()
	}
	uid, _ = postgres.NewUUIDv7Like(now)
	if repo.StoreRefreshHash(ctx, postgres.UUIDString(uid), repository.DomainID(a.cfg.DomainID), dev, c.SHA256([]byte(refresh.Token)), now, refresh.ExpiresAt) != nil {
		return node.RelayCredentials{}, unavailable()
	}
	return node.RelayCredentials{Access: access, Refresh: refresh}, nil
}
