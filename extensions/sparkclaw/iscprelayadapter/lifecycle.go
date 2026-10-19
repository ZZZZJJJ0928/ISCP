package iscprelayadapter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
	"github.com/jackc/pgx/v5"
)

func (a *Adapter) Recover(ctx context.Context, r node.RegistrationRecovery) (node.RegistrationReceipt, error) {
	var z node.RegistrationReceipt
	if requireOperation(r.OperationID, r.BindingDigest) != nil || node.ValidateIdentity(r.Identity) != nil || r.Identity.DomainID != a.cfg.DomainID {
		return z, invalid("invalid_recovery")
	}
	w := r
	w.BindingDigest = ""
	if node.Digest(w) != r.BindingDigest {
		return z, conflict("recovery_digest_conflict")
	}
	permission, audience := node.Permission, a.cfg.Responder.DeviceID
	if a.servicePeer(r.Identity) && len(r.Grant.Permissions) == 1 && r.Grant.Permissions[0] == "relay.recovery" {
		permission = "relay.recovery"
		audience = r.Identity.DeviceID
	}
	if e := a.validateGrant(r.Identity, r.Grant, permission, audience); e != nil {
		return z, e
	}
	if r.Revision != r.Grant.RevocationEpoch {
		return z, denied("authorization_revision_conflict")
	}
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return z, unavailable()
	}
	defer tx.Rollback(ctx)
	if lock(ctx, tx, "operation:"+a.authority+":"+r.OperationID) != nil || lock(ctx, tx, "device:"+a.cfg.DomainID+":"+r.Identity.DeviceID) != nil {
		return z, unavailable()
	}
	if e = a.checkStoredIdentity(ctx, tx, r.Identity); e != nil {
		return z, e
	}
	prior, found, e := a.receipt(ctx, tx, r.OperationID, r.BindingDigest, "recovery")
	if e != nil {
		return z, e
	}
	if found {
		return prior, nil
	}
	if e = a.useProof(ctx, tx, r.Identity, r.Proof, r.OperationID+"\x00"+r.ReceiptWrapPublicKey, time.Minute); e != nil {
		return z, e
	}
	if e = a.storeGrant(ctx, tx, r.Identity, r.Grant); e != nil {
		return z, e
	}
	repo := repository.NewRelayRepository(tx)
	if repo.RevokeDeviceCredentials(ctx, repository.DomainID(a.cfg.DomainID), r.Identity.DeviceID, a.now()) != nil {
		return z, unavailable()
	}
	tokens, e := a.issue(ctx, tx, r.Identity.DeviceID)
	if e != nil {
		return z, e
	}
	receipt, e := node.SealRegistrationReceipt(node.RegistrationReceipt{OperationID: r.OperationID, BindingDigest: r.BindingDigest, IssuedAt: a.now()}, r.ReceiptWrapPublicKey, r.Identity, tokens)
	if e != nil {
		return z, invalid("invalid_wrap_key")
	}
	if a.saveReceipt(ctx, tx, "recovery", receipt) != nil || tx.Commit(ctx) != nil {
		return z, unavailable()
	}
	a.invalidated(r.Identity.DeviceID)
	return receipt, nil
}
func (a *Adapter) checkStoredIdentity(ctx context.Context, tx pgx.Tx, id identity.DeviceIdentity) error {
	if e := a.active(ctx, tx, id.DeviceID); e != nil {
		return e
	}
	var raw []byte
	e := tx.QueryRow(ctx, "SELECT identity_raw FROM iscp_relay.devices WHERE domain_id=$1 AND device_id=$2 FOR UPDATE", a.cfg.DomainID, id.DeviceID).Scan(&raw)
	if e != nil {
		return unavailable()
	}
	var stored identity.DeviceIdentity
	if json.Unmarshal(raw, &stored) != nil {
		return unavailable()
	}
	if node.Digest(stored) != node.Digest(id) {
		return conflict("recovery_identity_conflict")
	}
	return nil
}
func (a *Adapter) Revoke(ctx context.Context, op, dev string, revision uint64) error {
	if !operationPattern.MatchString(op) || dev == "" || revision < 2 {
		return invalid("invalid_revocation")
	}
	if dev == a.cfg.Responder.DeviceID {
		return denied("service_peer_requires_operator")
	}
	for _, p := range a.cfg.ServicePeers {
		if dev == p.DeviceID {
			return denied("service_peer_requires_operator")
		}
	}
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return unavailable()
	}
	defer tx.Rollback(ctx)
	if lock(ctx, tx, "operation:"+a.authority+":"+op) != nil || lock(ctx, tx, "device:"+a.cfg.DomainID+":"+dev) != nil {
		return unavailable()
	}
	if e = a.owned(ctx, tx, dev); e != nil {
		return e
	}
	var otherDevice string
	e = tx.QueryRow(ctx, "SELECT device_id FROM iscp_relay.node_revocations WHERE operation_id=$1 AND authority_id=$2", op, a.authority).Scan(&otherDevice)
	if e == nil && otherDevice != dev {
		return conflict("revocation_operation_conflict")
	}
	if e != nil && e != pgx.ErrNoRows {
		return unavailable()
	}
	var knownOp string
	var knownRevision uint64
	e = tx.QueryRow(ctx, "SELECT operation_id,revision FROM iscp_relay.node_revocations WHERE domain_id=$1 AND device_id=$2 AND authority_id=$3 FOR UPDATE", a.cfg.DomainID, dev, a.authority).Scan(&knownOp, &knownRevision)
	if e == nil {
		if knownOp != op || knownRevision != revision {
			return conflict("revocation_operation_conflict")
		}
		return nil
	}
	if e != pgx.ErrNoRows {
		return unavailable()
	}
	var prior uint64
	e = tx.QueryRow(ctx, "SELECT revision FROM iscp_relay.node_grants WHERE domain_id=$1 AND device_id=$2 AND authority_id=$3", a.cfg.DomainID, dev, a.authority).Scan(&prior)
	if e != nil && e != pgx.ErrNoRows {
		return unavailable()
	}
	if e == nil && revision <= prior {
		return conflict("revocation_revision_conflict")
	}
	_, e = tx.Exec(ctx, "INSERT INTO iscp_relay.node_revocations(domain_id,device_id,revision,operation_id,revoked_at,authority_id) VALUES($1,$2,$3,$4,$5,$6)", a.cfg.DomainID, dev, revision, op, a.now(), a.authority)
	if e != nil {
		return unavailable()
	}
	repo := repository.NewRelayRepository(tx)
	if repo.RevokeDevice(ctx, repository.DomainID(a.cfg.DomainID), dev, a.now()) != nil || repo.RevokeDeviceCredentials(ctx, repository.DomainID(a.cfg.DomainID), dev, a.now()) != nil || tx.Commit(ctx) != nil {
		return unavailable()
	}
	a.invalidated(dev)
	if a.MarkRevoked != nil {
		a.MarkRevoked(dev)
	}
	return nil
}

// Refresh keeps the original body/response when node receipt headers are absent.
// The explicit deployment extension returns only a sealed response, making exact
// unknown-outcome replay safe without turning a captured old proof into a token.
func (a *Adapter) Refresh(r *http.Request) (json.RawMessage, error) {
	if r.Method != http.MethodPost {
		return nil, Error{"method_not_allowed", 405}
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 16385))
	if e != nil {
		return nil, invalid("decode_failed")
	}
	var input struct {
		Refresh string `json:"refresh"`
	}
	if node.StrictDecode(raw, &input) != nil || len(input.Refresh) < 32 || len(input.Refresh) > 512 {
		return nil, invalid("decode_failed")
	}
	op, wrap, encoded := r.Header.Get("Idempotency-Key"), r.Header.Get("X-SparkClaw-Refresh-Wrap-Key"), r.Header.Get("X-SparkClaw-Refresh-Proof")
	managed := op != "" || wrap != "" || encoded != ""
	var proof identity.DeviceProof
	digest := ""
	hash := c.SHA256([]byte(input.Refresh))
	if managed {
		if !operationPattern.MatchString(op) {
			return nil, invalid("idempotency_key_required")
		}
		pub, e := base64.RawURLEncoding.Strict().DecodeString(wrap)
		if e != nil || len(pub) != 32 {
			return nil, invalid("invalid_wrap_key")
		}
		pb, e := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if e != nil || node.StrictDecode(pb, &proof) != nil {
			return nil, Error{"device_proof_invalid", 401}
		}
		digest = node.Digest(map[string]any{"operation_id": op, "refresh_hash": c.Base64URL(hash), "wrap_public": wrap, "proof": proof})
	} else {
		op = "legacy-refresh:" + c.Base64URL(hash)
	}
	ctx := r.Context()
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return nil, unavailable()
	}
	defer tx.Rollback(ctx)
	if lock(ctx, tx, "operation:"+a.authority+":"+op) != nil {
		return nil, unavailable()
	}
	if managed {
		prior, found, e := a.receipt(ctx, tx, op, digest, "refresh")
		if e != nil {
			return nil, e
		}
		if found {
			if a.active(ctx, tx, prior.DeviceID) != nil {
				return nil, denied("device_revoked")
			}
			raw, _ := json.Marshal(prior)
			return raw, nil
		}
	}
	var dev string
	e = tx.QueryRow(ctx, "SELECT device_id FROM iscp_relay.refresh_tokens WHERE domain_id=$1 AND refresh_hash=$2 AND revoked_at IS NULL AND expires_at>$3", a.cfg.DomainID, hash, a.now()).Scan(&dev)
	if e == pgx.ErrNoRows {
		return nil, Error{"refresh_credential_invalid", 401}
	}
	if e != nil {
		return nil, unavailable()
	}
	if lock(ctx, tx, "device:"+a.cfg.DomainID+":"+dev) != nil {
		return nil, unavailable()
	}
	if e = a.active(ctx, tx, dev); e != nil {
		return nil, e
	}
	var id identity.DeviceIdentity
	var idraw []byte
	if tx.QueryRow(ctx, "SELECT identity_raw FROM iscp_relay.devices WHERE domain_id=$1 AND device_id=$2", a.cfg.DomainID, dev).Scan(&idraw) != nil || json.Unmarshal(idraw, &id) != nil {
		return nil, unavailable()
	}
	if managed {
		challenge := strings.Join([]string{"sparkclaw/iscp-node/refresh/v1", op, c.Base64URL(hash), wrap}, "\x00")
		if e = a.useProof(ctx, tx, id, proof, challenge, time.Minute); e != nil {
			return nil, e
		}
	}
	cmd, e := tx.Exec(ctx, "UPDATE iscp_relay.refresh_tokens SET revoked_at=$3 WHERE domain_id=$1 AND refresh_hash=$2 AND revoked_at IS NULL AND expires_at>$3", a.cfg.DomainID, hash, a.now())
	if e != nil {
		return nil, unavailable()
	}
	if cmd.RowsAffected() != 1 {
		return nil, Error{"refresh_credential_invalid", 401}
	}
	tokens, e := a.issue(ctx, tx, dev)
	if e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, "UPDATE iscp_relay.refresh_tokens SET rotated_to=(SELECT id FROM iscp_relay.refresh_tokens WHERE domain_id=$1 AND refresh_hash=$3) WHERE domain_id=$1 AND refresh_hash=$2", a.cfg.DomainID, hash, c.SHA256([]byte(tokens.Refresh.Token))); e != nil {
		return nil, unavailable()
	}
	var response json.RawMessage
	if managed {
		receipt, e := node.SealRegistrationReceipt(node.RegistrationReceipt{OperationID: op, BindingDigest: digest, IssuedAt: a.now()}, wrap, id, tokens)
		if e != nil {
			return nil, invalid("invalid_wrap_key")
		}
		if a.saveReceipt(ctx, tx, "refresh", receipt) != nil {
			return nil, unavailable()
		}
		response, _ = json.Marshal(receipt)
	} else {
		response = standardTokens(tokens)
	}
	if tx.Commit(ctx) != nil {
		return nil, unavailable()
	}
	a.invalidated(dev)
	return response, nil
}
