package iscprelayadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
	"github.com/jackc/pgx/v5"
)

type ServiceVerification struct {
	Identity  identity.DeviceIdentity `json:"identity"`
	Proof     identity.DeviceProof    `json:"proof"`
	Challenge string                  `json:"challenge"`
}

// VerifyServicePeer is private to the pinned control forwarder. It checks both
// operator enrollment and live durable device state, including after restart.
func (a *Adapter) VerifyServicePeer(ctx context.Context, p ServiceVerification) error {
	if !a.servicePeer(p.Identity) || !strings.HasPrefix(p.Challenge, "sparkclaw/iscp-node/control-grant/v1\x00") {
		return denied("service_peer_not_approved")
	}
	audienceApproved := false
	for _, id := range a.cfg.ServicePeers {
		if p.Proof.Audience == id.DeviceID && p.Identity.DeviceID != id.DeviceID {
			audienceApproved = true
		}
	}
	if !audienceApproved {
		return denied("service_audience_invalid")
	}
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return unavailable()
	}
	defer tx.Rollback(ctx)
	if lock(ctx, tx, "service-proof:"+p.Identity.DeviceID+":"+p.Proof.Nonce) != nil || lock(ctx, tx, "device:"+a.cfg.DomainID+":"+p.Identity.DeviceID) != nil {
		return unavailable()
	}
	if e = a.claimService(ctx, tx, p.Identity); e != nil {
		return e
	}
	if e = a.checkStoredIdentity(ctx, tx, p.Identity); e != nil {
		return e
	}
	digest := node.Digest(p)
	var old string
	e = tx.QueryRow(ctx, "SELECT binding_digest FROM iscp_relay.node_service_proofs WHERE domain_id=$1 AND device_id=$2 AND nonce=$3 AND authority_id=$4", a.cfg.DomainID, p.Identity.DeviceID, p.Proof.Nonce, a.authority).Scan(&old)
	if e == nil {
		if old != digest {
			return conflict("service_proof_binding_conflict")
		}
		return nil
	}
	if e != pgx.ErrNoRows {
		return unavailable()
	}
	if p.Proof.DomainID != p.Identity.DomainID || p.Proof.DeviceID != p.Identity.DeviceID || p.Proof.Nonce == "" || identity.VerifyProof(c.NewProvider(), p.Identity, p.Proof, p.Proof.Audience, p.Challenge, a.now(), time.Minute) != nil {
		return Error{"device_proof_invalid", 401}
	}
	_, e = tx.Exec(ctx, "INSERT INTO iscp_relay.node_service_proofs(domain_id,device_id,nonce,binding_digest,created_at,authority_id) VALUES($1,$2,$3,$4,$5,$6)", a.cfg.DomainID, p.Identity.DeviceID, p.Proof.Nonce, digest, a.now(), a.authority)
	if e != nil || tx.Commit(ctx) != nil {
		return unavailable()
	}
	return nil
}

type ServiceRecovery struct {
	OperationID          string                  `json:"operation_id"`
	Identity             identity.DeviceIdentity `json:"identity"`
	Proof                identity.DeviceProof    `json:"proof"`
	ReceiptWrapPublicKey string                  `json:"receipt_wrap_public_key"`
}

// ServiceRecover is an application extension for existing operator service
// peers only. Their standing permission is the root-owned identity allowlist;
// it grants no workbench access and can never enroll or revive a device.
func (a *Adapter) ServiceRecover(r *http.Request) (json.RawMessage, error) {
	if r.Method != http.MethodPost {
		return nil, Error{"method_not_allowed", 405}
	}
	var p ServiceRecovery
	if read(r, &p) != nil || !operationPattern.MatchString(p.OperationID) {
		return nil, invalid("decode_failed")
	}
	if !a.servicePeer(p.Identity) {
		return nil, denied("service_peer_not_approved")
	}
	digest := node.Digest(p)
	ctx := r.Context()
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return nil, unavailable()
	}
	defer tx.Rollback(ctx)
	if lock(ctx, tx, "operation:"+a.authority+":"+p.OperationID) != nil || lock(ctx, tx, "device:"+a.cfg.DomainID+":"+p.Identity.DeviceID) != nil {
		return nil, unavailable()
	}
	if e = a.claimService(ctx, tx, p.Identity); e != nil {
		return nil, e
	}
	if e = a.checkStoredIdentity(ctx, tx, p.Identity); e != nil {
		return nil, e
	}
	prior, found, e := a.receipt(ctx, tx, p.OperationID, digest, "service-recovery")
	if e != nil {
		return nil, e
	}
	if found {
		raw, _ := json.Marshal(prior)
		return raw, nil
	}
	challenge := strings.Join([]string{"sparkclaw/iscp-node/service-recovery/v1", p.OperationID, p.ReceiptWrapPublicKey}, "\x00")
	if e = a.useProof(ctx, tx, p.Identity, p.Proof, challenge, time.Minute); e != nil {
		return nil, e
	}
	repo := repository.NewRelayRepository(tx)
	if repo.RevokeDeviceCredentials(ctx, repository.DomainID(a.cfg.DomainID), p.Identity.DeviceID, a.now()) != nil {
		return nil, unavailable()
	}
	tokens, e := a.issue(ctx, tx, p.Identity.DeviceID)
	if e != nil {
		return nil, e
	}
	receipt, e := node.SealRegistrationReceipt(node.RegistrationReceipt{OperationID: p.OperationID, BindingDigest: digest, IssuedAt: a.now()}, p.ReceiptWrapPublicKey, p.Identity, tokens)
	if e != nil {
		return nil, invalid("invalid_wrap_key")
	}
	if a.saveReceipt(ctx, tx, "service-recovery", receipt) != nil || tx.Commit(ctx) != nil {
		return nil, unavailable()
	}
	a.invalidated(p.Identity.DeviceID)
	raw, _ := json.Marshal(receipt)
	return raw, nil
}
