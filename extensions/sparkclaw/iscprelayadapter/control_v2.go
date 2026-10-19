package iscprelayadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"time"

	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	node "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
	"github.com/jackc/pgx/v5"
)

// ControlBackend shares the authority rows with the duplex data transactions.
// Its operation ledger is encrypted; old credential tokens are never journaled
// in plaintext. Initialization does not activate history or create identities.
type ControlBackend struct {
	adapter *Adapter
	signer  identity.Device
	epoch   string
	key     []byte
}

func (a *Adapter) EnableControlV2(ctx context.Context, signer identity.Device, epoch string) (*ControlBackend, error) {
	if node.ValidateIdentity(signer.Identity) != nil || signer.Identity.DomainID != a.cfg.DomainID || epoch == "" || a.cfg.ControlIssuerActor == nil || !a.servicePeer(*a.cfg.ControlIssuerActor) {
		return nil, invalid("control_identity_required")
	}
	key, e := c.NewProvider().HKDF(signer.Private.BytesForDevStore(), nil, []byte("iscp/control-ledger/v2\x00"+a.authority), 32)
	if e != nil {
		return nil, e
	}
	_, e = a.db.Exec(ctx, `CREATE TABLE IF NOT EXISTS iscp_relay.control_operations (
 scope_id text NOT NULL, authority_id text NOT NULL, actor_domain text NOT NULL, actor_device text NOT NULL, namespace text NOT NULL, operation_id text NOT NULL,
 subject_device text NOT NULL, ciphertext bytea NOT NULL CHECK(octet_length(ciphertext)<=1048576),
 PRIMARY KEY(scope_id,actor_domain,actor_device,namespace,operation_id));`)
	if e != nil {
		return nil, e
	}
	b := &ControlBackend{adapter: a, signer: signer, epoch: epoch, key: key}
	a.controlEpoch = epoch
	a.controlBackend = b
	return b, nil
}
func (b *ControlBackend) Handler() http.Handler {
	return control.NewHandler(b.adapter.cfg.RelayID, b.signer, b)
}
func (b *ControlBackend) ResolveActor(ctx context.Context, domain, device string) (identity.DeviceIdentity, error) {
	a := b.adapter
	var raw []byte
	if domain != a.cfg.DomainID {
		return identity.DeviceIdentity{}, control.ErrAuthentication
	}
	e := a.db.QueryRow(ctx, "SELECT identity_raw FROM iscp_relay.devices WHERE domain_id=$1 AND device_id=$2", domain, device).Scan(&raw)
	var id identity.DeviceIdentity
	if e != nil || json.Unmarshal(raw, &id) != nil || node.ValidateIdentity(id) != nil {
		return id, control.ErrAuthentication
	}
	return id, nil
}
func (b *ControlBackend) storageAAD(k control.Key) []byte {
	return []byte("iscp/control-ledger/v2\x00" + b.adapter.authority + "\x00" + k.StorageKey())
}
func (b *ControlBackend) read(ctx context.Context, tx pgx.Tx, k control.Key) (*control.Record, error) {
	var blob []byte
	var e error
	q := "SELECT ciphertext FROM iscp_relay.control_operations WHERE scope_id=$1 AND authority_id=$2 AND actor_domain=$3 AND actor_device=$4 AND namespace=$5 AND operation_id=$6"
	if tx == nil {
		e = b.adapter.db.QueryRow(ctx, q, b.adapter.cfg.RelayID, b.adapter.authority, k.DomainID, k.DeviceID, k.Namespace, k.OperationID).Scan(&blob)
	} else {
		e = tx.QueryRow(ctx, q, b.adapter.cfg.RelayID, b.adapter.authority, k.DomainID, k.DeviceID, k.Namespace, k.OperationID).Scan(&blob)
	}
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if len(blob) < 28 {
		return nil, control.ErrInvalid
	}
	raw, e := c.NewProvider().Open(b.key, blob[:12], blob[12:], b.storageAAD(k))
	if e != nil {
		return nil, e
	}
	var r control.Record
	if json.Unmarshal(raw, &r) != nil || r.Key != k {
		return nil, control.ErrInvalid
	}
	return &r, nil
}
func (b *ControlBackend) save(ctx context.Context, tx pgx.Tx, r *control.Record) error {
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	nonce := c.RandomBytes(12)
	ct, e := c.NewProvider().Seal(b.key, nonce, raw, b.storageAAD(r.Key))
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO iscp_relay.control_operations(scope_id,authority_id,actor_domain,actor_device,namespace,operation_id,subject_device,ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(scope_id,actor_domain,actor_device,namespace,operation_id) DO UPDATE SET ciphertext=EXCLUDED.ciphertext WHERE iscp_relay.control_operations.authority_id=EXCLUDED.authority_id AND iscp_relay.control_operations.subject_device=EXCLUDED.subject_device`, b.adapter.cfg.RelayID, b.adapter.authority, r.Key.DomainID, r.Key.DeviceID, r.Key.Namespace, r.Key.OperationID, r.Intent.SubjectBinding.DeviceID, append(nonce, ct...))
	return e
}
func (b *ControlBackend) lock(ctx context.Context, tx pgx.Tx, actor, target string, key *control.Key, exclusive bool) (authority.Snapshot, error) {
	devices := []authority.DeviceLock{{ID: target, Exclusive: exclusive}}
	if actor != target {
		devices = append(devices, authority.DeviceLock{ID: actor})
	}
	keys := []authority.Key{}
	if key != nil {
		h := c.Base64URL(c.SHA256([]byte(key.StorageKey())))
		keys = append(keys, authority.Key{Namespace: key.Namespace, ID: h})
	}
	return authority.Lock(ctx, tx, authority.Request{ScopeID: b.adapter.cfg.RelayID, DomainID: b.adapter.cfg.DomainID, ExpectedWriterEpoch: b.epoch, Devices: devices, Keys: keys, AllowInactiveDevices: true})
}
func (b *ControlBackend) current(ctx context.Context, tx pgx.Tx, actor identity.DeviceIdentity, subject control.Subject, target control.Target, snapshot authority.Snapshot) (node.ControlAuthority, error) {
	a := b.adapter
	var out node.ControlAuthority
	delegated := actor.DeviceID != subject.DeviceID
	if subject.DomainID != a.cfg.DomainID || target.ServiceID != a.cfg.RelayID || target.ResourceID != subject.BindingID || actor.DomainID != subject.DomainID {
		return out, &control.Failure{Code: "scope_denied"}
	}
	if delegated && (a.cfg.ControlIssuerActor == nil || node.Digest(*a.cfg.ControlIssuerActor) != node.Digest(actor)) {
		return out, &control.Failure{Code: "scope_denied"}
	}
	for _, dev := range []string{actor.DeviceID, subject.DeviceID} {
		state, ok := snapshot.Devices[dev]
		if !ok {
			return out, &control.Failure{Code: "authorization_unavailable"}
		}
		if state.State != "active" {
			rev := control.Counter(state.AuthorizationRevision)
			code := "authorization_unavailable"
			if state.State == "revoked" {
				code = "authorization_revoked"
			}
			return out, &control.Failure{Code: code, Revision: &rev}
		}
		if a.active(ctx, tx, dev) != nil {
			return out, &control.Failure{Code: "authorization_unavailable"}
		}
	}
	var prepRaw []byte
	e := tx.QueryRow(ctx, "SELECT preparation FROM iscp_relay.node_preparations WHERE domain_id=$1 AND device_id=$2 AND authority_id=$3 ORDER BY created_at ASC LIMIT 1", a.cfg.DomainID, subject.DeviceID, a.authority).Scan(&prepRaw)
	var prep node.RegistrationPreparation
	if e != nil || json.Unmarshal(prepRaw, &prep) != nil || prep.Binding.ClientID != subject.BindingID || prep.Identity.DeviceID != subject.DeviceID {
		return out, &control.Failure{Code: "scope_denied"}
	}
	if a.owned(ctx, tx, subject.DeviceID) != nil {
		return out, &control.Failure{Code: "scope_denied"}
	}
	var raw []byte
	var revision uint64
	if tx.QueryRow(ctx, "SELECT revision,grant_raw FROM iscp_relay.node_grants WHERE domain_id=$1 AND device_id=$2 AND authority_id=$3", a.cfg.DomainID, subject.DeviceID, a.authority).Scan(&revision, &raw) != nil {
		return out, &control.Failure{Code: "authorization_unavailable"}
	}
	var grant trust.Grant
	if json.Unmarshal(raw, &grant) != nil || len(grant.Permissions) != 1 || grant.RevocationEpoch != revision || control.Number(revision) != control.Counter(snapshot.Devices[subject.DeviceID].AuthorizationRevision) {
		return out, &control.Failure{Code: "authorization_unavailable"}
	}
	if trust.VerifyGrant(c.NewProvider(), grant, a.cfg.GrantSigner, trust.VerifyOptions{Audience: grant.Audience, SubjectDeviceID: subject.DeviceID, ConfirmationThumbprint: prep.Identity.PublicKey.KID, Permission: grant.Permissions[0], RelayID: a.cfg.RelayID, Now: grant.NotBefore}) != nil {
		return out, &control.Failure{Code: "scope_denied"}
	}
	scopes := append([]string(nil), grant.Permissions...)
	sort.Strings(scopes)
	return node.ControlAuthority{Subject: subject, Target: target, Generation: control.Counter(snapshot.Devices[subject.DeviceID].CredentialGeneration), AuthorizationRevision: control.Number(revision), ResourceVersion: "1", Scopes: scopes}, nil
}

// Authority is only called behind the existing authenticated private service
// plane; the actor must be the configured registered issuer service device.
func (b *ControlBackend) Authority(ctx context.Context, actor identity.DeviceIdentity, subject control.Subject, target control.Target) (node.ControlAuthority, error) {
	var out node.ControlAuthority
	if b.adapter.cfg.ControlIssuerActor == nil || node.Digest(actor) != node.Digest(*b.adapter.cfg.ControlIssuerActor) {
		return out, control.ErrAuthentication
	}
	tx, e := b.adapter.db.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	snapshot, e := b.lock(ctx, tx, actor.DeviceID, subject.DeviceID, nil, false)
	if e != nil {
		return out, e
	}
	return b.current(ctx, tx, actor, subject, target, snapshot)
}
func (b *ControlBackend) Execute(ctx context.Context, r control.Request, actor identity.DeviceIdentity, token string) (control.Outcome, error) {
	var out control.Outcome
	a := b.adapter
	if r.Validate() != nil || r.Key.Namespace != control.RelayNamespace {
		return out, &control.Failure{Code: "invalid_request"}
	}
	prior, e := b.read(ctx, nil, r.Key)
	if e != nil {
		return out, e
	}
	var intent *control.Intent
	if prior != nil {
		intent = &prior.Intent
	} else {
		intent = r.Intent
	}
	if intent == nil {
		if a.cfg.ControlIssuerActor != nil && actor.DeviceID == a.cfg.ControlIssuerActor.DeviceID {
			return out, &control.Failure{Code: "invalid_request"}
		}
		var raw []byte
		err := a.db.QueryRow(ctx, "SELECT preparation FROM iscp_relay.node_preparations WHERE domain_id=$1 AND device_id=$2 AND authority_id=$3 ORDER BY created_at ASC LIMIT 1", a.cfg.DomainID, actor.DeviceID, a.authority).Scan(&raw)
		var prep node.RegistrationPreparation
		if err != nil || json.Unmarshal(raw, &prep) != nil {
			return out, &control.Failure{Code: "scope_denied"}
		}
		intent = &control.Intent{SubjectBinding: control.Subject{DomainID: actor.DomainID, DeviceID: actor.DeviceID, BindingID: prep.Binding.ClientID}, Target: control.Target{ServiceID: a.cfg.RelayID, ResourceID: prep.Binding.ClientID}}
	}
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	snapshot, e := b.lock(ctx, tx, actor.DeviceID, intent.SubjectBinding.DeviceID, &r.Key, r.Action != "lookup")
	if e != nil {
		return out, e
	}
	current, e := b.current(ctx, tx, actor, intent.SubjectBinding, intent.Target, snapshot)
	if e != nil {
		return out, e
	}
	if token != "" {
		var valid bool
		hash := c.SHA256([]byte(token))
		e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM iscp_relay.refresh_tokens WHERE domain_id=$1 AND device_id=$2 AND refresh_hash=$3 AND revoked_at IS NULL AND expires_at>$4 AND credential_generation=$5)", a.cfg.DomainID, actor.DeviceID, hash, a.now(), string(current.Generation)).Scan(&valid)
		if e != nil {
			return out, e
		}
		if !valid {
			return out, &control.Failure{Code: "authentication_failed"}
		}
	}
	if (prior != nil || r.Intent != nil) && (intent.TaskAuthorization.AuthorizationRevision != current.AuthorizationRevision || intent.Preconditions.AuthorizationRevision != current.AuthorizationRevision) {
		return out, &control.Failure{Code: "scope_denied"}
	}
	for _, scope := range intent.Payload.RequestedScopes {
		n := sort.SearchStrings(current.Scopes, scope)
		if n == len(current.Scopes) || current.Scopes[n] != scope {
			return out, &control.Failure{Code: "scope_denied"}
		}
	}
	delegated := actor.DeviceID != intent.SubjectBinding.DeviceID
	if delegated && (intent.Parent == nil || intent.Kind != "relay.recover") {
		return out, &control.Failure{Code: "scope_denied"}
	}
	if !delegated && intent.Parent != nil {
		return out, &control.Failure{Code: "scope_denied"}
	}
	now := a.now().Truncate(time.Second)
	record, e := b.read(ctx, tx, r.Key)
	if e != nil {
		return out, e
	}
	if snapshot.HistoryState != "continuous" {
		history := snapshot.HistoryID
		if history == "" {
			history = control.RandomID()
		}
		status, e := control.SignStatus(control.Status{AttemptID: r.AttemptID, Key: r.Key, SemanticDigest: r.SemanticDigest, State: "unknown", RecordVersion: "0", HistoryID: history, HistoryComplete: false, Code: "history_unavailable", CredentialGeneration: current.Generation, CheckedAt: now}, b.signer)
		out.Status = &status
		return out, e
	}
	if record != nil {
		if record.SemanticDigest != r.SemanticDigest {
			status, e := record.Status(r, snapshot.HistoryID, true, now, b.signer)
			out.Status = &status
			return out, e
		}
		if r.Action == "ack" {
			d, e := record.Acknowledge(*r.Ack, current.Generation, delegated, now, b.signer)
			if e != nil {
				return out, e
			}
			if e = b.save(ctx, tx, record); e != nil {
				return out, e
			}
			if e = tx.Commit(ctx); e != nil {
				return out, control.ErrUnknown
			}
			out.Disposition = &d
			return out, nil
		}
		out.Result = record.Result
		return out, nil
	}
	if r.Action == "lookup" || r.Action == "ack" {
		status, e := control.SignStatus(control.Status{AttemptID: r.AttemptID, Key: r.Key, SemanticDigest: r.SemanticDigest, State: "absent", RecordVersion: "0", HistoryID: snapshot.HistoryID, HistoryComplete: true, Code: "none", CredentialGeneration: current.Generation, CheckedAt: now}, b.signer)
		out.Status = &status
		return out, e
	}
	if r.Intent == nil || !reflect.DeepEqual(*r.Intent, *intent) || intent.Preconditions.ResourceVersion != current.ResourceVersion {
		return out, &control.Failure{Code: "generation_conflict"}
	}
	if p := intent.Predecessor; p != nil {
		if p.Key.DomainID != r.Key.DomainID || p.Key.DeviceID != r.Key.DeviceID || p.Key.Namespace != r.Key.Namespace {
			return out, &control.Failure{Code: "generation_conflict"}
		}
		old, e := b.read(ctx, tx, p.Key)
		if e != nil {
			return out, e
		}
		if e = control.CheckPredecessor(*intent, map[string]*control.Record{p.Key.StorageKey(): old}); e != nil {
			return out, e
		}
	}
	record = &control.Record{Key: r.Key, Intent: *intent, SemanticDigest: r.SemanticDigest, State: "succeeded", Version: "1", Generation: current.Generation, CreatedAt: now}
	expected, e := intent.Preconditions.CredentialGeneration.Uint64()
	if e != nil {
		return out, e
	}
	actual, _ := current.Generation.Uint64()
	if expected > actual {
		return out, &control.Failure{Code: "generation_conflict"}
	}
	body := control.ResultBody{}
	state := "succeeded"
	if expected < actual {
		record.Generation = intent.Preconditions.CredentialGeneration
		state = "failed"
		body.Code = "generation_conflict"
	} else {
		next, e := current.Generation.Next()
		if e != nil {
			return out, e
		}
		repo := repository.NewRelayRepository(tx)
		if e = repo.RevokeDeviceCredentials(ctx, repository.DomainID(a.cfg.DomainID), intent.SubjectBinding.DeviceID, now); e != nil {
			return out, e
		}
		tokens, e := a.issueGeneration(ctx, tx, intent.SubjectBinding.DeviceID, string(next))
		if e != nil {
			return out, e
		}
		tokens.Access.ExpiresAt = tokens.Access.ExpiresAt.Truncate(time.Second)
		tokens.Refresh.ExpiresAt = tokens.Refresh.ExpiresAt.Truncate(time.Second)
		body.RelayCredentials = &control.RelayCredentials{TargetServiceID: a.cfg.RelayID, BindingID: intent.SubjectBinding.BindingID, CredentialGeneration: next, AuthorizationRevision: current.AuthorizationRevision, Access: control.Credential{DomainID: tokens.Access.DomainID, DeviceID: tokens.Access.DeviceID, Token: tokens.Access.Token, ExpiresAt: tokens.Access.ExpiresAt}, Refresh: control.Credential{DomainID: tokens.Refresh.DomainID, DeviceID: tokens.Refresh.DeviceID, Token: tokens.Refresh.Token, ExpiresAt: tokens.Refresh.ExpiresAt}}
		record.Generation = next
		tag, e := tx.Exec(ctx, "UPDATE iscp_relay.device_authority SET credential_generation=$4,state_version=state_version+1 WHERE scope_id=$1 AND domain_id=$2 AND device_id=$3 AND credential_generation=$5", a.cfg.RelayID, a.cfg.DomainID, intent.SubjectBinding.DeviceID, string(next), string(current.Generation))
		if e != nil || tag.RowsAffected() != 1 {
			return out, control.ErrUnknown
		}
	}
	res, e := control.NewResult(control.ResultPayload{Key: r.Key, SemanticDigest: r.SemanticDigest, ResultVersion: "1", State: state, CompletedAt: now, CredentialGeneration: record.Generation, Body: body}, b.signer)
	if e != nil {
		return out, e
	}
	record.Result = &res
	record.State = state
	if e = b.save(ctx, tx, record); e != nil {
		return out, e
	}
	if e = tx.Commit(ctx); e != nil {
		return out, control.ErrUnknown
	}
	out.Result = &res
	return out, nil
}

func (b *ControlBackend) Disclose(ctx context.Context, r control.Request, actor identity.DeviceIdentity, emit func() error) error {
	prior, err := b.read(ctx, nil, r.Key)
	if err != nil {
		return err
	}
	// A status without a retained record reveals no credentials; Execute already
	// checked that actor's registration. For retained data lock the target too.
	subject := actor.DeviceID
	if prior != nil {
		subject = prior.Intent.SubjectBinding.DeviceID
	} else if r.Intent != nil {
		subject = r.Intent.SubjectBinding.DeviceID
	}
	tx, err := b.adapter.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	snapshot, err := b.lock(ctx, tx, actor.DeviceID, subject, &r.Key, false)
	if err != nil {
		return err
	}
	if prior != nil {
		current, err := b.current(ctx, tx, actor, prior.Intent.SubjectBinding, prior.Intent.Target, snapshot)
		if err != nil {
			return err
		}
		if prior.Intent.TaskAuthorization.AuthorizationRevision != current.AuthorizationRevision {
			return &control.Failure{Code: "scope_denied"}
		}
	} else {
		for _, id := range []string{actor.DeviceID, subject} {
			if snapshot.Devices[id].State != "active" {
				return &control.Failure{Code: "authorization_unavailable"}
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return emit()
}
