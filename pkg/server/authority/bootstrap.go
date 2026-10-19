package authority

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"regexp"
)

// BootstrapEmpty is an operator action for a freshly created domain only.
// Empty tables cannot prove historical completeness: the caller must supply
// independent genesis evidence and explicitly attest this domain never served
// traffic. Existing scope/domain records can never be re-bootstrapped.
func BootstrapEmpty(ctx context.Context, tx pgx.Tx, scope, domain, history, evidence string, attestNeverServed bool) error {
	valid := regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	if !attestNeverServed || scope == "" || domain == "" || !valid.MatchString(history) || !valid.MatchString(evidence) {
		return errors.New("explicit new-domain genesis evidence required")
	}
	// Maintenance excludes every legacy writer for the entire verification and
	// authority installation transaction. Operators must also stop old binaries
	// and revoke their DB role before admitting the first new client.
	if _, e := tx.Exec(ctx, `LOCK TABLE iscp_relay.messages,iscp_relay.delivery_receipts,iscp_relay.admissions,iscp_relay.legacy_admission_keys,iscp_relay.devices,iscp_relay.writer_scopes,iscp_relay.domain_authority IN ACCESS EXCLUSIVE MODE`); e != nil {
		return e
	}
	var used bool
	e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iscp_relay.writer_scopes WHERE scope_id=$1) OR EXISTS(SELECT 1 FROM iscp_relay.domain_authority WHERE domain_id=$2) OR EXISTS(SELECT 1 FROM iscp_relay.messages WHERE domain_id=$2) OR EXISTS(SELECT 1 FROM iscp_relay.delivery_receipts WHERE domain_id=$2) OR EXISTS(SELECT 1 FROM iscp_relay.admissions WHERE domain_id=$2) OR EXISTS(SELECT 1 FROM iscp_relay.legacy_admission_keys WHERE domain_id=$2)`, scope, domain).Scan(&used)
	if e != nil {
		return e
	}
	if used {
		return errors.New("domain cannot use empty bootstrap; controlled legacy cutover required")
	}
	if _, e = tx.Exec(ctx, `INSERT INTO iscp_relay.writer_scopes(scope_id,writer_role,writes_enabled) VALUES($1,current_user,true)`, scope); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO iscp_relay.domain_authority(scope_id,domain_id,history_id,history_state,history_evidence_sha256,activated_at) VALUES($1,$2,$3,'continuous',$4,now())`, scope, domain, history, evidence); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO iscp_relay.device_authority(scope_id,domain_id,device_id,credential_generation,authorization_revision,state_version,state) SELECT $1,domain_id,device_id,1,1,1,'active' FROM iscp_relay.devices WHERE domain_id=$2`, scope, domain); e != nil {
		return e
	}
	// These tokens were minted only inside the operator-attested new domain.
	for _, table := range []string{"access_tokens", "refresh_tokens"} {
		if _, e = tx.Exec(ctx, "UPDATE iscp_relay."+table+" SET credential_generation=1 WHERE domain_id=$1", domain); e != nil {
			return e
		}
	}
	_, e = tx.Exec(ctx, `INSERT INTO iscp_relay.connection_owners(scope_id,domain_id,device_id) SELECT scope_id,domain_id,device_id FROM iscp_relay.device_authority WHERE scope_id=$1 AND domain_id=$2`, scope, domain)
	return e
}
