package cleanup

import (
	"context"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// ExpiredDuplexRelayMessages removes delivery payloads, never immutable
// admission tombstones. The process's original writer epoch fences maintenance
// just like an ordinary admission; incomplete histories cannot be pruned.
func ExpiredDuplexRelayMessages(ctx context.Context, pool *pgxpool.Pool, scope, domain, epoch string, now time.Time, dryRun bool) (Result, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback(context.Background())
	if _, err = authority.Lock(ctx, tx, authority.Request{ScopeID: scope, DomainID: domain, ExpectedWriterEpoch: epoch, RequireContinuousHistory: true}); err != nil {
		return Result{}, err
	}
	result := Result{Name: "expired_duplex_relay_messages", DryRun: dryRun}
	if dryRun {
		err = tx.QueryRow(ctx, `SELECT count(*) FROM iscp_relay.messages m WHERE domain_id=$1 AND expires_at<$2 AND EXISTS(SELECT 1 FROM iscp_relay.admissions a WHERE a.domain_id=m.domain_id AND a.message_id=m.message_id)`, domain, now).Scan(&result.WouldDelete)
	} else {
		tag, e := tx.Exec(ctx, `DELETE FROM iscp_relay.messages m WHERE domain_id=$1 AND expires_at<$2 AND EXISTS(SELECT 1 FROM iscp_relay.admissions a WHERE a.domain_id=m.domain_id AND a.message_id=m.message_id)`, domain, now)
		err = e
		result.Deleted = tag.RowsAffected()
	}
	if err != nil {
		return Result{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Result{}, err
	}
	return result, nil
}
