package cleanup

import (
	"context"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DuplexBatchSize bounds locks, WAL and work in one independently committed batch.
const DuplexBatchSize = 256

// ExpiredDuplexRelayMessages removes one batch of expired delivery payloads,
// never immutable admissions. DryRun counts only the next unlocked batch.
func ExpiredDuplexRelayMessages(ctx context.Context, pool *pgxpool.Pool, scope, domain, epoch string, now time.Time, dryRun bool) (Result, error) {
	return pruneDuplexRelayMessages(ctx, pool, scope, domain, epoch, now, dryRun, false)
}

// PruneDuplexRelayMessages also reclaims successfully delivered payloads. A
// delivered queue row is already excluded from every future delivery claim;
// transport recovery reads its immutable admission, not its former payload.
func PruneDuplexRelayMessages(ctx context.Context, pool *pgxpool.Pool, scope, domain, epoch string, now time.Time, dryRun bool) (Result, error) {
	return pruneDuplexRelayMessages(ctx, pool, scope, domain, epoch, now, dryRun, true)
}

func pruneDuplexRelayMessages(ctx context.Context, pool *pgxpool.Pool, scope, domain, epoch string, now time.Time, dryRun, delivered bool) (Result, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback(context.Background())
	state, err := authority.Lock(ctx, tx, authority.Request{ScopeID: scope, DomainID: domain, ExpectedWriterEpoch: epoch, RequireContinuousHistory: true})
	if err != nil {
		return Result{}, err
	}
	result := Result{Name: "expired_duplex_relay_messages", DryRun: dryRun}
	if delivered {
		result.Name = "retired_duplex_relay_payloads"
	}
	// Only queue rows are locked. Current-history evidence is retained forever,
	// and a busy delivery transaction must not stall unrelated reclamation.
	candidates := `SELECT m.id FROM iscp_relay.messages m
 WHERE m.domain_id=$1 AND (m.expires_at<=$2 OR ($5 AND m.delivered_at IS NOT NULL))
 AND EXISTS(SELECT 1 FROM iscp_relay.admissions a WHERE a.domain_id=m.domain_id
   AND a.message_id=m.message_id AND a.scope_id=$3 AND a.history_id=$4)
 ORDER BY m.expires_at,m.id LIMIT 256 FOR UPDATE OF m SKIP LOCKED`
	if dryRun {
		err = tx.QueryRow(ctx, `SELECT count(*) FROM (`+candidates+`) batch`, domain, now, scope, state.HistoryID, delivered).Scan(&result.WouldDelete)
	} else {
		tag, e := tx.Exec(ctx, `WITH batch AS (`+candidates+`)
 DELETE FROM iscp_relay.messages m USING batch WHERE m.id=batch.id`, domain, now, scope, state.HistoryID, delivered)
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
