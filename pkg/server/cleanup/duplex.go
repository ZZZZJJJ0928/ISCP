package cleanup

import (
	"context"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
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
	result, err := ExpiredRelayMessages(ctx, tx, repository.DomainID(domain), now, dryRun)
	if err != nil {
		return Result{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Result{}, err
	}
	return result, nil
}
