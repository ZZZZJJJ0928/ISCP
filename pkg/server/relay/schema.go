package iscprelayreference

import (
	"context"
	_ "embed"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var receiveSchema string

// PrepareDatabase adds the local receive-path index after the pinned upstream
// migrations. It preserves every receipt and the original delivery transaction.
// On a running large database, operators can create the same index CONCURRENTLY
// before upgrading; startup then verifies it without rebuilding it.
func PrepareDatabase(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, receiveSchema); err != nil {
		return err
	}
	var valid bool
	if err := pool.QueryRow(ctx, `SELECT indisvalid FROM pg_index
WHERE indexrelid = 'iscp_relay.idx_sparkclaw_receipts_queued_message'::regclass`).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return errors.New("Relay queued receipt index is invalid; complete database index maintenance before startup")
	}
	return nil
}
