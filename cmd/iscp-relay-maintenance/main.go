// Operator-only maintenance; normal service startup never activates history.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"github.com/jackc/pgx/v5"
	"os"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 || os.Args[1] != "bootstrap-empty" {
		return fmt.Errorf("usage: iscp-relay-maintenance bootstrap-empty --relay-id ID --domain-id ID --history-id ID --evidence-sha256 HASH --confirm-never-served (ISCP_DATABASE_URL required)")
	}
	f := flag.NewFlagSet("bootstrap-empty", flag.ContinueOnError)
	scope := f.String("relay-id", "", "Relay writer scope")
	domain := f.String("domain-id", "", "new domain")
	history := f.String("history-id", "", "persistent base64url history ID")
	evidence := f.String("evidence-sha256", "", "base64url SHA256 of independent genesis evidence")
	attest := f.Bool("confirm-never-served", false, "attest newly created domain has never served traffic; empty tables are insufficient")
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, e := pgx.Connect(ctx, os.Getenv("ISCP_DATABASE_URL"))
	if e != nil {
		return e
	}
	defer conn.Close(context.Background())
	tx, e := conn.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	if e = authority.BootstrapEmpty(ctx, tx, *scope, *domain, *history, *evidence, *attest); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
