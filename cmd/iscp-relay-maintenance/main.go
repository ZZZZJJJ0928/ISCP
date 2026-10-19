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
	if len(os.Args) < 2 || (os.Args[1] != "bootstrap-empty" && os.Args[1] != "prepare-legacy-cutover" && os.Args[1] != "activate-legacy-cutover") {
		return fmt.Errorf("usage: iscp-relay-maintenance {bootstrap-empty|prepare-legacy-cutover|activate-legacy-cutover} --relay-id ID --domain-id ID (ISCP_DATABASE_URL required). Existing domains require independently audited complete legacy keys, stopped/privilege-fenced old writers and a separately committed prepare step; insufficient evidence stays incomplete in maintenance. Never clear old queues or change identity to bypass this boundary.")
	}
	f := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	scope := f.String("relay-id", "", "Relay writer scope")
	domain := f.String("domain-id", "", "domain (never reused or changed to bypass historical uncertainty)")
	history := f.String("history-id", "", "persistent base64url history ID")
	evidence := f.String("evidence-sha256", "", "base64url SHA256 of independent genesis evidence")
	manifestPath := f.String("evidence-file", "", "audited legacy key manifest; includes keys removed by old cleanup")
	complete := f.Bool("confirm-complete-history", false, "operator attests independent source checkpoint proves complete historical key inventory; empty database is insufficient")
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
	switch os.Args[1] {
	case "bootstrap-empty":
		e = authority.BootstrapEmpty(ctx, tx, *scope, *domain, *history, *evidence, *attest)
	case "prepare-legacy-cutover":
		e = authority.PrepareLegacyCutover(ctx, tx, *scope, *domain)
	case "activate-legacy-cutover":
		st, err := os.Stat(*manifestPath)
		if err != nil {
			return err
		}
		if st.Size() > 64<<20 {
			return fmt.Errorf("cutover evidence exceeds 64 MiB")
		}
		raw, err := os.ReadFile(*manifestPath)
		if err != nil {
			return err
		}
		manifest, err := authority.ParseLegacyCutoverEvidence(raw, *evidence)
		if err != nil {
			return err
		}
		if manifest.ScopeID != *scope || manifest.DomainID != *domain {
			return fmt.Errorf("manifest does not match requested Relay/domain")
		}
		e = authority.ActivateLegacyCutover(ctx, tx, manifest, *evidence, *complete)
	}
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
