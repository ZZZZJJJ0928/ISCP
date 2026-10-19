package iscpnodeissuer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/url"
	"os"
	"os/exec"
	"testing"
)

func TestControlIssuerOldExecutableAndStaleEpochCannotOverwrite(t *testing.T) {
	dsn := os.Getenv("SC_ISCP_NODE_TEST_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = "postgres"
	admin, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	database := "iscp_issuer_writer_" + hex.EncodeToString(c.RandomBytes(8))
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)")
	cfg.ConnConfig.Database = database
	databaseURL, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	databaseURL.Path = "/" + database
	isolatedDSN := databaseURL.String()
	key := c.RandomBytes(32)
	store, err := NewPostgresStore(ctx, isolatedDSN, key)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	old, err := NewPostgresStore(ctx, isolatedDSN, key)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	binary := os.Getenv("SC_ISCP_NODE_OLD_TEST_BINARY")
	if binary == "" {
		binary = "/Users/dev/.cache/sparkclaw-iscp-parallel-20261019/baseline-iscp-nodeissuer.test"
	}
	executable, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("baseline executable required for this test:", err)
	}
	digest := sha256.Sum256(executable)
	if fmt.Sprintf("%x", digest) != "53a7947e6c305cd876c426ca88ed6a07364501a812b4840525856831cdd29cd2" {
		t.Fatal("unexpected baseline issuer executable")
	}
	runBaseline := func() ([]byte, error) {
		command := exec.Command(binary, "-test.run=^TestPostgresEncryptedRestartAndConcurrentConsumption$", "-test.count=1")
		command.Env = append(os.Environ(), "SC_ISCP_NODE_TEST_DSN="+isolatedDSN)
		return command.CombinedOutput()
	}
	// Prove the exact historical executable and database pass before enabling
	// the fence; a crypto key mismatch must not stand in for a writer rejection.
	if output, err := runBaseline(); err != nil || !bytes.Contains(output, []byte("PASS")) {
		t.Fatalf("unfenced old executable control failed: %v %s", err, output)
	}
	if err = store.ActivateControlWriter(ctx, "1", c.Base64URL(c.RandomBytes(32))); err != nil {
		t.Fatal(err)
	}
	if err = store.ConfigureControlWriter(ctx, "1"); err != nil {
		t.Fatal(err)
	}
	id := "v2-protected-" + hex.EncodeToString(c.RandomBytes(8))
	if err = store.Create(ctx, id, &State{State: "active", Revision: 1, Control: newControlState()}); err != nil {
		t.Fatal(err)
	}
	var before []byte
	if err = store.pool.QueryRow(ctx, "SELECT ciphertext FROM sparkclaw_iscp_issuer_state WHERE id=$1", id).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err = old.Update(ctx, id, func(s *State) error { s.Control = nil; return nil }); err != ErrWriterFenced {
		t.Fatalf("old process adopted epoch: %v", err)
	}
	output, err := runBaseline()
	if err == nil || !bytes.Contains(output, []byte("issuer temporarily unavailable")) {
		t.Fatalf("old executable unexpectedly passed the activated writer boundary: %v %s", err, output)
	}
	var after []byte
	if err = store.pool.QueryRow(ctx, "SELECT ciphertext FROM sparkclaw_iscp_issuer_state WHERE id=$1", id).Scan(&after); err != nil || !bytes.Equal(before, after) {
		t.Fatal("old executable changed encrypted aggregate", err)
	}
	if _, err = store.pool.Exec(ctx, "UPDATE sparkclaw_iscp_issuer_writer SET writer_epoch=2"); err != nil {
		t.Fatal(err)
	}
	if err = store.Update(ctx, id, func(*State) error { return nil }); err != ErrWriterFenced {
		t.Fatalf("stale new process adopted next epoch: %v", err)
	}
}
