package iscprelayreference

import (
	"strings"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
)

func TestQueuedReceiptIndexPreservesHistoryAndBoundsDeliveryLookup(t *testing.T) {
	pool := receiveDatabase(t)
	ctx := t.Context()
	// A long retained history in one domain reproduces the production planner
	// choice. Distinct domains share a message ID to exercise the authority scope.
	_, err := pool.Exec(ctx, `INSERT INTO iscp_relay.delivery_receipts
(id,domain_id,receipt_id,message_id,relay_id,status,receipt_raw,receipt_canonical,issued_at)
SELECT md5(n::text)::uuid, 'domain-a', n::text, n::text, 'relay-a',
'delivered_to_connection', 'history'::bytea, 'history'::bytea, now()
FROM generate_series(1,20000) n;
INSERT INTO iscp_relay.delivery_receipts
(id,domain_id,receipt_id,message_id,relay_id,status,receipt_raw,receipt_canonical,issued_at)
VALUES
(md5('pending-a')::uuid,'domain-a','pending-a','target','relay-a','queued','original','original',now()),
(md5('pending-b')::uuid,'domain-b','pending-b','target','relay-a','queued','original','original',now()),
(md5('accepted-a')::uuid,'domain-a','accepted-a','target','relay-a','accepted','original','original',now());
ANALYZE iscp_relay.delivery_receipts`)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := func() string {
		t.Helper()
		var digest string
		if err := pool.QueryRow(ctx, `SELECT md5(string_agg(md5(row_to_json(r)::text), '' ORDER BY id))
FROM iscp_relay.delivery_receipts r`).Scan(&digest); err != nil {
			t.Fatal(err)
		}
		return digest
	}
	plan := func() string {
		t.Helper()
		var value string
		if err := pool.QueryRow(ctx, `EXPLAIN (FORMAT JSON)
UPDATE iscp_relay.delivery_receipts SET status='delivered_to_connection'
WHERE domain_id=$1 AND message_id=$2 AND status='queued'`, "domain-a", "target").Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if !strings.Contains(plan(), `"Seq Scan"`) {
		t.Fatal("fixture does not reproduce the unindexed history scan")
	}
	before := fingerprint()
	for range 2 {
		if err := PrepareDatabase(ctx, pool); err != nil {
			t.Fatal(err)
		}
	}
	if fingerprint() != before {
		t.Fatal("index preparation changed retained receipts")
	}
	indexed := plan()
	if !strings.Contains(indexed, "idx_sparkclaw_receipts_queued_message") || strings.Contains(indexed, `"Seq Scan"`) {
		t.Fatalf("delivery lookup still scans retained history: %s", indexed)
	}
	repo := repository.NewRelayRepository(pool)
	if err := repo.MarkMessageDelivered(ctx, repository.DomainID("domain-a"), "target", time.Now()); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"pending-a": "delivered_to_connection", "pending-b": "queued", "accepted-a": "accepted"} {
		var status, raw string
		if err := pool.QueryRow(ctx, `SELECT status,convert_from(receipt_raw,'UTF8')
FROM iscp_relay.delivery_receipts WHERE receipt_id=$1`, id).Scan(&status, &raw); err != nil {
			t.Fatal(err)
		}
		if status != want || raw != "original" {
			t.Fatalf("receipt %s changed outside original delivery semantics: %s, %s", id, status, raw)
		}
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM iscp_relay.delivery_receipts`).Scan(&count); err != nil || count != 20003 {
		t.Fatalf("retained receipt history changed: %d, %v", count, err)
	}
}
