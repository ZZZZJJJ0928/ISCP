# Relay data retention

Language: English | [简体中文](../zh-cn/docs/relay-retention.md)

Relay storage separates disposable delivery payloads from the evidence needed to
reject duplicate operations. This policy preserves `iscp.relay.duplex.v1` and the
original signed receipt returned by `submit.query`.

| Data | Retention |
| --- | --- |
| Queue envelope after a committed successful transport write | Eligible for the next cleanup pass; no receiver acknowledgement or redelivery is implied |
| Undelivered queue envelope | Until `expires_at`; never extend its deadline |
| Admission key, matching fields and original signed `receipt_raw` | Retain while the namespace admits requests, including after payload expiry |
| Duplicate admission `receipt_canonical` JSON | Removed by migration 7; no reader requires this copy |
| Unresolved control operations, credential history and authorization evidence | Retain under their existing recovery rules; payload cleanup does not remove them |

The Relay runs cleanup at startup and every 15 seconds. A pass processes at most
eight independently committed batches of 256 queue rows within a five-second
budget. Locked delivery rows are skipped. Every batch checks the original writer
epoch/role and continuous history, then only removes queue rows with an admission
in that same scope/history. Legacy or unexplained rows are not silently discarded.
A later timeout cannot roll back an earlier committed batch.

The private `/metrics` endpoint exposes
`iscp_relay_payload_cleanup_{runs_total,batches_total,deleted_total,errors_total,last_success_unixtime}`.
Errors produce a generic warning without payloads or credentials. Monitor stalled
success timestamps, growing eligible backlog, relation bytes and filesystem free
space together. The interval is a scheduling target, not a hard maximum age during
database unavailability; failed passes retry without weakening the writer fence.

Admission evidence is deliberately smaller than a message body, but its key count
still grows. Never impose an arbitrary TTL on an open namespace's unique keys:
that would let an old message ID be accepted again. Further compaction must retain
the same original receipt and matching semantics. Deleting deduplication evidence
requires permanent namespace closure and fenced writers under the existing contract.

Migration 7 drops a redundant physical column. Stop Relay writers, preserve a
database checkpoint and the original receipt fingerprints, apply the migration,
then run a binary that no longer inserts that column. Pre-migration binaries are
not direct rollback targets. Dropping a column does not itself reclaim existing
heap space. Normal autovacuum makes deleted space reusable; any one-time
`VACUUM FULL` needs an explicit maintenance window, sufficient rewrite/WAL space,
and post-maintenance receipt/identity checks. Do not schedule repeated full-table
rewrites as ordinary expiration processing.

Credential/control-result compaction is a separate lifecycle change: historical
tokens participate in generation/routing, and completed control results still
need digest, maximum credential lifetime, predecessor and pending-ACK evidence.
Do not delete those rows merely because one token expiry has passed.
