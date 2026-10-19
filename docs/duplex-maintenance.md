# Duplex history maintenance and qualification

This implementation uses the frozen key `(domain_id, message_id)`. It never repairs an unknown history by changing a device, domain, history identifier, or key namespace. Normal startup does not activate history. Deploying or cutting over an existing environment remains an operator action.

## Fresh domains

Only an independently attested never-served domain may use:

```sh
iscp-relay-maintenance bootstrap-empty --relay-id RELAY --domain-id DOMAIN \
  --history-id HISTORY --evidence-sha256 GENESIS_EVIDENCE_DIGEST --confirm-never-served
```

The command obtains its database URL from `ISCP_DATABASE_URL`. An empty database is not proof of a never-served domain; old cleanup can remove both queue rows and delivery receipts.

## Existing legacy domains

The following is a preparation procedure, not authorization to execute it on a deployment.

1. Stop ingress, all legacy writers, and their cleanup processes. Retain the old database backup, queues, receipts, unknown client operations, and original enrollment identities.
2. Use a distinct database role for the new writer. Retire every old writer role: `NOLOGIN`, no elevated privileges, no table mutation privileges, no login role able to assume it, and no surviving sessions. Revoke credentials outside this tool; it never guesses which roles may be disabled.
3. Commit `prepare-legacy-cutover --relay-id RELAY --domain-id DOMAIN`. This installs an **incomplete**, write-disabled maintenance boundary. It refuses to replace an existing continuous history or another domain's scope.
4. Independently audit the full historical message-key inventory, including keys that old cleanup already deleted. Retain the source checkpoint evidence. A database scan alone is insufficient. If that evidence cannot be obtained, keep the domain in maintenance; this package does not offer a safe automatic cutover for it.
5. Save the reviewed evidence manifest as UTF-8 JSON. Hash its exact file bytes with SHA-256 and encode the digest as unpadded base64url. The manifest fields are:

```json
{
  "version": 1,
  "scope_id": "RELAY",
  "domain_id": "DOMAIN",
  "history_id": "BASE64URL_32_BYTES",
  "expected_writer_epoch": "1",
  "complete_key_history": true,
  "source_checkpoint_sha256": "BASE64URL_32_BYTES",
  "retired_writer_roles": ["retired_writer"],
  "legacy_message_ids": ["all-legacy-keys-including-cleaned-keys"]
}
```

6. Run `activate-legacy-cutover --relay-id RELAY --domain-id DOMAIN --evidence-file MANIFEST --evidence-sha256 EXACT_FILE_DIGEST --confirm-complete-history`. The explicit operator assertion covers completeness of the independent source; the program verifies file integrity, schema, every retained database key, role/session fences, and expected maintenance epoch. Failure leaves the separately committed incomplete boundary in place.
7. Restart only the compatible new Relay with its persistent signer and new writer role. Activation increments the writer epoch, permanently fencing pre-maintenance processes. Recover credentials through the control plane; legacy tokens with no credential generation are not upgraded by this command.

Activation reserves the complete audited key inventory as legacy tombstones. These keys return `unknown/legacy_record`, never `absent`. It neither imports business requests nor creates new signed acceptance receipts. Original old queue bytes and delivery receipts remain in place; the duplex delivery and cleanup jobs operate only on messages with v0.3 admission records. The open namespace retains immutable admission tombstones indefinitely.

The source audit cannot be inferred or manufactured by the CLI. An empty or incomplete manifest is not a remedy for missing historical evidence. Do not clear tables, substitute new identities, or alter the key semantics to make activation succeed.

## Qualification evidence and limits

The focused Go tests exercise the real PostgreSQL repository and raw independent WebSocket client:

- `TestDuplexWireExactByteLimits`: exact 1 MiB envelope and 1088 KiB whole-frame limits, each at minus one, exact, and plus one byte.
- `TestDuplexEightDayTombstoneAndMissingHistory`: an admission explicitly timestamped eight days earlier, production guarded payload cleanup, byte-identical expired receipt, unknown query and rejected new admission when history becomes incomplete. This is a clock-boundary test, not a claim to have waited eight calendar days.
- `TestDuplexPublicRevocationUsesSharedAuthority`: public operator revocation waits for the current disclosure guard, then atomically revokes credentials and closes the owner.
- `TestDuplexCrossOwnerUnfinishedCommitCannotProveAbsence`: an unfinished original transaction blocks new ownership; timeout does not install a new owner or prove absence; eventual commit is returned by the original-key query.
- `SC_RELAY_LONG_QUALIFICATION=1`: 57 seconds of empty healthy socket, actual credential generation/token rotation on the same owner, then network reconnection and original receipt reconciliation. Queued byte and frame counts remain zero during idle.
- `SC_RELAY_RESTART_QUALIFICATION=1`: creates its own PostgreSQL 18 container and persistent volume, restarts that database instance, reconstructs the compatible Relay with its original signer, and compares the original signed receipt byte for byte. The test removes only its own container and volume. It never restarts `SC_RELAY_TEST_DSN`'s server.
- `SC_RELAY_LATENCY_QUALIFICATION=1`: 100 independent raw-WebSocket samples with 3000-byte ciphertext, recording send-to-receipt, actual SQL COMMIT, and separately measured complete admission transaction (authority locks and signing included). `SC_RELAY_LATENCY_REPORT` optionally saves the measured JSON; these are local transport/database observations, not native UI paint timing.
- `TestLegacyCutoverRequiresCompleteEvidenceAndRetiredWriter`: LOGIN, active session, retained write privilege, incomplete inventory, and omitted database key all block activation. Complete external inventory preserves deleted keys as unknown and old ciphertext unchanged.

The PostgreSQL tests otherwise require an isolated `SC_RELAY_TEST_DSN` and create independent databases. The existing old-binary test uses the actual pre-change executable and demonstrates database rejection of its writes after activation.

No previous release has been qualified as a rollback binary against the new schema. If the compatible package cannot restart safely, remain in maintenance. The current-compatible-code/database restart test is evidence for restart recovery only; it is not proof of an older-version rollback. Five-node production deployment and actual legacy production history audits have not been performed by these tests.

## Coverage after retiring the split transport fixtures

Positive tests specific to the retired `POST /envelopes` plus receive-drain transport were replaced, rather than enabling a production fallback. Still-applicable security and session behavior maps to the following current tests:

| Retained behavior | Current test evidence |
| --- | --- |
| Relay descriptor signature, domain and signer/TLS pin | `TestSignedRelayDiscoveryPinnedCloudRoot`, `TestLocalRelaySignatureDomainAndSignerPin`, `TestNodeTLSCertificateCannotTrustUnknownReplacement` |
| Signed acceptance and exact original tuple | `TestAcceptanceSignatureAndOriginalBinding`, `TestDuplexPostgresBidirectionalAdmissionQueryAndFences` |
| Fresh connection-bound proof, replay/time validity | `TestDuplexReadinessRequiresFreshProof`, `TestDuplexCandidateAuthenticationReplaysAndTime`, live cross-connection proof replay in `TestDuplexPostgresBidirectionalAdmissionQueryAndFences` |
| Actual initial authentication timeout | `TestDuplexAuthenticationChallengeTimeoutCannotBecomeReady`: real 10-second server deadline, later validly signed proof cannot create an owner |
| Scope revision and rotated credential fences | `TestDuplexPostgresBidirectionalAdmissionQueryAndFences`, `TestCredentialScopeSnapshotDoesNotDisconnectNewOwner` |
| Owner replacement and unfinished transaction | `TestDuplexPostgresBidirectionalAdmissionQueryAndFences`, `TestDuplexCrossOwnerUnfinishedCommitCannotProveAbsence` |
| Socket timeout cannot release guarded data later | `TestDuplexTimedOutQueuedWriteCannotOutliveAuthority` |
| Healthy idle and dead socket liveness | `TestRelayIdlePingTrafficExtendsLivenessDeadline`, `TestRelaySilentConnectionStillTimesOut`, opt-in `TestDuplexLongIdleRealCredentialRotationAndReconnect` |
| Original-key crash/reconnect recovery, FIFO, no duplicate callback | `TestDuplexPostgresClientCallbackMayWaitForReceipt`, `TestRelayJournalCancellationBetweenCheckpointAndFutureCompletion`, `TestReceiptConsumedNormallyPrunesButConcurrentUnknownSurvives` |
| Durable immutable admission and actual old writer rejection | `TestDuplexPostgresBidirectionalAdmissionQueryAndFences` invokes the pre-change executable against the upgraded database and verifies no message overwrite |
| Retired drain frame cannot be treated as v0.3 | `TestRelayRejectsRetiredDrainFrame` |

These names identify the new transport tests. Legacy-route positive tests are not cited as v0.3 evidence, and elapsed-time boundary tests are distinguished from actual calendar-duration or production deployment evidence.
