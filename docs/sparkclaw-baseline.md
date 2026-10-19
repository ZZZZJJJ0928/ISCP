# SparkClaw baseline in the ISCP fork

[简体中文](../zh-cn/docs/sparkclaw-baseline.md)

This fork starts from ISCP `47f1f6c231c56c92eff6b6c5d398e037ebcf9602`
and imports the transport implementation from SparkClaw
`cf9b81dec39b8872efc43650080bb8facaa58511`. The source repository is
[Infinimesh-ai/SparkClaw](https://github.com/Infinimesh-ai/SparkClaw).
It is a development baseline for [this fork](https://github.com/ZZZZJJJ0928/ISCP),
not an upstream protocol release. SparkClaw's source dependency was
`github.com/Infinimesh-ai/ISCP v0.2.0-rc.1`.

## What is included

| Location | Responsibility |
| --- | --- |
| `pkg/server/relay` | Current Relay implementation: continuous receive, independent heartbeat, durable queue claims, failed-write rollback, revocation, persistent signer and managed-authority hook |
| `pkg/iscp/appstream` | Generic optional application frames, subscription identifiers, sequence validation, cancellation and completion decoding |
| `schemas/candidates/application-stream.v1.json` | Unchanged application-stream candidate schema; its original ID and candidate status are retained |
| `extensions/sparkclaw/iscpauth` | Standing authorization, scope and grant policy |
| `extensions/sparkclaw/iscpbridge` | Portable configuration, enrollment, credential recovery, Relay clients, identity and grant validation |
| `extensions/sparkclaw/iscplocalenroll`, `iscplocalissuer` | Local enrollment and issuer, including renewal, reauthorization and deletion |
| `extensions/sparkclaw/iscpnodeclient`, `iscpnodeissuer`, `iscpnodecontrol` | Node enrollment, persistent encrypted authority state, proof-bound control peers and recovery |
| `extensions/sparkclaw/iscprelayadapter` | PostgreSQL authority transactions, service recovery, device isolation and multi-authority routing |
| `extensions/sparkclaw/iscpworkbench` | Desktop helper RPC, encrypted application streams, authorization checks and cancellation |
| `extensions/sparkclaw/protocol` | SparkClaw bridge/execution schemas, fixtures and desktop operation projection |
| `cmd/iscp-*` | Seven standalone commands, listed below |

The existing reference executable `services/relay-reference/cmd/relayd` now uses
`pkg/server/relay`. The superseded private reference implementation was removed;
its existing tests are retained in the imported Relay tests. Go package names,
wire names and environment variable names remain unchanged to keep the import
mechanical.

## Behavior at this baseline

Envelope submission still uses HTTP `POST /v2/relay/envelopes`. A device receives
continuously over `GET /v2/relay/connect` after the existing challenge/READY
exchange. The old fixed 55-second receive window is gone. Idle heartbeat handling
does not block queued data. Device replacement, revocation, shutdown and failed
writes are covered by the imported receive tests. A receive socket is not a
persistent application subscription: application completion, renewal and ACK
rules remain separate from the Relay connection lifetime.

Authorization still distinguishes Relay access, device proof of possession,
end-to-end grants and application scopes. The import preserves enrollment,
renewal, revocation, permanent-authorization revisions, recovery receipts,
encrypted issuer storage and the current credential expiration checks. It does
not add WebSocket submission, change cryptographic formats, or promise new
delivery guarantees. Full duplex transport is the next design change.

The optional `POST /api/sparkclaw/iscp-control/v1/service-recover` route is a
SparkClaw profile extension. It requires the configured managed adapter and a
preapproved service identity; it cannot enroll or revive a device. Ordinary
reference deployments without that adapter return 404.

## Build and run

Use Go 1.25.5 or newer in the 1.25 series. No SparkClaw checkout, external Go
workspace or local module replacement is needed:

```sh
GOWORK=off go build ./...
GOWORK=off go test ./...
GOWORK=off go vet ./...
GOWORK=off go run ./services/relay-reference/cmd/relayd
```

The reference command defaults to the existing local-lab profile. Its optional
`ISCP_RELAY_SIGNER_FILE` enables the imported signer persistence. The production
`iscp-public-relay` command retains SparkClaw's `ISCP_SIGNER_FILE` name and requires
persistent PostgreSQL state plus its existing production configuration. Review
and explicitly supply domain, Relay URL, identity, authority and private paths;
the imported command's historical deployment defaults are not a new deployment.

| Command | Purpose |
| --- | --- |
| `go build ./cmd/iscp-public-relay` | Production Relay and managed transaction sockets |
| `go build ./cmd/iscp-control-forwarder` | Encrypted issuer/control peer forwarding |
| `go build ./cmd/iscp-node-issuer` | Node authority and invitation management |
| `go build ./cmd/iscp-node-provision` | Device initialization and operator provisioning |
| `go build ./cmd/iscp-local-issuer` | Private local-test issuer |
| `go build ./cmd/iscp-local-enroll` | Local enrollment and pinned credential refresh |
| `go build ./cmd/iscp-workbench` | Desktop helper over its existing stdin/stdout protocol |

Production configuration and credentials are intentionally not included. The
baseline has been built on macOS arm64 and cross-built for Linux amd64. Native
keyring behavior and deployed environments still require their own integration
acceptance.

## Verification and provenance

`extensions/sparkclaw/baseline-manifest.json` records 159 source/target mappings,
three extractions, source and target SHA-256 values, fixed revisions, excluded
business files and import/fixture path changes. The extracted helpers preserve
their original function bodies and constants. Only two tests for excluded
Gateway business adapters were removed from the mixed bridge contract test.

```sh
python3 scripts/verify-sparkclaw-baseline.py
# Optional independent replay against the pinned source commit:
python3 scripts/verify-sparkclaw-baseline.py --source /path/to/SparkClaw
node scripts/sync-iscp-operations.mjs --check
```

The manifest describes this historical import. Intentional future edits will
report baseline drift; do not regenerate its hashes to conceal subsequent
changes. The operation registry remains the source for generated Go constants
and the desktop projection; run `node scripts/sync-iscp-operations.mjs` after an
intentional registry change.

For a disposable PostgreSQL database, run:

```sh
SC_RELAY_TEST_DSN="$TEST_DATABASE_URL" SC_RELAY_LONG_TEST=1 \
  GOWORK=off go test -race -count=1 ./...
SC_ISCP_NODE_TEST_DSN="$TEST_DATABASE_URL" \
  GOWORK=off go test -p 1 -race -count=1 \
  ./extensions/sparkclaw/iscpnodeclient ./extensions/sparkclaw/iscpnodeissuer
```

The database role needs permission to create temporary databases. Never point
these integration tests at deployed state. The node fixture packages share a
schema and must run serially (`-p 1`) to avoid concurrent DDL initialization.
CI includes both PostgreSQL test paths and the test that receives after the
former 55-second boundary. Recorded import results are in
`extensions/sparkclaw/baseline-validation.json`.

Functional checks do not imply release security approval. At import time,
`govulncheck` reports reachable advisories GO-2026-6629 and GO-2026-5970 in the
source-pinned `golang.org/x/text v0.38.0`; gosec reports 28 findings requiring
triage. These dependencies and function bodies were preserved for this baseline,
and the existing release gate is retained without suppressions. A separate
security update and review are required before claiming a release-ready fork.

## Ownership and next changes

SparkClaw's Agent runtime, UI, business storage, Gateway handlers and original
phone bridge business service remain in SparkClaw. This import does not switch
SparkClaw's module pin or change any running Relay, database or installed client.
The framework still contains its previous transport copy until a separate
consumer migration pins this fork and replaces the relevant imports.

Develop transport, Relay and authorization changes here. Keep SparkClaw-specific
bindings under `extensions/sparkclaw`; promote shared candidates only through
the protocol decision process. Preserve the upstream Go module path for
compatibility, and pin the fork explicitly when consumers adopt a release.
`origin` is the personal fork; `upstream` is `Infinimesh-ai/ISCP`.

The original ISCP MIT license and imported SparkClaw Apache-2.0 license are
retained. See [NOTICE](../NOTICE) and
`extensions/sparkclaw/SPARKCLAW_LICENSE.txt`; importing code does not relicense it.
