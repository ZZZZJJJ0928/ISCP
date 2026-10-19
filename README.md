# ISCP

[![CI](https://github.com/Infinimesh-ai/ISCP/actions/workflows/ci.yml/badge.svg)](https://github.com/Infinimesh-ai/ISCP/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

ISCP, the Interoperable Secure Connectivity Protocol, is a protocol-first
implementation of secure device identity, trust authorization, relay delivery,
and end-to-end encrypted session messaging.

This fork includes the [SparkClaw transport and authorization baseline](docs/sparkclaw-baseline.md)
from `cf9b81de`: continuous Relay receive, application streams, node/local issuers,
credential recovery, control peers and the SparkX helper. Generic components live
in `pkg/`; SparkClaw-specific bindings live in `extensions/sparkclaw/`.
Transport still uses HTTP submission plus continuous WebSocket receive. Duplex
WebSocket is subsequent design work. Imported source retains the licensing and
provenance recorded in [NOTICE](NOTICE).

## Origin

ISCP began inside Infinimesh as the Infinimesh Secure Connectivity Protocol, a
core infrastructure layer for private intelligent systems. As the design
matured, Infinimesh chose to make the protocol independent and public: a
connectivity foundation trusted enough for private deployments should also be
open enough to audit, implement, and interoperate across vendors and
environments.

That is why ISCP is now developed as the Interoperable Secure Connectivity
Protocol.

## What Is Included

- Protocol specifications and JSON Schemas for ISCP v2 objects.
- Go Core SDK packages for identity, proofs, descriptors, trust grants,
  sessions, envelopes, payloads, provisioning, errors, storage, and logging.
- Go Server SDK packages for HTTP helpers, policy, PostgreSQL repositories,
  rate limiting, replay protection, queueing, audit logs, and key boundaries.
- Relay Reference Service for opaque message delivery.
- Trust Root Reference Service for device authorization, trust grants, and
  revocation checks.
- CLI workflows for local demos, conformance, descriptor/proof/session/envelope
  commands, and operator checks.
- PostgreSQL 18 migrations, Docker Compose, Helm baseline, OpenAPI 3.1,
  conformance vectors, release gates, and operations documentation.

## Security Model

ISCP keeps relay access, trust authorization, and payload confidentiality as
separate boundaries:

- Device long-term identity private keys are generated and stored on the device
  side only.
- Trust Grants must be signed by the Trust Root and validated against audience,
  confirmation, permissions, relay constraints, expiry, and revocation state.
- Relay envelope submission requires a valid access credential bound to the
  envelope sender device.
- Trust Root operator actions and Relay admin APIs require an admin credential in
  production profile.
- Relay services handle opaque envelopes and do not hold end-to-end session
  keys.
- `session.ready` key confirmation is required before business payload
  delivery.
- Production profile blocks unsigned descriptors, bearer-only relay access, and
  plaintext debug behavior.
- Logs, errors, audit records, panic output, and CLI output must not disclose
  private keys, access tokens, refresh credentials, session keys, or plaintext
  payloads.

See [SECURITY.md](SECURITY.md) and
[docs/security/release-gates.md](docs/security/release-gates.md) for the full
release gate policy.

## Repository Layout

```text
spec/                         Protocol specifications
schemas/json/                 JSON Schemas for iscp.*.v2 objects
pkg/iscp/                     Go Core SDK packages
pkg/server/                   Go Server SDK packages
services/relay-reference/     Relay Reference Service
services/trust-root-reference/ Trust Root Reference Service
tools/iscp-cli/               CLI entry point
conformance/                  Conformance runner and vectors
deploy/                       Compose, migrations, and Helm baseline
docs/                         API, operations, decisions, release, security
scripts/                      Local and CI automation
examples/                     Device/watch simulator examples
```

## Requirements

- Go 1.25.x.
- Bash for Linux/macOS repository scripts.
- PowerShell 7 or Windows PowerShell for the Windows-compatible script entry
  points.
- Docker, when running the reference services or when the scripts need their Go
  fallback runtime.

The Linux/macOS and PowerShell scripts use a local `go` binary when available.
If Go is not installed, they fall back to `docker run --rm golang:1.25`.

## Quick Start

Run the test suite:

```bash
./scripts/test.sh
```

Run formatting and static checks:

```bash
./scripts/lint.sh
```

Start the reference environment:

```bash
docker compose -f deploy/docker-compose/docker-compose.yaml up --build
```

Default local endpoints:

- Relay: `http://localhost:8080`
- Trust Root: `http://localhost:8081`
- PostgreSQL: `localhost:5432`

If those ports are busy, override only the host bindings:

```bash
export ISCP_BIND_ADDR="127.0.0.1"
export ISCP_POSTGRES_PORT="55435"
export ISCP_RELAY_PORT="9080"
export ISCP_TRUST_PORT="9081"
docker compose -f deploy/docker-compose/docker-compose.yaml up --build
```

Run the local end-to-end demo:

```bash
go run ./tools/iscp-cli/cmd/iscp demo local-e2e
```

Run conformance:

```bash
export ISCP_RELAY_ENDPOINT="http://127.0.0.1:9080"
export ISCP_TRUST_ENDPOINT="http://127.0.0.1:9081"
./scripts/conformance.sh
```

## CLI

Run the CLI from source:

```bash
go run ./tools/iscp-cli/cmd/iscp --help
```

Install it from the repository module:

```bash
go install github.com/Infinimesh-ai/ISCP/tools/iscp-cli/cmd/iscp@latest
```

## Documentation

- [Documentation index](docs/README.md)
- [Protocol specifications](spec/protocol.md)
- [OpenAPI document](docs/api/openapi.yaml)
- [Event catalog](docs/api/events.md)
- [Installation notes](docs/operations/install.md)
- [PostgreSQL operations](docs/operations/postgres.md)
- [Release checklist](docs/release/checklist.md)
- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Release Validation

The full local release gate runs tests, conformance, secret scanning,
vulnerability scanning, static security checks, OpenAPI/schema/traceability
validation, PostgreSQL and Helm validation, SBOM generation, service startup,
and release-report validation:

```bash
./scripts/release-gate.sh
```

The gate writes reproducible local evidence under `dist/` and
`conformance/report.json`. Those files are generated artifacts and are ignored
by Git.

The PostgreSQL gate covers durable proof nonce replay rejection and persistent
Relay queue claim/lease behavior, which are required for multi-instance or
restart-tolerant deployments.

Windows users can run the equivalent `.ps1` scripts from PowerShell.

## Non-Goals

- No Web UI or admin static asset bundle.
- No mobile app store release flow or full mobile UI.
- No relay-side decryption of business payloads.
- No hard-coded IMMS, Infinimesh Cloud, or other vendor service endpoints in
  protocol objects, Core SDK, or reference service core logic.

## License

ISCP is released under the [MIT License](LICENSE).
