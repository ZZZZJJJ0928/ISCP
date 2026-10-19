# Relay Protocol

Relay is a zero-knowledge message transport boundary. It authenticates relay
access, routes opaque envelopes, stores offline queues, and emits relay receipts.

## REST API

- `GET /.well-known/iscp/relay`
- `POST /v2/relay/devices/bind-self`
- `POST /v2/relay/devices/register-with-ticket`
- `POST /v2/relay/devices/refresh-access`
- `POST /v2/relay/devices/revoke-access`
- `POST /v2/relay/envelopes`
- `GET /v2/relay/admin/devices`
- `GET /v2/relay/admin/connections`
- `GET /v2/relay/admin/messages`

Optional device lifecycle endpoints, offered by deployments that operate the
relay and trust root together and advertised via relay descriptor `metadata`
capability keys (see spec/device-lifecycle.md):

- `POST /v2/relay/devices/renew-grant` (optional)
- `POST /v2/relay/devices/auto-renew-grant` (optional)
- `POST /v2/relay/devices/recover-credentials` (optional)
- `POST /v2/relay/devices/repair-recovery-anchor` (optional)

`bind-self` is the first-device bootstrap transport and is actor-authorized:
production deployments MUST gate it behind an external actor authorization in
addition to the device proof (spec/provisioning.md).

`register-with-ticket` consumes a signed pairing ticket. Production
deployments MUST require the full signed `iscp.pairing_ticket.v3` object,
verify its signature against the Trust Root, and require the device proof
challenge to equal the `ticket_id`; accepting a bare ticket identifier with a
self-reported challenge is a local-lab behavior. Ticket consumption enforces
the grant role invariants defined in spec/provisioning.md, including rejecting
consumption by the ticket's `grant_audience`.

Production Relay envelope submission requires both a bearer access credential
and proof of possession in `X-ISCP-Access-Proof`. The proof is a base64url
encoded `iscp.device.proof.v2` over this challenge:

```text
iscp/v2/relay/access-proof || NUL || METHOD || NUL || PATH || NUL || access_token_sha256_base64url
```

The proof audience is the Relay ID. The proof nonce is replay-protected.

## WebSocket API

- `GET /v2/relay/connect`

Connection state:

```text
CONNECTED -> CHALLENGE_SENT -> POP_VERIFIED -> READY -> CLOSED
```

Business envelopes are accepted only in READY state. Relay receipt confirms
relay handling only and does not imply E2E application receipt.

## Fork reference implementation baseline

The SparkClaw-aligned reference Relay in this fork continuously receives queued
and newly arriving envelopes on an authenticated connection, including when the
queue is empty. It does not emit `drained` after a batch or rotate a healthy
connection after 55 seconds. Ping/Pong runs independently of delivery. The
deployment no longer applies artificial request-rate or cumulative allowances.
Identity, authorization, message-size bounds and actual resource failures remain.

Envelope submission still uses the REST endpoint above. The receive socket does
not accept business submission frames. No duplex transport binding is introduced
by this baseline. See the [baseline scope and validation](../docs/sparkclaw-baseline.md)
for persistent signers, queued-receipt indexing and optional node-authority adapters.
