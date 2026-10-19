# Security Baseline Traceability

This matrix tracks the release-gated requirements in
`spec/security-baseline.md`. A 95%+ protocol-readiness target requires every
MUST and MUST NOT to have executable evidence or an explicit blocking gap.

| ID | Requirement | Evidence | Status |
| --- | --- | --- | --- |
| ISCP-SB-001 | Devices MUST generate long-term identity private keys locally. | `pkg/iscp/identity.NewDevice`; `pkg/iscp/identity/identity_test.go` | Covered |
| ISCP-SB-002 | Provisioning agents MUST NOT generate, export, or persist new device long-term private keys. | `pkg/iscp/provisioning.ApplyBundle`; `pkg/iscp/provisioning/provisioning_test.go` | Covered |
| ISCP-SB-003 | Ed25519 long-term identity signing keys MUST NOT be reused as X25519 session agreement keys. | Typed key APIs in `pkg/iscp/crypto`; `pkg/iscp/crypto/crypto_test.go` | Covered |
| ISCP-SB-004 | Public key thumbprints MUST bind the key type and canonical public key bytes. | `pkg/iscp/crypto.Thumbprint`; identity/trust/session verification tests | Covered |
| ISCP-SB-005 | Relay Access MUST NOT be treated as Trust Authorization. | Separate Relay and Trust services, grants, and access credentials; service conformance workflows | Covered |
| ISCP-SB-006 | Relay MUST NOT hold E2E session keys. | Relay stores opaque envelopes only; relay response leakage tests | Covered |
| ISCP-SB-007 | Relay MUST NOT decrypt business payloads. | `pkg/server/relay`; conformance `P1-SVC-003` | Covered |
| ISCP-SB-008 | Relay MUST NOT forge a SecureEnvelope accepted by the receiver. | AEAD envelope authentication and route AAD tests | Covered |
| ISCP-SB-009 | Access revocation MUST invalidate refresh credentials and block new valid connections. | Relay revoke tests and conformance `P1-SVC-003` | Covered |
| ISCP-SB-010 | Relay MUST enforce message size, queue TTL, deadline, rate limit, quota, and backpressure policies. | `pkg/server/queue`; relay metadata validation; rate limiter; conformance `P1-FEAT-002` | Covered |
| ISCP-SB-011 | Trust Grants MUST be signed by the Trust Root. | `pkg/iscp/trust.SignGrant`; trust service tests | Covered |
| ISCP-SB-012 | Trust Grants MUST validate audience, confirmation key, permission, expiry, relay constraint, and revocation state. | `pkg/iscp/trust/trust_test.go`; conformance `P0-SEC-004` through `P0-SEC-009` | Covered |
| ISCP-SB-013 | Trust revocation MUST block new sensitive sessions. | Trust service revoke/verify tests and conformance `P1-SVC-004` | Covered |
| ISCP-SB-014 | Device record versions and revocation epochs MUST increase monotonically. | Trust repository and revoke flow tests | Covered |
| ISCP-SB-015 | Session keys MUST provide forward secrecy through ephemeral X25519. | `pkg/iscp/session.CreateHello`; session tests | Covered |
| ISCP-SB-016 | HKDF transcript input MUST bind both parties, both ephemeral keys, and the negotiated ciphersuite. | `pkg/iscp/session.TranscriptHash`; `pkg/iscp/session/session_test.go` | Covered |
| ISCP-SB-017 | Business payloads MUST NOT be delivered before `session.ready` key confirmation. | Envelope/session tests and conformance `P0-SEC-010` | Covered |
| ISCP-SB-018 | AEAD nonces MUST NOT repeat for the same direction and key. | Session sequence tracking and envelope replay tests | Covered |
| ISCP-SB-019 | SecureEnvelope AAD MUST bind route metadata. | `pkg/iscp/envelope`; conformance `P0-SEC-011` | Covered |
| ISCP-SB-020 | Route metadata tampering MUST fail AEAD authentication. | Envelope negative tests and conformance `P0-SEC-011` | Covered |
| ISCP-SB-021 | Production profile MUST reject unsigned descriptors. | `pkg/iscp/config`; descriptor tests; conformance `P0-SEC-002` | Covered |
| ISCP-SB-022 | Production profile MUST reject bearer-only relay access. | Profile gate rejects `allow_bearer_only_access`; Relay WebSocket requires device proof; Relay REST envelope submission requires `X-ISCP-Access-Proof` in production | Covered |
| ISCP-SB-023 | Production profile MUST reject plaintext debug. | `pkg/iscp/config`; conformance `P0-SEC-001` | Covered |
| ISCP-SB-024 | Logs, errors, audit records, panic output, and CLI output MUST NOT reveal private keys, refresh credential plaintext, access token plaintext, session keys, or plaintext business payloads. | Redaction helpers, CLI tests, conformance `P0-SEC-016` | Covered |
| ISCP-SB-025 | Secret redaction MUST run before structured logs are emitted. | `slog.ReplaceAttr` wiring in service entrypoints | Covered |
| ISCP-SB-026 | Refresh Credentials MUST be stored only as hashes. | PostgreSQL repository stores hashes; refresh serialization tests | Covered |
| ISCP-SB-027 | Signed object raw and canonical bytes MUST be retained for verification. | PostgreSQL migrations and repositories store raw/canonical bytes | Covered |
| ISCP-SB-028 | `jsonb` reserialization MUST NOT be used as a signature verification input. | Raw/canonical byte storage in repository layer | Covered |
| ISCP-SB-029 | Repository methods MUST scope by `domain_id`. | Repository domain guard tests and SQL predicates | Covered |

## 95% Readiness Rule

This matrix must not contain `Partial` or `Gap` rows for a business release
candidate. New protocol MUST or MUST NOT language must update this matrix in the
same change as the implementation or release gate evidence.
