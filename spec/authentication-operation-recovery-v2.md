# Authentication and operation recovery v2 freeze candidate

Language: English | [简体中文](../zh-cn/spec/authentication-operation-recovery-v2.md)

Status: **candidate for InfiniCenter 0041**, 2026-10-19. This file and its
[schema](../schemas/candidates/operation-recovery.v2.json),
[vectors](../conformance/fixtures/operation-recovery.v2.json) and test-only API
contracts are review assets. They do not advertise, implement or accept a public
protocol. Service and client implementations remain independently built.

## 1 Scope and profiles

The protocol token is `iscp.operation.recovery.v2`. New control namespaces are
`control.credentials.v2` (issuer) and `control.relay-credentials.v2` (Relay).
Only four control families are frozen here. Existing application operations keep
their existing strict schemas and original task authorization. Their recovery
inventory is maintained in SparkClaw; consuming this protocol does not silently
give an existing handler find-or-admit semantics. No legacy pending-request
import, source migration, shared module or shared release commit is required.

| Kind | Namespace / target | Exact payload | Successful result body |
| --- | --- | --- | --- |
| `credential.renew` | `control.credentials.v2` / issuer | sorted unique `requested_scopes` | `grant` |
| `credential.recover` | `control.credentials.v2` / issuer | sorted unique `requested_scopes` | `grant`, complete signed `relay_result` |
| `relay.refresh` | `control.relay-credentials.v2` / Relay | sorted unique `requested_scopes` | `relay_credentials` |
| `relay.recover` | `control.relay-credentials.v2` / Relay | sorted unique `requested_scopes` | `relay_credentials` |

All four use `task_authorization.kind=standing`, a null business deadline and
the original binding. Its scopes equal payload scopes and must be a subset of
current standing authority. Renewal cannot widen them. Preconditions are durable
resource version, **target** credential generation and authorization revision;
these are control CAS values, not connection IDs. An existing operation is
looked up before comparing a precondition with the current generation. A new
business intent must not acquire these credential CAS fields merely because
the control profile has them.

The parent result generation belongs to the issuer. Its embedded `relay_result`
uses a restricted nonrecursive child-result profile and carries the Relay target,
binding, independent credential generation and authorization revision. The client
verifies the original pinned Relay signature, actor/subject linkage, target and
generation as well as the outer issuer signature. Installing issuer generation 9
and Relay generation 22 requires two correctly scoped CAS checks. Both installs
are durably recorded before parent installed ACK; a crash reconciles each part.

Failure/cancel result bodies contain exactly `code` from the schema. Grant and
Relay credential shapes are closed; existing Grant signature/confirmation,
recipient, audience, permissions and validity checks remain mandatory. A
successful renew cannot carry Relay credentials, and recover cannot omit them.
All fields, including optional parent/predecessor fields, are part of the stable
intent. Unknown kinds or unmatched namespace/kind/result shapes are rejected.

## 2 HTTPS entries and outcomes

All entries use the original pinned HTTPS authority and POST. Redirects are
forbidden. Neither an authenticated WSS data channel nor a valid old access or
refresh token is required for challenge and standing-identity recovery.

| Path | Input / response |
| --- | --- |
| `/v2/control/challenge` | `challenge_request` / `challenge`; no account state, admission or authority is disclosed |
| `/v2/control/operations/submit` | `request_submit` / signed status or sealed immutable result |
| `/v2/control/operations/lookup` | `request_lookup` / signed status or sealed immutable result; never executes |
| `/v2/control/operations/recover` | `request_recover` / atomic find-or-admit for the four declared control profiles |
| `/v2/control/operations/ack` | `request_ack` / signed immutable disposition receipt |

The action and exact path must match. The verified HTTPS context's domain/device
are the **actor** and must match the operation key, including lookup and ACK.
Intent namespace/operation ID match that key. Target service matches audience.
Direct requests require actor = subject. The sole delegated exception is
section 6's issuer-to-Relay profile; a caller cannot request it by adding a role
or principal header. The TLS terminator/forwarder preserves the exact path and
body; issuer verification is end to end, not delegated to a self-reported header.

At shared public HTTPS ingress, challenge_request.audience selects only a
preconfigured trusted issuer/Relay route. The authority-issued challenge ID is
recorded as an opaque route mapping for its ten-second lifetime; all operation
actions route through that mapping, including lookup/ACK without intent. The
verifier independently checks its actual audience/path. This uses a protected
independent HTTPS/service path, never an expired WSS control peer. Caller URLs
or unsigned routing headers cannot choose a verifier. Ingress restart/unknown
challenge ID requires a fresh challenge without changing the operation ID.
Failure before the selected signer is unresolved transport failure, not revoke.

HTTP 200 carries a signed status/result/disposition, 400 malformed request, 401
authentication failure, 403 verified authority refusal, 409 conflicting intent
or credential generation, 410 closed namespace, 503 temporarily unavailable.
Every control error is the schema's signed typed error; HTTP status alone cannot
prove revocation, non-admission or rollback. Transport failure preserves unknown.
Body/frame maximum is 128 KiB; oversized ciphertext uses a typed pre-admission
failure and cannot silently truncate a stored result.

Statuses are admitted, running, succeeded, failed, cancelled, absent, unknown,
conflict and namespace_closed. `result_expired` is a code on the retained
terminal state, never absent. Missing/incomplete history produces
unknown/history_unavailable with `history_complete=false`; uncertain commit or
external effect produces unknown/commit_unknown or unknown/effect_unknown.
An absent lookup requires complete continuous history and a completed admission
barrier under the same key lock. Absence is only a point-in-time observation;
only the atomic recover transaction can subsequently admit the original intent.
Existing JingSi `not_started` remains its permanent negative admission fence.

Schema variants fix status combinations: admitted/running use complete history,
code=none and null result digest; terminal states retain result digest and use
none/result_expired; absent also requires record_version=0; history gaps are
unknown/history_unavailable/incomplete; unknown commit/effect uses complete
history and its matching code; conflict discloses no result; closed namespace
uses its closure code and incomplete history. Error retryable is true only for
challenge_expired, authorization_unavailable and resource_exhausted. Uncorrelated
malformed requests use null attempt_id/key/revision, never invalid echoes.
Revoked/ended errors require a valid attempt, actor key and authority revision;
other refusals never imply revoked authority.

## 3 Exact canonical and authentication bytes

Use the ISCP [canonical profile](canonical-jcs-v2.md): valid UTF-8, no duplicate
members, lone surrogates, trailing data, floats/exponents, unknown fields or
noncanonical base64url. Counters are canonical decimal strings in uint64 range;
Grant's existing integer revision remains a safe JSON integer. Times are real
calendar UTC RFC3339 seconds without fractional/offset alternatives. Scope sets
are sorted unique UTF-8 strings. Reject nonzero unused base64 bits by decode and
re-encode equality. A schema match alone is insufficient for these checks.

Let `C(x)` be exact canonical bytes and `H` SHA-256, represented as unpadded
base64url. NUL below is one zero byte.

```text
semantic_digest = H("ISCP-OPERATION-INTENT-V2\0" || C(intent))
request_digest = H("ISCP-CONTROL-REQUEST-V2\0" || C(request without authentication))
signature_input = "ISCP-V2-SIGNATURE\0iscp.control.authentication.v2\0" || C(context)
```

The context is the schema's complete `authentication_context`, reconstructed by
the verifier from protocol, purpose, real method/path, configured audience,
verified actor, server-issued challenge/ID, nonce, issuance time, request digest
and `credential_sha256`. The latter is SHA-256 of the exact bearer token UTF-8
bytes, or null if absent; it is never an intent field. A supplied invalid token
must not silently become absent. Fresh standing-identity recovery may explicitly
omit an expired token. The proof signs the context, not an old DeviceProof or a
recursive request containing itself. Changing delivery key, attempt, path,
audience, credential or intent invalidates authentication without changing the
stable operation's identity.

Challenges and challenge IDs are independent 32-byte random values, valid for
10 seconds, bound to authority/actor/purpose and consumed atomically with the
authenticated action. Nonces contain 16–64 fresh random bytes. Issuance time may
be 60 seconds behind or 30 ahead of server time without extending challenge
expiry. Lost replies use fresh challenges; consumed proofs are never replayed.
The registered Ed25519 KID and key must match the actor. A proof alone cannot
restore revoked/ended authorization. The service checks live authority under
section 7's fence at authentication/admission/disclosure boundaries.

## 4 Immutable result, resealing and disposition

```text
result_digest = H("ISCP-OPERATION-RESULT-V2\0" || C(result.payload))
result signature = SignatureInput("iscp.operation.result.v2", result without signature)
disposition_digest = H("ISCP-OPERATION-DISPOSITION-V2\0" || C(disposition without
                       signature, disposition_digest, accepted_at))
```

Result version, key, semantic digest, terminal state, completion time, issued
credential generation and body are immutable. Repeated retrieval has identical
result bytes/signature, regardless of new credentials, challenge or session.
Statuses and dispositions use their respective schema type as SignatureInput's
object type. The original trusted issuer/Relay signer verifies all results.

Resealing uses X25519, HKDF-SHA256 and ChaCha20Poly1305. Its canonical context
contains exactly protocol, actor operation key, semantic digest, result digest,
delivery ID, recipient X25519 public key and fresh server X25519 public key.
Delivery IDs contain 32 random bytes. Nonces contain 12 random bytes; each seal
uses a fresh server key. Invalid/low-order X25519 agreement is rejected.

```text
salt = SHA256("ISCP-CONTROL-RESULT-SALT-V2\0" || C(delivery_context))
key  = HKDF-SHA256(X25519(server_private, recipient_public), salt,
                  "ISCP-CONTROL-RESULT-KEY-V2\0" || C(delivery_context), 32)
aad  = "ISCP-CONTROL-RESULT-AAD-V2\0" || C(delivery_context)
plaintext = C(the same signed result)
```

The recipient key is protected by fresh request authentication, and the current
actor must still be authorized to receive the result. A delegated child result
belongs to the authenticated issuer actor; it is never directly disclosed to an
unrelated device. The issuer places required child credentials into its own
immutable parent result for the original device. Secrets are encrypted at rest
and in transit, and excluded from logs/plaintext journals.

ACK names the exact result digest and generation. `installed` means the original
still-valid issued credentials were durably installed under a local binding and
generation CAS before sending ACK. `acknowledged_expired` explicitly closes a
result whose credentials can no longer be installed due to expiry;
`acknowledged_superseded` closes a result fenced by a durable newer generation.
These do not falsely assert installation. `applied` is reserved for noncredential
result application and cannot acknowledge credential issuance. The receiver
checks the disposition against its immutable result/current generation.

Only a registered issuer actor may ACK its delegated Relay child with `delegated`
and non-null `parent_result_digest`. First freeze/persist the signed parent result
containing the complete child result; then obtain/persist the child signed
delegated disposition; then recheck current parent authority and publish parent
completion. Closure means incorporation in that exact parent, not installation
on the device. Lost ACK replays identical bytes and cannot invent a disposition.
Other dispositions require parent_result_digest=null. A terminal device cannot
use delegated to bypass installation/expiry. These are durable cross-service
steps, not a single transaction.

The first valid ACK creates one signed disposition receipt atomically. Exact
ACK retries return it; another disposition or result digest conflicts. A successor
intent includes predecessor key/result/disposition digests and current expected
generation. It is allowed only after durable predecessor closure. An unknown
predecessor cannot be discarded, acknowledged as installed or bypassed with a
new operation ID. A late expired ACK may not overwrite a newer installation.

## 5 Control state and credential CAS

Persist immutable intent/key/digest, admission authorization snapshot, state and
record version, reserved target generation, child steps/outbox, signed result,
disposition and timestamps before their externally visible effects. State is
`admitted → running → succeeded|failed|cancelled`, with uncertainty represented
by durable step/effect state rather than a second operation. Admission reserves
the next credential generation with an exclusive durable CAS; only one mutation
of a target generation can be outstanding. The same key/digest returns the same
reservation/result. Another key using a consumed generation receives conflict.

Commit issued credential rows and the immutable receipt in one storage
transaction where co-located. Persist dispatch intent before an external step.
Worker recovery claims by record version; old workers cannot overwrite new
ownership. A database connection lost during COMMIT is unknown until lookup,
not an inferred rollback. Failed operations cannot silently reuse an already
consumed generation. Current authorization remains required for reconciliation
and disclosure even when admission was authorized earlier.

## 6 Issuer-to-Relay child authority

The issuer durably records its parent admission and child intent before sending
the child. It then authenticates using its own enrolled **service** identity,
with fresh Relay-audience challenge/proof. The child operation key belongs to
that service actor; `subject_binding` names the original target device.

The Relay reads protected authority rows establishing: active service actor;
the domain/device/binding's registered issuer owner; active target standing
authorization; exact current authorization/resource revision; permitted target
scopes; and expected target credential generation. Actor, target and parent
domain must agree. The child parent key is the original target's issuer operation
key, with its unchanged semantic digest and step. A regular device, unrelated
issuer, wrong target, revoked service/subject, stale revision or broader scope
is denied. These facts come from authority storage, never caller-provided claims.

No parent **terminal** receipt is required: that would create a cycle. The
protected service request plus registered issuer ownership authorizes this
restricted child operation. Parent references provide stable linkage and audit,
not independent authority or an assertion of parent completion.

```text
child_context = {parent_key, parent_semantic_digest, target_service_id, step,
                 child_index, predecessor_disposition_digest}
child_operation_id = "child-" + H("ISCP-CHILD-OPERATION-V2\0" || C(child_context))
```

For credential recovery the step is `relay.credentials.recover`. Relay child
admission, credential rotation, result/disposition and parent completion are
reconciled durably. A child that committed before a lost reply is never rotated
again. The parent cannot complete or start a successor while its child outcome
is unknown. Expired child results are explicitly closed before an appropriately
linked child successor is recorded; a changed child key cannot hide unknown
work. Initial child_index is "0" and predecessor_disposition_digest is null.
After signed expired/superseded child closure, increment durable child_index,
bind that disposition digest and current target generation, and persist the new
child before sending. This derives a distinct successor key; unknown predecessors
cannot produce successors. Before the parent result freezes this permits child
recovery. After freeze, an expired embedded child requires expired closure and
a successor parent, never rewriting the old parent result. No old RelayProof
enters stable intent.

## 7 Shared authority locks and retention

The accepted integration must use one helper/lock hierarchy with the duplex
line: **writer epoch/scope → domain → device (sorted IDs) → owner → unique keys
(control operation or message, uniformly sorted by namespace/ID)**. Missing
levels are skipped. Never acquire authority after an operation key. Authority
reads may hold shared locks; rotation, revoke and takeover acquire exclusive
locks on those same rows. Authentication commit, admission, result disclosure,
duplex send/delivery/query and owner transitions participate. The duplex line
owns the common helper/migration; authentication consumes it without a parallel
advisory-lock namespace. Separate issuer databases use the same logical order
and durable CAS, but this does not create a cross-service database transaction.
Network calls never occur while a cross-service database lock is held.

Cross-service revocation is a durable transition, not a distributed lock. The
issuer first persists closing at the new revision and fences new parent admission,
completion and disclosure. A stable existing revocation operation/outbox updates
Relay. Under the shared authority lock, Relay commits revoked/new revision,
revokes every credential generation (including children committed immediately
before it), fences owners, and retains immutable revocation operation/revision.
Its protected successful response or authenticated repeated lookup of that exact
record supplies durable acknowledgement. Only after saving that evidence may
issuer mark the transition globally effective/revoked. Lost ACK stays closing
and retries the original operation; failure never reopens rights. A child can
commit before Relay revocation, but parent closing blocks disclosure and Relay
revocation invalidates its credentials. A delayed child then fails current
revision/status checks. Scope narrowing uses the same fail-closed transition;
remaining rights reopen after every required enforcement point acknowledges the
new revision. Pending is not reported as completed global revocation.

Retain signed result content for at least seven days after completion and while
any contained credential remains usable. Keep unresolved operations and their
reconciliation evidence. After result-content expiry, retain terminal state,
key/digest, result digest, credential generation/expiry bounds and disposition
or pending-ACK metadata. Return terminal/result_expired; never execute to
reconstruct the result. Deduplication tombstones persist while the namespace
admits requests. Before pruning them, permanently close the actor namespace,
fence all writers and retain a closure marker that forbids its reuse. A restored
database without complete history is unknown/closed and cannot admit an old ID.
A fresh history ID or empty table cannot establish completeness.

## 8 Shared client API and generation rules

The test-only compile contract names the future `iscpbridge.CredentialProvider`,
`CredentialBinding`, `CredentialLease`, `CredentialEvent` and invalidation types.
The provider owns encrypted persistence, installation CAS and one recovery flight
per original identity/domain/target binding. Binding includes original issuer,
Relay and TLS pins. The duplex socket owner owns WSS PoP, socket reads/writes,
Relay owner generation and local connection epoch. Construction verifies
identity/pins even when both access and refresh are expired; it permits only
independent HTTPS recovery until a valid lease exists, never data READY.

`CredentialGeneration` is server-persistent credential CAS;
`RelayOwnerGeneration` is server-persistent socket ownership from READY;
`ConnectionEpoch` is a local process callback/waiter fence. They are separate
types and cannot substitute for one another. Lease expiry is the earliest
deadline of the access token and all authority needed to use that transport,
not an enrollment-file cache TTL and not an extension of task authorization.

`Invalidate(binding, expected_generation, reason)` marks that exact lease
unusable even before nominal TTL; the next EnsureAccess reconciles/refreshes
instead of returning the rejected token forever. Stale invalidation is ignored.
Reasons are `authentication_required`, `access_rejected`, `rotation_required`.
They cannot assert revocation. Verified provider events are `rotated`,
`recovered`, `revoked`, `identity_changed`, `scope_changed`, with binding,
credential generation, authorization revision and ordered provider state
version. Subscribers reject events for old bindings/state versions; delayed
rotation cannot overwrite revocation. Terminal authority facts require verified
service evidence. Same-authority rotation may reauthenticate an existing socket;
actual identity/scope changes fence it.

A caller's context cancels only its waiter. The shared flight has the provider's
shutdown context and bounded 30-second attempts; all writes use current binding,
generation and provider state CAS. With no verified state, including expired
credentials at cold start, Subscribe waits for the first verified lease/authority
event; it emits neither a fictitious lease nor revoked for ordinary recovery
pending. Subscriber delivery is nonblocking and may
coalesce states only while preserving terminal/invalidation precedence. All
socket lease use is revalidated; holding an old lease object grants no rights.

## 9 Review and implementation gates

Run `node conformance/fixtures/generate-operation-recovery-v2.mjs` and
`go test ./conformance -run AuthenticationRecoveryCandidate`. The fixed fixtures
are independently encoded/signed/sealed using Node's crypto; Go verifies
canonical bytes, digests, Ed25519 binding, two different result wraps, malformed
input, schema and delegated authorization examples. Review also validates the
JSON Schema with a Draft 2020-12 validator. Passing these checks proves candidate
asset consistency, not service behavior.

Before release, fault-inject real persistent stores at admission, child dispatch,
credential commit, result save, install and ACK; race rotate/revoke/takeover;
expire proof/access/refresh; reopen unknown commits; verify history-gap fences,
independent builds and native original UI/data. Business-family inventory gates
must run against actual handlers, including never-sent submission, running-task
attach, durable result/ACK, unknown side effects and stream snapshot recovery.
