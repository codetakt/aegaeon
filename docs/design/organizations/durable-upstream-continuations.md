# Durable upstream continuations

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: implementers, reviewers, operators

Upstream authorization callbacks and logout relays use current PostgreSQL rows.
They implement S13/S18 of the [storage migration](recovery-storage-migration.md).
The rows represent outstanding operations with expiry; they are not a replayable
operation log or a recovery journal.

## Authorization callbacks

`runtime_upstream_auth` binds an Environment/flow namespace and a SHA-256 state
digest to the existing validated request snapshot and its absolute expiry. The
shared codec retains managed connection context, issuer-policy version, nonce,
PKCE verifier, browser binding and redirect URI. It deliberately omits the upstream
client secret; the selected managed registration supplies that secret when needed.
Snapshot storage is subject to the database's normal access and backup controls.

A callback first reads and validates the snapshot, then compares the independent
browser-cookie digest in constant time and checks the exact state, redirect URI
and expiry. The consuming DELETE compares the exact snapshot bytes atomically;
a changed snapshot or competing consumer cannot reuse the first read. SQL checks
expiry after acquiring the row. Application freshness is checked again after
owned connection cleanup before returning the request. Invalid snapshots and
incorrect browser/redirect bindings do not consume a valid continuation.

Absolute expiry is encoded as a UTC timestamp without floating-point epoch
conversion. Sub-microsecond precision is truncated, which can only shorten the
acceptance interval. Out-of-range representations fail closed. This does not
prove cross-host clock synchronization. The existing callback still checks issuer
and current managed connection policy before publishing authentication effects.

## Logout relays

`runtime_logout_relays` holds a namespace, hashed relay token, incident identity,
registered downstream redirect URI/state and expiry. One DELETE returns the
retained routing information only if it is still live. Concurrent callbacks have
at most one winner. Missing, expired or consumed rows cannot create a redirect;
backend failures are unavailable. Relay consumption precedes the existing incident
handling and response. It is not a claim of exactly-once HTTP delivery.

## Lifecycle and verification

Both stores use asynchronous pooled SQL, five-second operation deadlines and
owned cleanup. Confirmed random-key collisions refuse publication. An uncertain
mutation is not retried and does not fall back to memory or Redis. Shared bounded
expiry cleanup preserves live and other-namespace rows and reports backlog.

Apply migrations through `20261105021000_runtime_security_catalog`. The two
former upstream Redis URL variables cannot select a production backend; their
legacy adapters are test-only. The current Redis inventory has eight other families after the management-session migration.
A stopped-worker migration may discard outstanding callbacks and require a new
flow. Fresh-generation activation and old-worker exclusion after PITR remain
REC-T06/T08; these backend changes do not complete recovery or managed Redis
compatibility. Historical credential selection never triggers automatic audit
replay of later password changes or revocations.

The relay increment passes nine affected native checks and two PostgreSQL/route
checks. Authorization callbacks pass 18 affected native checks and two PostgreSQL/route
checks. An initial test mistook the authentication method name `client_secret_basic`
for a persisted secret; the corrected assertion checks the actual secret sentinel
and the absent secret field, without weakening the codec requirement. Earlier build failures and
the immutable artifact sources are retained. Task 1b/3 retain strict refinement,
whole-product claims and qualified provider/load work; functional callback and
storage defects remain the current PR's responsibility.
