# Durable management sessions

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: implementers, reviewers, operators

This implements the management-session portion of S14 in the
[storage migration](recovery-storage-migration.md). PostgreSQL stores each current
human session's namespace, bearer-token digest, administrator, creation time and
absolute expiry. The bearer token is returned only to the client. These rows do
not retain an operation history or replay audit records after restoration.

## Current authority

Ordinary authentication performs a keyed read with no capacity lock or cleanup
scan. It checks the stored absolute expiry, current policy lifetime and future
creation times; application freshness is checked after owned connection cleanup.
An absent or expired row is unauthenticated. A database failure is unavailable,
with no Redis or memory fallback. A session identifies a human administrator;
the existing database identity, topology and authorization checks still determine
that administrator's current powers.

Organizations first reads the session through its explicit admission. The final
check reuses the existing domain transaction's SQL connection and takes a shared
row lock until commit or rollback. This avoids acquiring a second connection
while holding the transaction and orders the accepted operation against session
deletion or eviction. Reads outside that transaction do not retain a row lock.
Cancellation of this read keeps connection cleanup owned; it must not permanently
close admission merely because the caller went away.

## Capacity and failures

New-session creation serializes only within its Environment/flow namespace.
It performs bounded opportunistic expiry cleanup, counts retained rows and evicts
the oldest rows if needed, then inserts the new session in the same SQL statement.
The existing capacity policy is preserved. A confirmed random-key collision is
rejected before eviction; it cannot replace a different administrator's session.
Statement failure or rollback also rolls back eviction. An uncertain result is
not retried and no cookie is published without confirmed success.

The namespace capacity row contains no change journal, counter or reconstructed
history. Authentication reads do not lock it. Creation's count can scan up to the
configured one-million-session bound, and a sharp policy reduction can require
many evictions. These costs apply to new administrative logins and remain part of
REC-T11's resource evaluation; they are not evidence for 10,000 HTTP requests/s
or p99 200 ms. SQL work has a five-second deadline, separate from owned cleanup.
Background expiry cleanup uses the shared batch limits and backlog metrics.

## Recovery and required evidence

Apply migrations through `20261105021000_runtime_security_catalog`. Stop old
workers before migrating this family; administrators can establish new sessions.
`AEGAEON_MANAGEMENT_SESSION_REDIS_URL` cannot select a production backend. Its
legacy implementation is test-only. After the browser-session increment, seven
Redis-backed families remain.

This increment does not activate a restored database. REC-T06/T08 must establish
a fresh session generation and exclude old workers before serving selected PITR
state. Restored credentials and revocations have the values at the selected
restore point; audit records do not automatically reinstate later changes.

Current-PR checks cover namespace isolation, concurrent capacity enforcement,
lookup without a namespace lock, TTL reduction and expiry, collision/rollback,
deletion, database failure, final checks with a one-connection pool and concurrent
logout, cancellation ownership, and actual management/Organizations HTTP paths.
The 36 affected native and five PostgreSQL/HTTP checks pass, including actual
Organizations grants/replay/revocation routes. Initial compile and lint failures
are retained with the corrected artifacts.
Strict refinement, whole-product composition and qualified provider/load evidence
remain Task 1b/3 obligations. No new product proof discharge is claimed.
