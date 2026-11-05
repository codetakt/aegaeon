# Durable step-up challenges

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: implementers, reviewers, operators

This implements S16 of the [storage migration](recovery-storage-migration.md).
PostgreSQL stores the current pending or completed challenge for an
Environment/flow and request binding. Consuming the completed challenge removes
that row. These are domain states, not a state-transition journal or audit replay.

## Binding and transitions

The primary key contains the namespace and SHA-256 of three independently framed
fields: client, session and request. Each UTF-8 field has an unsigned 64-bit
big-endian byte-length prefix. Separator ambiguity cannot alias two bindings;
the session bearer identifier is not stored or written to diagnostic logs.

Issuing replaces the current challenge for that binding, including any completion.
Completion conditionally updates an uncompleted row once. Consumption deletes a
completed row once. Competing operations use PostgreSQL row concurrency, with no
independent operation journal. Missing, expired, incomplete or mismatched bindings
cannot satisfy step-up. The existing authorization gate separately checks the
current session's ACR and authentication age; challenge completion cannot bypass
those requirements.

Application epoch bounds and the database clock both constrain acceptance.
Completion and consumption check expiry after acquiring the row lock, and again
against the application clock after owned connection cleanup. Timestamp conversion
is checked and uses a UTC string rather than floating-point epoch arithmetic.
Clock synchronization remains an operational assumption, not a proven property.

Local login uses asynchronous SQL for the original completion and the successor
challenge associated with the new session. Failure at any of these steps cannot
produce a completed successor. The current flow can leave an unused original
completion or pending successor; their expiry and the authorization gate bound
their use. HTTP delivery is not exactly once. Diagnostics retain request/challenge
correlation and fixed error categories without bearer IDs or opaque backend errors.

## Resources and recovery

Request handling performs no global expiry scan. Bounded background cleanup uses
the shared expiry index, batch/time limits and backlog metrics. Reads and writes
use asynchronous pooled connections and five-second operation deadlines; owned
connection cleanup has its separate bound. This is not a p99 or throughput result.

Apply migrations through `20261105021000_runtime_security_catalog` and stop old
workers before moving this family from Redis. Existing challenges may be discarded
and users repeat the flow. `AEGAEON_STEPUP_REDIS_URL` cannot select the production
backend; its legacy implementation is test-only. Eight other Redis families remain after the management-session migration.
PITR activation, fresh generations and old-writer exclusion are REC-T06/T08 and
remain incomplete. No later credential change is replayed from audit data.

## Required evidence

Current-PR checks cover binding isolation, concurrent completion/consumption,
replacement, exact expiry boundaries, expiry after row-lock waits, rollback,
backend failure, asynchronous login transfer and current-session age enforcement.
Thirty affected native checks and five PostgreSQL/HTTP checks pass, including
GET/POST positive-age continuation. Initial build failures (hash import and a
stale environment-inventory tuple) were corrected. A wrong filter selected zero
tests; its corrected inventory check initially used the wrong working directory.
The corrected source-bound inventory check passes. These failures and the
immutable artifact sources are kept.

The finite security model requires at most one successful consumption per current
completed challenge and no acceptance from missing or expired state. Actual SQL
and HTTP checks establish implementation behavior within their tested conditions.
Task 1b/3 retain strict SQL/Rust refinement, whole-product composition and qualified
provider/load evidence. No new product proof discharge follows from these checks.
