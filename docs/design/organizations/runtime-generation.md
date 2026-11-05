# Runtime generation and connection fencing

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: implementers, operators, reviewers

## Contract

The selected PostgreSQL database owns current application state. The protected
startup configuration names a deployment and a randomly generated runtime
generation. A current database row must agree with both. Ordinary reconnects reuse
that selection; a restore/reset activation chooses a fresh generation before
traffic resumes. Neither startup nor cache failure automatically activates a row.

Every runtime physical SQL connection takes the same database-local shared session
advisory lock, then checks the current selection using a separate statement and
fresh snapshot. It retains the lock while idle in the pool and through transactions,
rollbacks and cleanup. SQLx's replacement-connection hook repeats the check before
application work. After owned work has drained, close guarded pools with
`lifecycle::close_pool` (used by `Runtime::close`). SQLx 0.8.6 can publish a late
idle connection while its first close pass waits for a checked-out permit. A
second pass drains that connection with acquisition already disabled; caller
shutdown deadlines and the database's actual lock check remain authoritative.
A deterministic real-PostgreSQL test pauses `after_release` at that race: a single
close leaves one session, while the guarded close drains it and allows activation.

No per-request independent witness connection, pending journal,
paired seal or lifecycle-row update is required by this mechanism.

Activation uses the conflicting transaction-scoped exclusive advisory lock and an
expected predecessor. It refuses immediately while a runtime session remains. The
selection update and activation audit record commit together. A reused generation,
operation ID or wrong predecessor refuses. An unknown commit result requires reading
the selected row and operation receipt; it is not permission to retry with a fresh
operation. Generation uniqueness in retained activation rows is an additional local
check, not a claim that PITR preserved all past generations. The operator generates
a new random UUID outside the restored snapshot.

The lock behavior follows PostgreSQL's documented
[advisory-lock semantics](https://www.postgresql.org/docs/18/explicit-locking.html#ADVISORY-LOCKS).
This design requires session-preserving connections. Transaction-multiplexing
proxies and connection reset commands that release session locks are unsupported.
Direct managed PostgreSQL connections do not require superuser access for the
runtime lock operation. Provider topology and proxy qualification remain explicit
deployment work, not a result of local tests.

## Restore and memory boundary

Before restoring or exposing a replacement database, operators stop traffic and
exclude old workers from that target. The application cannot infer an intentional
rewind from a normal reconnect to an identical restored row. Activation occurs
while the target is isolated, after the selected schema/configuration is checked.
Old workers retain their old configured generation and fail any later connection
check against the newly activated row. New workers build empty disposable caches
and generation-specific continuation/session stores.

A live connection fence alone cannot stop a detached external HTTP effect or a
process serving already-loaded memory after its database connection dies. The
serving dispatcher must retain a finite runtime owner and verify readiness; the
operator drain/exclusion procedure remains necessary. External effects use domain
event identity, current delivery state and reconciliation. They are not undone by
PITR. Later audit records never reapply credentials or revocations automatically.

Externally generated assertions/proofs need a separate replay boundary: changing
the session namespace alone does not invalidate their signatures. The integration
must preserve a complete acceptance horizon or enforce a bounded activation
barrier before those surfaces accept old proofs. This item is still open; the
connection adapter does not claim to close it.

## Authority and verification

The runtime receives read-only lifecycle state, never activation or table-write
privileges. The connection hook rejects those overprivileges. Activation is a
maintenance-only fixed function. The lifecycle schema is separate from ordinary
application tables so broad application-table grants do not silently grant it.
The database administrator remains inside the operational trust boundary.

Direct PostgreSQL checks cover multiple physical connections, idle pool ownership,
rollback, exclusive activation, old-generation reconnect, replacement after backend
termination, predecessor conflicts and runtime privilege refusal. Production
dispatch, startup, domain receipt migration, generation namespaces and restore
tooling remain REC-T06 through REC-T09 work. No measured throughput or new product
proof discharge follows from the adapter.

## Current startup configuration

The production startup now reads version 2, with `deployment_id`, `generation`,
`primary: {url, root_cert}`, `environments: [{id, issuer}]`, explicit
`admission: {ordinary, revocation, snapshot}` limits and optional `delivery_trust`.
The database URL must exactly match the bootstrap database URL. The primary
connection uses verified TLS and captured CA bytes. Version 1's control/token
endpoints and per-Environment witness selections are refused by this parser.

The dispatcher uses the same guarded pool as runtime construction and security
stores. Each Environment retains a fixed issuer binding. A management parent may
create a child for one registered Environment; the child shares the parent's
capacity and failure state and retains it through SQL and response cleanup.
A child cannot create another child or substitute a different pool. Capacity and
request failures do not permanently close other requests. Admission bounds are
per runtime: ordinary 1–4096, reserved revocation 1–64 and snapshot 1–4. These are
resource limits, not evidence for the requested throughput or p99.

Creation retries use `organization_creation_receipts` committed atomically with
user creation. Competing selectors serialize inside that transaction. A current
receipt is checked against actor, payload and actual current identity; an absent
receipt permits the operation, and a conflicting payload refuses. No independent
prepare/finish journal is written. Historical receipts retained in the selected
DB remain usable after a new generation; a receipt is never caller authorization.

The runtime provisioning script grants only lifecycle schema usage and current
row reads. `activate-organizations-runtime.sql` calls the maintenance-only function
with an explicit predecessor and externally generated generation/operation UUIDs.
It defaults to rollback. After an uncertain response, read the selected row and
activation record for the same operation before deciding what to do next. The
operator links that operation to their restore point and audit-gap record. The
script does not restore a database, stop workers or replay later audit events.

Production excludes the legacy control dispatcher and continuity schema.
Predecessor fixtures are test-only. The operations package exposes selected-state
activation; see the [runbook](restore-runbook.md) for isolation, audit gaps,
external delivery and offline domain maintenance.

## External proof activation policy

The adopted safe default preserves single-use protection across an authorized
PITR/reset. A fresh generation alone cannot invalidate an externally signed proof
whose consumed row disappeared at the restore point. Only affected JWT assertion
and Request Object routes refuse temporarily. Permanent credentials and revocations
remain exactly the selected database state; no audit replay or blanket reset occurs.
Normal same-generation restart does not reset or extend the durable deadlines.

Activation records deadlines and the prior acceptance policy in the selected
PostgreSQL database, atomically with the new generation and an operation/actor
receipt. Old workers must already be excluded from the restored target. The wait
starts at activation, after that exclusion, never at the historical restore time.
It uses prior maximum assertion/Request Object windows (default 3600 seconds),
maximum supported leeway (300 seconds), four times the operator's absolute clock-error bound
(default 300 seconds) and one second for the inclusive expiration boundary.
With defaults, each JWT/JAR wait is 5101 seconds. The DPoP horizon is 600 seconds
plus four times the clock bound and one second (1801 seconds with defaults).

The clock bound covers each old worker, new worker and selected database clock
against UTC throughout recovery, including a restart. Two margins cover opposite
old/new validation clock errors. Two more cover opposite database-clock errors at
activation and at a later deadline reload. Omitting the latter permits a restart
after a database-clock advance to reopen too early. Runtime loads remaining time
into monotonic deadlines; ordinary requests need no extra clock query.

A smaller prior acceptance window is valid only when established for every former
worker; otherwise retain the product maximum. If clock bounds or old-worker
exclusion cannot be established, keep the affected routes offline. These are
operational prerequisites, not application detection of arbitrary clock faults or
reconstruction of the selected restore point. A deployment can select a smaller
clock bound only with corresponding operational evidence.

DPoP uses a fresh nonce namespace derived from the generation and Environment,
separately for authorization-server and resource-server roles. During its recovery
horizon, a proof without that nonce receives `use_dpop_nonce`; after a fresh nonce
is supplied, normal signature, freshness and durable single-use checks still apply.
This permits DPoP recovery without replaying old proofs. It does not reopen JWT
client authentication when that separate assertion route is still deferred.

Empty restored data cannot establish that no external proof was ever used.
The default therefore waits even when there are no Environments or predecessor
receipt. Only an operator assertion `"initial_install": true` in `proof_policy`
can omit the wait, and only with no selected generation and no Environments.
It asserts first-ever installation; it is invalid for PITR to an empty historical
state. The durable policy receipt records that operational premise. The application
cannot establish deployment history from an empty database alone.

Maintenance activation validates policy bounds, excludes live runtime sessions
and records the selected policy; runtime logins cannot modify it. The activation
script defaults to rollback.

No new `iat` requirement is introduced:
[RFC 7523 section 3](https://www.rfc-editor.org/rfc/rfc7523.html#section-3) makes it
optional. DPoP nonce behavior follows
[RFC 9449 sections 8 and 11.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-8).
The bounded model and directly affected integration checks are current-PR work;
full clock/provider qualification and composed conformance proofs remain Task 3.

## Temporary database outage

A running process distinguishes transport loss, unavailable connections and
bounded read deadlines from changed configuration or invalid durable authority.
During an outage, protected requests and readiness fail with 503 while `/health`
continues to report process liveness. Observed database failures invalidate the
brief readiness revision cache. The runtime never authorizes from that cache or
replaces the database with in-memory state.

Each periodic read or housekeeping pass remains finite. The current-generation
runtime may start a fresh pass on its next configured tick after an unavailable
pass; it neither marks that failed pass successful nor retries a user's mutation.
Retained work keeps its actual ownership and cleanup boundaries. Startup still
requires valid current authority. Configuration/key drift, malformed authority,
closed runtime admission and worker panic retain their fail-closed behavior.
Ordinary recovery reconnects through the physical generation fence and leaves
the selected generation unchanged.

Startup also performs one bounded direct generation/role validation before
creating its fenced pools, so an explicit refusal is not hidden behind SQLx's
retrying connection-hook timeout. Every later physical connection repeats the
fence check. The diagnostic names selected database generation/runtime role
refusal; no independent control-store supplier is implied.
