# Drained store restart continuity

Last updated: 2026-11-04

Status: draft

Owner: Engineering

Audience: implementers, operators and security reviewers

> Status note: The implementation is under validation. Finite test results do
> not establish a new formal guarantee or qualify a deployment supplier.

## Superseded operational design

This page records predecessor behavior and its source-scoped evidence. Its
control-store, paired-seal, generic history-replay and credential-cutover commands
are not shipped or supported by the current implementation. Use the
[current generation contract](runtime-generation.md) and
[restore runbook](restore-runbook.md). Predecessor code retained under test-only
modules is not a production fallback. Historical test results below do not prove
the replacement implementation.

## Responsibility revision — 2026-11-05

The [adopted recovery rules](recovery-responsibilities.md) are the successor
design. The mechanisms and results below describe the existing implementation
and its historical validation, not a requirement to preserve volatile state or
implement application-level WAL/PITR. The [workplan](recovery-workplan.md) tracks
the replacement; legacy guards are test-only after their consumers migrated.

## Contract

A normal PostgreSQL or Redis restart changes its process identity even when all
application data survives. Process identity remains a required observation on
each live connection. A new process can be accepted only through the independent
control store's drained continuity protocol described here. Merely ignoring a
changed start time or Redis `run_id`, or observing a larger WAL position, does not
establish continuity.

This protocol permits a restart with no unresolved work and matching durable
post-work seals in both stores. It does not recover uncertain in-flight effects,
accept PostgreSQL timeline changes, repair a lost or rolled-back control store,
or qualify a cloud failover. Existing all-writer, credential, transport and
independent durability requirements remain in force. A seal is operational
evidence, not an authorization grant or a substitute for supplier qualification.

## Completion before restart

The primary has one private continuity row and Redis has one nonexpiring
`aegaeon:organization-store-continuity:v1` key in the selected database. Each binds
the deployment UUID to a random, non-nil UUID seal. A scalar counter is
insufficient: an old store could receive enough unrelated writes to exceed a
retained lower bound without restoring revoked authority.

Initial preparation pins the same seal in the independent control store and both
data stores. This requires the exact drained prepared operation and revision.
Primary initialization requires maintenance authority. Runtime functions can only
compare and replace an existing seal. Activation and admission require the
current epoch's pinned seal. The primary table is private and its fixed functions,
ownership and physical catalog are checked on each dedicated connection's first
seal operation. Runtime credentials have no direct table access.

The primary observer accepts only an idle autocommit connection and retains it
without exposing raw query access. It checks both SQLx transaction depth and a
standalone PostgreSQL transaction-control probe, since raw `BEGIN` is not tracked
by SQLx's depth counter. An existing transaction is refused without committing
its effects. This makes the seal write's acknowledged autocommit a requirement
of the observer API, rather than an assumption about its callers.

Every parent completion proceeds in this order:

1. Wait for all actual child, data, response-body and cleanup owners to finish.
2. Start a control transaction and lock the exact deployment and pending owner.
3. Recheck the dedicated live store connections and their previous seals.
4. Compare and replace the primary seal, then the Redis seal, with one fresh UUID.
   Redis acknowledges local AOF persistence with `WAITAOF 1 0 4000` on the same
   connection as the write. Both stores are read back and observed again.
5. Close the dedicated data connections, record the final observation and seal,
   and release the exact pending owner in that same control transaction.
6. Commit before reporting completion.

The control lock serializes seal completion; unrelated business work remains
covered by its own durable pending owner. With every owner drained, the most
recent seal follows every completed work item's effects. A whole-store snapshot
that predates a completed effect also predates its post-work seal. Catching up WAL
with unrelated activity cannot recreate that random seal.

This adds durable writes and a serialized completion section to admitted work.
The supported Redis supplier already requires AOF with `appendfsync always`.
No throughput or latency improvement is claimed. Existing request and connection
deadlines are retained; inability to finish within them fails closed.

Application connection cleanup always drains an explicit `ROLLBACK` before
restoring settings and making its final observation. This also covers a cancelled
`BEGIN` whose reply never reached SQLx's transaction guard. It adds a command to
normal cleanup; pending ownership covers that command and the bounded cleanup.

## Accepting a different process

Before allocating a durable parent slot, the connector checks the exact current
selection and actual store observations. An unchanged process uses the ordinary
observation checks. A changed process requires a control transaction that locks
the parent and all its Environment authorities in canonical order and establishes:

- no pending parent, child or maintenance work;
- unchanged PostgreSQL cluster, database OID/name and timeline, with WAL covering
  every retained parent and child floor;
- the same Redis database index;
- complete current parent/child bindings;
- exact agreement of both actual data seals with the current control seal.

It then reobserves those same live connections and updates the parent and every
bound current child checkpoint atomically. The preceding checkpoints, new
observations, operation UUID, principal and seal remain in an append-only restart
journal. Authority epochs do not change and data seals are never rewritten by
restart acceptance. At most 65,536 restart records are admitted per epoch;
exhaustion refuses rather than deleting evidence.

Actual work still performs fresh acquisition and checkpoint checks after this
diagnostic phase. A read-only observation is never converted into a serving
capability. Startup validates both parent and child selections before attempting
continuity and shares its existing deadline with actual startup and cleanup.
Rejected preflight does not allocate, clear or reuse a durable pending slot.

## Refusal and recovery boundaries

Failure after a data seal write and before control commit leaves the pending
owner retained. If the commit response is lost, local admission closes and the
result remains unknown: durable state may still be pending, or may contain the
atomically completed seal, observations and release. A timeout never authorizes
clearing or replaying an owner. Partial seal updates cannot be retried by replacing
whichever value is found: normal completion requires the previous control seal
exactly. Existing explicit exclusion, inspection and recovery remain necessary
for unresolved durable work.

An idle or deliberately drained restart can therefore resume automatically;
restarting during unresolved work can still require operator recovery. This is
not two-phase commit for every application mutation. Logical partial rewrites,
administrator changes outside the admitted writers, or coordinated rollback of
all independent evidence remain outside this continuity argument. The existing
recovery command also keeps its own stricter current-source requirements; this
runtime protocol does not silently weaken an in-progress recovery operation.

Startup logs use fixed reason codes, including `primary_incarnation_changed`,
`primary_progress_behind`, `token_incarnation_changed`,
`store_continuity_mismatch` and `store_restart_pending`. Raw source errors, store
URLs, credentials and seal contents are excluded. External startup errors retain
their generic form.

## Upgrade and evidence

Stop and drain all runtime and maintenance writers before the primary migration
`20261105000000_organizations.sql` and control schema versions
15 and 16. Control migration requires fenced authorities and no pending work or
unfinished cutover. Prior migration and catalog files are preserved. Provision
the narrowly scoped primary function grants and Redis `WAITAOF` capability before
the normal qualified preparation and activation process.

Required local acceptance covers actual PostgreSQL and Redis restarts, old
whole-store restoration despite later WAL activity, failed and uncertain seal
completion, concurrent completion/restart, all-child updates and retained
history, and repeated rejected startup without pending growth. Synthetic SQL
transition tests, individual store tests and complete runtime tests are separate
evidence. They do not discharge a new atomic or composite formal guarantee.
