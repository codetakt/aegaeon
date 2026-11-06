# Retained Organizations store observations

Last updated: 2026-11-04

Status: historical record

Owner: Engineering

Audience: implementers, operators and security reviewers

## Superseded operational design

This page records predecessor behavior and its source-scoped evidence. Its
control-store, paired-seal, generic history-replay and credential-cutover commands
are not shipped or supported by the current implementation. Use the
[current generation contract](runtime-generation.md) and
[restore runbook](restore-runbook.md). Predecessor code retained under test-only
modules is not a production fallback. Historical test results below do not prove
the replacement implementation.

## Purpose and limits

This component contributes to ORG-R17/R18/R19/R21, ORG-G10/G11 and
ORG-P08/P11/P12/P13/P14. It retains observed PostgreSQL progress and exact
PostgreSQL/Redis incarnations in the selected control store across observer loss.
It does not qualify that store's independent durability, prove absence of logical
rewrites or VM rollback, complete pending work, or authorize activation.

The [import and restore contract](import-activation.md) still requires actual
supplier qualification, current history, credential recovery and cutover. The
production factory must bind actual selected connections to these observations,
check new connections before authority operations, and retain their work through
cleanup. Enclosing runtime and final completion integration remain required.
There is no new public OAuth/OIDC field or enablement switch.

## Durable observation protocol

This section records the original version-six component protocol. For a current
installation, apply versions one through sixteen in order as described in the
[reference control store](reference-control-store.md), including the
[drained restart protocol](store-continuity.md).

Install `db/organization-witness/schema-v6.sql` after versions one through five
with service writers stopped. Previous schema bytes, state and credentials remain
unchanged. The client requires the exact version-six catalog. Each already
bounded retained epoch has at most one checkpoint; each Environment has at most
64 current observation rows, indexed by its existing admission slot. Reusing a
slot preserves the preceding epoch's checkpoint. No history is deleted to make
room, and exhausted control counters retain their existing refusal behavior.

Maintenance rechecks the owned PostgreSQL and Redis connections and pins their
actual observations only under
the exact drained prepared operation and revision. The record binds the selected
epoch and primary/token-store UUIDs to the PostgreSQL cluster, database OID/name,
postmaster start, timeline, WAL position and Redis process/database. Repeated pinning under the same operation, revision and incarnations returns
the original record when the newly observed WAL is at least its initial value.
It never rewrites that checkpoint. Lower progress or conflicting replay refuses. It cannot replace
an earlier epoch's observation or change a serving selection.

A runtime begins an observation with its exact live pending admission. The
authority lock records the then-current retained WAL minimum before the caller
observes its actual connections. A repeated begin refuses: loss of the reply
does not create another executable handle. Rust borrows that admission in an
opaque, non-cloneable handle with no public deserialization path.

The Rust recording entrypoint rechecks both owned connections itself; retained
observation values cannot be supplied in their place. Each read retains its
five-second deadline and permanently discards its handle on failure.

Completion requires the same Environment, deployment, epoch, slot, generation,
work UUID and authenticated runtime principal. Both store incarnations must match;
the newly observed WAL position must be at least the beginning minimum. The
retained maximum becomes `max(previous, observed)`, allowing concurrent
observations to finish out of order without moving retained progress backwards.
An exact finished replay is only a receipt. A different value refuses. Fencing
prevents new observations but permits recording one already begun under that
pending epoch. Recording never releases the admission.

These comparisons assume authenticated observations from the actual selected
connections. A raw SQL argument is not physical evidence. The finite SQL checks
do not by themselves detect a logical rewrite, a cloned store or restoration of
the observer and store together. Normal admission and restore must separately
establish their supplier premises and continuous connection boundaries.

## Bounds and required evidence

Primary JSON is at most 1,024 bytes and token-store JSON at most 256 bytes, with
exact keys and types. Database names use PostgreSQL's 63-byte bound. OIDs,
timelines and Redis database indices retain their unsigned 32-bit domains;
WAL positions retain all unsigned 64-bit values without signed conversion or
decimal rounding. Functions use the existing finite control-client deadlines.
Runtime and maintenance receive only their distinct fixed function capabilities;
neither can read or write the retained tables directly.

Required cases include normal actual observations, pin conflicts, scoped and
principal refusals, malformed input, all integer boundaries, stale slot reuse,
fence races, lost acknowledgements and out-of-order completion. Retain negative
controls for the progress and incarnation checks, exact catalog correspondence
and stopped-upgrade preservation. SQL transition tests with synthetic
observations are separate from actual-store and transport-failure tests. These
component checks do not discharge a composite proof obligation.

## Current construction boundary

The mandatory parent constructor in [observed connection construction](observed-connector.md#mandatory-parent-construction-2026-11-03-successor)
supersedes the standalone begin/start API names in the historical sections below.
The same observation, finite-response and retained-cleanup contracts now apply
through `deployment::dispatch::Dispatcher` and its parent/child owners. Diagnostic
connections remain observational; the removed standalone serving API has no
permission fallback. Runtime roles still cannot acquire a child without a parent.

The current catalog also requires [post-work durable seals](store-continuity.md)
before parent completion. A drained restart may atomically rebind physical
incarnations after both actual seals, stable identities and every retained floor
are checked under the independent lock. Historical checkpoint values are retained.
Per-connection checks never ignore incarnation changes, and unresolved work is
never cleared by restart acceptance. The version-six sections describe the
underlying observation contract, not the complete current installation sequence.

## Actual data connection composition

`Work::begin_observed` obtains the exact pending admission and retained minimum
before authority operations. It keeps the owned PostgreSQL and Redis metadata
links and an opaque shared observation state until work completion. It is a
runtime component; it does not qualify suppliers or mount production routes.
Production construction must use this boundary after the supplier requirements
are satisfied. The lower-level `Work::begin` remains a component interface and
cannot substitute for this observation contract.

The admitted primary-pool path observes each actual checked-out connection before
returning it to repository code, then rechecks it after protocol cleanup and
before pool return. The owned Redis driver observes its actual process and
selected database during preparation and before and after each command or
pipeline. These reads share the existing finite driver deadlines; no connection
is silently replaced. Different incarnations, unsafe primary settings, lost
observations or progress below the beginning minimum close the admission class
and retain durable pending work.

All primary observations contribute to a retained in-memory maximum under a
bounded critical section. Out-of-order callbacks may report positions below that
maximum but cannot erase it. Once every data and cleanup owner has finished, the
same owned metadata links are rechecked. The final primary position must cover
that maximum; the witness records it before the durable admission is completed.
A failed final observation, record, connection close or completion cannot report
success. Response cancellation retains the existing detached worker and cleanup.

These checks cover the admitted pool and owned Redis driver. Complete startup,
HTTP/background mounting, other raw connection paths, actual independent supply,
logical rewrite exclusions and restore/cutover acceptance remain separate. The
component adds no public protocol field, configuration bypass or activation API.

### Owned HTTP execution

`Work::start_observed` and `Work::start_http_observed` take ownership of local
capacity synchronously before polling their connection future. The future yields
`ObservedConnections`, which owns the control, primary and Redis links but does
not confer supplier qualification. The observed execution always enters
`begin_observed`; an observation or connection failure has no unobserved fallback.

Both observed and lower-level HTTP execution share the same body implementation.
Finite response success follows actual store work, bounded body materialization,
cleanup, final observations and durable completion. Snapshot execution keeps its
one-frame channel, existing progress deadline and terminal completion frame.
Lazy producers remain inside the checked store scope through EOF or trailers.
Dropping the response waiter cannot abort the owned worker or clear its slot.
The existing ordinary and snapshot execution budgets remain unchanged.

Native acceptance includes actual PostgreSQL and Redis mutations, a foreign
Redis database, loss of the final observer after committed effects, lazy body
production and response cancellation. Startup/router/background installation and
supplier qualification are still required before production use.

### Production progress arithmetic

The actual observation accumulator and final completion check call
`aegaeon_pure::organization_progress`. The retained-position function accepts
exactly when both the previous maximum and the new observation cover the captured
minimum, returning their exact maximum. The final predicate requires a valid
maximum and a final position covering it. Both functions retain the full unsigned
64-bit domain without wrapping, truncation or saturation.

The registered `organization-store-progress` Kani group imports those production
functions directly. Its two harnesses use arbitrary unsigned inputs and separate
signed 128-bit differences as their range oracle. Guard-removal controls must
falsify the corresponding harness. These are two executable component harnesses,
not two newly discharged composite or baseline atomic obligations. Actual fresh
reads, all caller coverage, serialization, independent SQL storage, ownership,
suppliers and final acceptance remain separate obligations.

### Protocol composition evidence

The explicit observed caller fixture runs the existing authenticated authorization
code, Token Exchange, RS256 JWT and JSON/signed-introspection flows with actual
PostgreSQL and Redis observation retention. It also composes own-resource GET/HEAD,
foreign Environment and capacity refusals, epoch retirement, fresh authorization
and rejection of the old root. Current checkpoint records and zero pending work
are checked after the real protocol consumers complete. A separate mounted
resource GET/HEAD flow uses observed HTTP execution through body completion and
checks exact public UUID/external-ID representations.

This fixture uses a dedicated primary database and a separate witness database
on the same test cluster, with only the required builtin observation grant in
that disposable primary. It is test supply, not independent nonrollback
qualification or production router installation. Its inventories overlap prior
protocol tests and do not discharge a composite proof obligation.
