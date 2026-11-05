# Organizations recovery redesign proposal

Last updated: 2026-11-04

Status: future plan

Owner: Engineering

Audience: implementers, operators and security reviewers

This is a proposal. Runtime implementation and provider qualification remain pending.

## Superseded recovery proposal

The 2026-11-05 [adopted responsibility rules](recovery-responsibilities.md)
supersede this proposal. Per-operation independent journals, three-phase
confirmation, complete application redo and reproduction of volatile state are
not implementation requirements. Source inventories remain useful references;
the numerical budgets tied to that architecture are withdrawn. See the
[current workplan](recovery-workplan.md) for implementation status.

## Decision and boundary

Use PostgreSQL for all security-authoritative state, retain an independently
administered control journal, and recover individual operations after transport
or process failures. Redis becomes optional for data whose loss cannot increase
authority, reset an enforced security limit or erase replay protection. Select
RDS for PostgreSQL Multi-AZ DB instances as the first managed-service adapter to
implement and qualify. This selects an implementation target, not a cloud
resource, region, size, cost plan or production deployment.

This proposal replaces request-wide PostgreSQL/Redis seal rotation with durable
operation reconciliation. It preserves independent rollback detection, permanent
subject ownership, original authorization ceilings, online currentness, old-writer
exclusion, bounded work and fail-closed handling of missing evidence. Existing
`store-continuity.md` describes the current implementation until a verified
cutover; this proposal does not enable a bypass in that implementation.

The design review and inventory are in [recovery inventory](recovery-redesign-inventory.md)
and [acceptance and review](recovery-redesign-acceptance.md). They cover the
Organizations-enabled dependency closure, including shared protocol state,
management, attributes and LTI. They do not adopt unrelated protocol changes or
resume unrelated proof or physical-measurement work.

The user-selected 10,000 HTTP/s and normal-API p99 <= 200 ms target is specified
in [performance design](recovery-performance.md) and its
[qualification plan](recovery-performance-qualification.md). That supplement
requires three durable phases per logical mutation, exact dependency domains,
partitioned history/lifecycle locks and bounded resources before qualification.
The target is not an observed result or a selected production infrastructure size.

## Storage responsibilities

| Store | Required responsibility | Failure meaning |
| --- | --- | --- |
| Primary PostgreSQL | Organization/identity/configuration authority; sessions; one-use state; token/root/refresh/revocation state; security rate limits; operation receipts; outbox | No protected success from unavailable, unconfirmed or behind-current state |
| Independent control PostgreSQL | Deployment and schema generations; scoped reservations; decisions; accepted history heads; immutable operation recovery records | No new protected admission without current control evidence |
| Optional Redis or local cache | Reconstructible values with current provenance and explicit expiry; non-authoritative coordination or acceleration | Miss/recompute or bounded refusal; never an allow-by-default policy |
| Independent recovery storage | Verified baseline plus complete accepted changes and required protected keys | Restore remains fenced until complete correspondence is established |

The control database is outside the primary administrator's restore authority.
Use separate DB resources, runtime and maintenance principals, administrator and
restore roles, and backup custody. Separate schemas or different database UUIDs
alone are insufficient. Control backups cannot be restored as current authority
without an independent current anchor. Coordinated loss/rollback of every trusted
anchor has no automatic recovery in this proposal.

The primary stores mutable business and security state. The control journal
records acceptance and sufficient recovery material; it is not a second mutable
copy from which callers independently resolve membership. Public runtime roles
must not bypass operation-aware repositories through unrestricted DML or an old
binary. Maintenance and DDL use their own exclusive lifecycle.

Moving security state to PostgreSQL includes all twenty configured shared-store
surfaces. In particular, JWKS key-fingerprint history and enforced login/device
rate limits are not disposable caches. JWKS HTTP bodies can be cached only while
their provenance, expiry and current key policy remain valid. Positive
Organizations introspection remains uncached. Every use still validates current
authority and sender possession.

## Operation identity and records

An operation has a server-established scope, principal, kind, operation ID,
attempt generation, deployment epoch, schema generation, canonical input digest,
read/write dependency set, expected authority versions and absolute validity
limits. The client cannot supply an authority scope or a recovery success flag.
Use unique constraints over the complete scope/kind/ID; the same identity with
different input or principal is a conflict. Internal recovery IDs do not make
OAuth codes, refresh credentials or DPoP proofs externally reusable.

Before execution, the control reservation retains the complete executable intent
in encrypted form, or an already durable independent reference whose content has
been verified. A digest alone supports conflict detection but cannot support
automatic re-execution. Operations with intentionally unretained input may only
be reconciled from an existing receipt or safely aborted after fencing; they must
not reconstruct missing secrets or ask the caller to reuse a consumed credential.

The primary receipt commits atomically with all local effects and outbox entries.
It records exact pre/post versions, the result disposition, deterministic output
identities, recovery material or a verified durable reference, and a digest of
the complete change set. Random values and timestamps needed to reproduce the
result are retained, not regenerated on retry. Sensitive inputs/results are
encrypted with separately retained, versioned keys; logs contain neither those
values nor bearer capabilities.

The recovery payload is a versioned deterministic change batch, bound to its
schema, baseline and predecessor heads. It includes deletes, trigger effects,
generated identifiers and outbox state. Reconstruction applies that batch under
an exclusive maintenance role; it must not rerun business triggers, generate new
random values or repeat external delivery as a side effect of replay. A payload
size/deadline limit is checked before accepting an operation. Oversized work uses
a separately specified bounded maintenance protocol rather than partial capture.

Each scoped history head is an exact predecessor-linked digest, not just a
monotonic counter or WAL position. Registration of every accepted change and
dependency is required. A restore with a newer unrelated WAL position cannot
satisfy an absent accepted change. Hashes authenticate correspondence under the
writer/custody assumptions; hashes alone do not reconstruct lost data or detect
arbitrary administrator rewrites of an otherwise matching database.

## State transitions and publication

| State | Durable evidence | Allowed next action |
| --- | --- | --- |
| Unregistered | No control reservation | Validate and reserve; no protected side effect |
| Waiting | Authenticated bounded writer intent recorded for a conflict; no executable grant | Resolve preceding owners, then acquire complete reservations under the same operation identity |
| Reserved | Control has immutable intent, dependency versions and principal-bound attempt | Execute the one permitted primary transaction or prove it cannot commit |
| Applied | Primary has atomic effects, receipt and outbox; control may still say Reserved | Reconcile the exact receipt and recovery payload; do not publish authority |
| Confirmed | Control atomically accepts receipt, complete recovery record and new heads, then releases reservations | Return an allowed response; make confirmed state usable; dispatch outbox under its own policy |
| Aborted | Primary attempt is durably prevented from committing; control records disposition | Return the recorded failure; release exact reservations |

`Unknown` is an observer's knowledge state, not an extra fact created by timeout.
After a lost primary COMMIT reply, query the unique receipt on the qualified
current writer. After a lost control COMMIT reply, inspect the exact decision.
Never allocate a new logical operation simply because an acknowledgement was lost.

The primary mutation transaction uses `SERIALIZABLE`, locks the applicable
epoch/attempt fence and authority
rows, revalidates authorization and expected versions, performs the changes, and
inserts the attempt grant, receipt/outbox in one transaction. Native uniqueness
and row/predicate locking with serialization-conflict detection handle concurrent
one-use consumption, last-administrator constraints
and competing version updates. Retryable serialization/deadlock failures retry
only the entire bounded transaction with unchanged operation identity and fresh
precondition checks. Transport uncertainty follows reconciliation instead.

Control confirmation checks the same registered intent, complete receipt,
dependency reservations and predecessor heads in one short control transaction.
No control row lock is held during primary, Redis or external network I/O. The
persisted reservation survives between transactions. Confirmation is the logical
publication point for changes governed by this protocol. A successful HTTP
response is later and can be lost; there is no exactly-once network delivery claim.

An Applied mutation must not become a source for a dependent authorization,
token publication or notification before Confirmed. Initial implementation uses
conservative scope gates rather than a second MVCC implementation. Conflicting
operations wait within a bound or are refused. Gates must follow the exact
dependency domains in the performance supplement rather than treating an entire
Environment as one ordinary writer. A durable reservation is released
only after Confirmed or Aborted; age, lease expiry and process disappearance do
not establish either outcome.

An absent receipt is not proof of abort. The recovery worker must acquire the
same primary operation lock and establish a terminal attempt fence, or observe
the original transaction's terminal outcome under the qualified failover contract.
A late old worker must then be unable to commit. If those facts are unavailable,
retain the reservation and report recovery required. Re-execution of a proven
unapplied operation rechecks validity and current authorization; expiry or changed
preconditions can turn it into a recorded abort.

Once a primary receipt exists, recovery confirms that exact mutation instead of
marking it unapplied because its request expired. Confirmation does not renew the
result's lifetime or waive current authorization on response/receipt disclosure.
If compensation is required, it is a new authorized operation with its own
receipt; no terminal decision silently reverses committed history.

## Read protocol and dependency isolation

Every positive authority read uses the following protocol:

1. Read current control epoch, dependency heads and gate revisions, requiring no
   conflicting unresolved writer. Pin that exact vector.
2. Read the primary state and its receipts/heads in one `REPEATABLE READ`,
   `READ ONLY` transaction on the current writer.
   Require exact correspondence with that vector, including permanent histories.
3. Re-read control and require the same vector/gate revisions and no conflicting
   writer or fence before publishing the decision. A change causes a bounded
   retry or refusal, never a stale positive answer.

Gate revisions advance on reservation, terminal decision and lifecycle fence.
This prevents an unconfirmed primary write from being mistaken for accepted
state between two otherwise equal history-head reads. Any later stream chunk
that makes a new authority-dependent read repeats the protocol; lazy bodies do
not escape the retained owner. DPoP replay consumption, session touches and
one-use GET handlers are mutations even when their HTTP method is GET.

The last successful control check is a possible linearization point for a pure
read. Mutations require the primary transaction protocol instead of carrying a
read result across an unchecked write. A revocation's successful response occurs
after control confirmation; checks begun afterward must reject old authority.
Previously admitted external resource I/O may finish, preserving the adopted
profile. No external resource-server transaction is implied.

Reservations use typed read/write dependency sets. Conflicting sets cannot
execute simultaneously; compatible reads and disjoint writes may proceed.
Use deployment/Environment lifecycle dependencies plus explicit policy,
principal/client, membership, root/family, replay-key and collection dependencies.
Do not infer independence from a URL's organization ID. This complete map and its
concurrency evidence are initial implementation requirements for the selected
performance target. A replay-key write
may be independent of another replay key, but its authorization dependencies
remain shared reads. Predicate invariants such as the last administrator are
represented by an aggregate dependency, not only individual member rows.

No new global deployment completion seal is added. Scoped journal partitions
must preserve complete per-scope ordering and cross-scope predecessor vectors;
partition count is not itself a correctness argument. Cross-Environment topology
and shared-principal changes acquire their complete sets in canonical order.

## Writer fencing and ordinary failover

Epochs are checked under a primary lock held until transaction completion. A
check followed by an unlocked later write is insufficient. Operation attempts
are bound to a specific authorized principal and instance; an old worker cannot
fetch a new epoch and thereby acquire a new capability.

Use a distinct coordinator principal to install a primary attempt grant and
apply its effects in the same primary transaction after the matching control
reservation is durable. The grant binds operation ID,
attempt generation, epoch, schema, principal/instance, input digest and complete
dependency set. The coordinator invokes restricted operation functions on behalf
of the authenticated runtime principal; public runtime credentials cannot
install/alter grants, alter fences or perform direct DML on authoritative tables.
Fixed function ownership/search paths and role
separation are part of this boundary. The trusted coordinator validates control
evidence; it is not a generic caller-controlled permission proxy.

Installation is idempotent for the same exact reservation and never reopens a
terminal attempt. Execution holds a server-selected shared lifecycle-shard lock
and exclusive operation lock through commit. Epoch replacement acquires all
lifecycle shards exclusively under the fixed shard manifest. A reconciler uses
the same operation lock to inspect a receipt or create a terminal tombstone,
including when the primary attempt never existed, before recording control abort.
Replacement increments the attempt generation only after closure. A missing
primary acknowledgement follows inspection, not a new grant. Coordinator loss
leaves the control reservation durable and recoverable; runtime possession of an
operation UUID alone grants no write authority. The performance supplement defines
the lock ordering, shard coverage and missing-installation race acceptance.

All primary paths acquire epoch, attempt and authority dependencies in the same
documented order, with dependency keys canonically sorted. A transaction cannot
upgrade its epoch lock into a maintenance fence. Discovering a missing dependency
before effects requires an expanded reservation/revalidation; discovering one
after effects is an implementation defect, not permission to widen the scope.

For controlled epoch replacement: stop new control reservations; establish an
exclusive primary fence after earlier transactions resolve; reconcile their
receipts; install the new epoch and permissions; then activate the corresponding
control generation. If a step is uncertain, inspect its persisted identity.
Credential rotation includes existing-session termination and reconnect refusal
when required by cutover. Credential expiry alone does not terminate a session.

Ordinary restart/failover retains the logical epoch if the selected provider
establishes a current single writer and complete accepted state. Reconnect with
fresh DNS resolution and verified TLS, discard broken pooled connections, check
schema/role/resource identity, and reconcile pending receipts before reopening
their affected scopes. Unaffected scopes resume only when their dependencies
are proved independent. Changed process start time or PostgreSQL timeline invokes
this assessment; neither automatic refusal forever nor unconditional acceptance
is the policy. Normal failover does not require rotating every credential.

Redis process identity no longer participates in authoritative continuity after
all relevant state is migrated. Flush/restart/cache replacement invalidates cache
entries and triggers bounded rebuild. No cache miss grants authority, resets a
security quota, reuses a code or selects an unregistered upstream key.

## External effects and lifetime

Notification delivery and audit export use stable outbox/event IDs. Confirmed
outbox work rechecks required current grants before sending. Record attempts and
acknowledgements durably; deliver at least once where the receiver supports
deduplication. A lost external acknowledgement is not proof of no delivery.
Re-sending the same invitation does not mint a different capability or membership.

An upstream authorization-code exchange may succeed remotely while its reply is
lost. Without an upstream idempotency/status contract, do not retry consumption
or claim exact recovery. Fence the local login attempt against late completion,
record an indeterminate remote outcome, and require a new authentication attempt.
Read-only JWKS/discovery fetches may be retried within their existing destination,
TLS, size, freshness and time constraints. Failed background notification or
cache work does not restart the entire server.

Expiry cleanup is an operation when it changes authoritative state. Retention
must cover original validity, maximum accepted clock skew and all replay/recovery
references. Permanent ownership/tombstone history is never TTL-collected. Active
refresh lineages are not discarded because an access token expired. A safe floor
for journal compaction comes from verified baselines and all retained dependency
references; age or storage pressure alone cannot advance that floor.

## Admission and bounded recovery

Separate foreground, background, revocation and reconciliation queues. Reserve
capacity down to primary/control connections and worker execution, not just an
HTTP semaphore. Derive each configured bound from maximum connection/worker use
and enforce a deployment-wide budget across replicas. Bound unauthenticated
admission separately, before allowing an attacker to create arbitrary tenant
queues. Queue count, byte budget, wait, operation, cleanup and recovery deadlines
are explicit. The existing 30-second request budget is not a failover deadline.

Use recoverable local states: Serving, Throttled, Reconnecting, Reconciling and
Fenced. Capacity rejection starts no durable operation. A failed read-only
preflight invalidates its connection and initiates a bounded probe; it does not
permanently close a process semaphore. Uncertain mutations preserve ownership
for reconciliation. A circuit's half-open probe cannot grant serving authority
without the same current-state validation.

Catalog verification can be reused only for an immutable connection identity and
approved schema generation, with DDL excluded from runtime roles and a controlled
migration/fence protocol. Reconnect, generation change or role mismatch discards
the validation. Until those premises exist, retain current checks. Log fixed
reason codes for overload, unavailable transport, uncertain result, stale epoch,
rollback, capacity exhaustion and required recovery, without secret values.
Liveness remains separate from readiness; a dependency outage must not create a
supervisor restart loop. Recovery uses reserved bounded attempts with backoff and
jitter; exhausted budgets retain evidence and readiness refusal rather than
running an unbounded request or erasing work.

## Disaster recovery and migration

Normal HA failover and restore are different operations. For primary loss or an
old snapshot, keep the destination offline, exclude old writers, select a verified
baseline, and replay every Confirmed recovery record to the current control
frontier. Compare content, histories, operation receipts, tombstones, schema and
dependency vectors. Resolve Reserved operations only from surviving exact
evidence, or prove them unable to publish before recording abort. Missing
unconfirmed primary effects can be discarded only under that publication fence.

To promise recovery of every acknowledged operation after primary loss, control
confirmation must durably retain the complete change payload (or an already
durable, verified independent reference), including required secrets under
retained encryption keys. A digest-only witness or an asynchronous backup cannot
make that promise. Baseline-only recovery and incomplete logical change capture
are insufficient. An initial implementation must refuse this recovery class
until complete payload coverage and reconstruction are qualified.

Restoration enters a fresh security epoch and invalidates pre-restore credentials,
as required by the existing profile. Reconstructed permanent ownership, revocation
and refresh history still prevents identity/grant resurrection. Do not preserve
old-token validity merely because state can be reconstructed. Missing control
anchors or necessary keys remains an explicit unrecoverable condition for automatic
activation; no forced clear or checkpoint edit is provided.

The migration from Redis uses a bounded maintenance cutover: stop new issuance,
drain or reconcile all writers, snapshot every authoritative namespace, migrate
and compare complete unexpired state plus permanent histories, exclude old
credentials/processes, then activate the new epoch. Unmigratable ephemeral
challenges require an explicit expiry/reauthentication policy, never treating
missing used-state as unused. No dual-write fallback chooses a winner on error.
Organizations-disabled deployments retain their existing supported backend until
separately migrated. Return to the old implementation after new-format writes
requires a validated forward conversion; a branch rollback is not data recovery.

## Managed provider contract and alternatives

RDS PostgreSQL 18 is the initial adapter family; exact minor version, region,
extensions, privileges, parameter values and deployment type must be pinned
before qualification. AWS documents synchronous standby replication for the
[Multi-AZ DB instance](README.md#aws-redesign-sources).
The adapter must support an authenticated resource identity, writer replacement,
current reads, acknowledged-commit durability, restricted runtime SQL and
administrative fencing/session termination. RDS exposes neither host OS access
nor a normal PostgreSQL superuser; rewrite those existing operator/catalog
assumptions explicitly rather than adding an allow-RDS bypass. See
[RDS privileges](README.md#aws-redesign-sources).

AWS describes [failover](README.md#aws-redesign-sources)
as usually taking 60–120 seconds, with existing connections requiring
re-establishment. This is not a maximum recovery guarantee. IAM authentication
tokens do not end established sessions when they expire; see
[IAM database authentication](README.md#aws-redesign-sources).
Do not assume RDS Proxy resolves an unknown COMMIT or supplies operation identity.
Automatic read-replica routing is prohibited for current authorization checks.

MemoryDB and synchronous ElastiCache Valkey durability are credible alternative
authoritative suppliers, but they retain SQL/Redis cross-store recovery and
cluster key/script constraints. MemoryDB documents durable successful writes and
strong primary consistency across failover, with eventual replica reads:
[consistency](README.md#aws-redesign-sources).
ElastiCache synchronous durability persists before reply; asynchronous durability
can lose acknowledged changes, and even durable clusters need an appropriate
eviction policy: [options](README.md#aws-redesign-sources).
Its [limitations](README.md#aws-redesign-sources)
include Valkey 9+, cluster mode, Multi-AZ/replica requirements and no Serverless
support. These alternatives should be reconsidered only against a demonstrated
SQL throughput/resource limitation and a complete supplier-specific contract.

The SQL-first choice incurs additional primary/control writes, indexes,
encrypted history storage and garbage collection. Scoped concurrency and removal
of repeated catalog/three-store seal I/O address the current structural costs;
no throughput increase is claimed without measurement. Regional catastrophe,
administrative compromise and simultaneous control/key loss require separate
explicit recovery contracts, not an implication from Multi-AZ.
