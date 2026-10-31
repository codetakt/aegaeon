# Organizations runtime authority epochs

Last updated: 2026-10-31

Status: active plan

Owner: Engineering

Audience: implementers and security reviewers

## Contract

This refines ORG-R17/R18/R19/R21 and ORG-G10/G11, contributing to
ORG-P02/P06/P08/P10/P11/P12/P13/P14/P15. It follows the independent witness and
owned-work contract in [import activation](import-activation.md). It does not
qualify an independent supplier or enable production activation.

A protected epoch binding contains version 1, Environment UUID, immutable
deployment UUID, authority epoch UUID and the selected primary/token-store UUIDs.
All five identifiers must be nonnil and match the actual acquired witness
admission exactly. These are structured fields, not prefixes embedded in object
IDs. Public organization UUIDs, exact scoped external IDs, OIDC subjects and
standard token fields keep their existing representations.

A serialized binding is data, never an admission credential. A current witness
acquisition constructs the live comparison value after the fixed SQL supplier
checks its active selection. Deserialized metadata must match that value; merely
being well formed or matching a locally cached configuration is insufficient.
Missing fields, unknown versions, nil IDs and unknown fields refuse. No decoder
fills a missing epoch from current state. A retained binding can be compared
only inside an open owned-work boundary, which remains pending through every
primary/token-store operation and its confirmed cleanup.

## Binding to an actual worker

Only the opaque durable admission returned by the live control store can bind
an epoch to local request work. Binding occurs once, before any tracked primary
or token-store operation, with the coordinator as the sole local owner. A local
permit that already entered a store scope, blocking store worker or connection
checkout cannot be upgraded after that work, even if it has since completed.
Clones share the immutable binding; a derived snapshot-authority owner inherits
its parent's binding and retains that parent. It cannot acquire another epoch.
No deserialized binding or setter accepting ordinary record data is exposed.

Protected-record consumers can compare the stored binding against this actual
owner only while its admission remains open. A bare local permit, another
Environment/deployment/epoch/store selection, or closed admission refuses.
This connects the coordinator to its retained owners, not all runtime callers or
the forthcoming protected-record fields. Caller completeness and live supplier
qualification remain required; raw operations outside these boundaries cannot
be justified retrospectively by acquiring a witness.

## Protected record integration

The original consent snapshot and its immutable root authority must capture the
binding before display and recheck it at approval/code issuance. Authorization
code redemption, refresh lineage and selected-token metadata retain the exact
same binding; exchanging, refreshing or deserializing a record never upgrades it
to a new epoch. Original consent and selected authority use an explicit new
internal record version when that integration is introduced. Earlier records
remain historical and cannot grant Organizations authority without a fresh
original authorization.

Invitations, recipient challenges, enrollment/recovery requests and temporary
administrative grants require the corresponding protected binding at creation
and every use. Their migration preserves historical IDs and status separately
from capability usability. An imported or restored record never inherits the
selected epoch merely because its object UUID is unchanged. Audit and export
must retain the historical binding when their versioned format is extended.
The parser must distinguish a historical format from a current activation input.

These field integrations are subsequent implementation work. The typed binding
and witness coordinator alone do not establish their caller coverage. No new
JWT or introspection profile field is introduced by this component; any later
public extension requires its own versioned contract and compliance tests.

The Authorization Server DPoP worker captures the explicit task owner before
detaching its nonce/replay work, just as the own-resource proof worker does.
Its existing proof-capacity bound and error precedence remain. Lost replay
acknowledgement closes that owner and retains the durable pending slot even when
the HTTP response is an error. An ordinary error response is not completion
evidence for a successful upstream replay mutation whose acknowledgement was lost.

Browser authentication sessions, OIDC sessions and logout delivery transitions,
browser step-up workers and private-key client assertion validation also capture
an explicitly entered task owner before detaching store work. Their async
facades use the same bounded worker mechanism; outside an Organizations scope
they retain ordinary behavior and acquire no Organizations authority. This is
explicit ownership propagation, not a substitute for entering the enclosing
browser/token/introspection admission or for supplier qualification. A lost
browser-session read reply closes the current owner too; a successful upstream
read alone does not prove that the tracked driver and its barrier completed.

## Runtime admission and recovery

Organizations admission requires explicit configuration, a qualified independent
supplier, fresh current selection and verified selected-store identity. These
checks precede authority-bearing store work. The witness runtime login cannot
initialize, fence, prepare or activate authority. Maintenance credentials never
enter ordinary runtime state. Failure refuses with the existing unavailable or
inactive result; no positive decision cache or administrator bypass is allowed.

Primary cleanup is only one owner. Redis command/driver threads, proof workers,
root guards, session reads and detached HTTP workers must retain the same work
admission. A command timeout or transport close cannot prove that Redis finished
its mutation. Uncertain command completion must keep the durable slot pending
until qualified reconciliation. Connection preparation that cannot yet have
performed authority work is a distinct case and must retain its actual owners.

Primary connection cleanup has a 30-second absolute deadline covering protocol
draining, timeout restoration and pool return. Server statement deadlines cannot
bound a missing network response or a pool hook. Expiry closes local admission;
it never supplies completion evidence or clears a durable witness slot. Any
detached supplier work remains part of explicit reconciliation. This bounded
wait is independent of the request response deadline and the coordinator's
completion wait.

`Work::blocking` installs the admission on its owned synchronous worker thread.
Redis facades created there capture that admission; both the facade and its
driver retain it through runtime/resolver shutdown. A facade from another work
boundary or one opened outside the boundary cannot be used inside it. The scope
is thread-local, never process-global, and ends even on panic. Nested scopes and
untracked child threads are not supported; callers must keep all token-store
work in this boundary or explicitly carry the same admission to another owner.

For scoped Redis commands, the same connection must acknowledge a trailing PING
with PONG within the original command deadline before reporting completion.
This ordered barrier covers every response in a pipeline, including script-cache
misses. A missing or malformed barrier, lost response, cancellation or worker
panic closes local admission and leaves the durable slot pending. It never
retries an uncertain mutation. This relies on the pinned standalone Redis
command supplier: authority mutations use synchronous commands/scripts, never
background jobs, cluster redirects or commands that change protocol mode.
The barrier proves processing order, not persistence, store identity or rewind
resistance; those qualification obligations remain separate. Existing unscoped
store operations retain their current behavior.

The same explicit owned blocking boundary is available on a local request
admission. Management-session lookups, resource DPoP and token validation, delegated and
support root checks and enrollment password work must use it rather than merely
retain a permit in an otherwise unscoped thread. This connects their actual
Redis driver ownership and panic handling. It does not create a durable witness
admission by itself. Browser/issuer workers and the complete enclosing runtime
admission still require their own caller integration;
the explicit workers above are not a claim of complete coverage.

An explicitly entered asynchronous store scope carries the same admission as
task-local state while polling its future. Token and authorization-code async
facades capture it before starting each blocking worker; the worker then enters
the existing synchronous Redis scope. This preserves ownership across async
suspension without putting an admission in process-global state. Outside an
explicit scope, existing non-Organizations facade behavior is preserved.
Nested scopes refuse. A cancelled or panicking scope closes local admission;
already started blocking work still retains its owner through actual cleanup.
Successful scope return requires the class to remain open. A spawned async task
does not inherit task-local state: its caller must carry the admission and enter
a new explicit scope. This is a caller obligation, not implicit propagation.
The own-resource middleware enters this scope around its entire detached worker.
Resource authentication requires that the current scope matches its request
admission before calling token facades; a missing or foreign scope refuses.
The browser invitation credential form shares this boundary. Its CSRF generation
and one-time consumption capture the task admission before starting their
blocking workers, and use the bounded Redis driver through confirmed completion.
All CSRF operations use that driver with finite connection/command/lifetime and
capacity bounds, including callers outside Organizations. Outside an explicit
Organizations scope they gain these bounds but no Organizations authority.
Lost CSRF mutation acknowledgement closes the admitted Organizations class; a
fresh request on a healthy connection cannot bypass that closure. Body admission
remains before the detached worker for GET/HEAD. Existing POST byte/time bounds
remain enforced inside the owned worker, which survives response cancellation.
Issuer, browser and introspection entrypoints still need complete enclosing
runtime admission before this facade mechanism can cover their operations.

An acquired authorization-code exchange lock also retains its original admission
after being returned from a blocking worker. Explicit synchronous/asynchronous
release and its detached drop cleanup use that owner, including a matching Redis
scope. Failure to start cleanup or loss of its execution closes admission. Lock
TTL alone cannot supply successful completion or clear a durable witness slot.

A control-store FATAL/PANIC response or connection-class/shutdown SQLSTATE
invalidates the client connection just like transport loss. Only an ordinary
PostgreSQL ERROR response can retain a connection for a subsequent command.
Fatal refusal never retries an uncertain command or clears a durable slot.
A successful local close after discarding that connection is cleanup only.

Process restart does not forgive prior uncertain admissions. Startup must bind
its instance and selected stores through the qualified recovery boundary before
serving. A live primary/Redis server restart, rewind, replacement or failover must
refuse old authority until independent history reconciliation and a fresh epoch
complete. A timestamp, process ID, Redis run ID or stored local marker alone is
not sufficient qualification. The store identity supplier and independent current
permanent-history supply remain separate implementation and proof obligations.

Acquisition owns a cancellation guard before its first control-store await.
After the fresh, exclusive local-owner check, acquisition error, cancellation
or panic closes that local admission class. Only a successful live acquisition
and binding can hand the owner to `Work`. Dropping `Work`, cancelling completion
or failing completion also closes the class. The guard is disarmed only after
explicit durable completion and control-connection cleanup both succeed.
No destructor issues a completion command. Cancellation may race with an actual
server commit, so transport cleanup cannot infer whether acquisition took a
durable slot; any such pending slot still requires qualified reconciliation.

Authorization parsing and request-object replay, PAR persistence/continuation,
local-login and recovery CSRF parsing, login rate limits, upstream authentication
and logout continuations, JWT-bearer proof replay and management-session facades
also retain an explicitly entered owner on detached store work. The same bounded
worker path preserves ordinary behavior outside that scope. This closes these
worker-propagation gaps; it does not qualify background cleanup, deployment supply
or the still-required enclosing runtime admission.

An async store facade never treats a synchronous Organizations thread scope as
an ordinary unowned call. A thread-only async invocation refuses before spawning
work; with both explicit task and thread scopes, their owners must match. A
synchronous store closure must not drive unrelated asynchronous tasks under its
thread-local context. This caller precondition is checked at the async worker
boundary, in addition to protected-record checks. Only the absence of both scopes
permits the ordinary unscoped path; a missing task scope, conflicting owner or
closed admission is never an allow fallback.
