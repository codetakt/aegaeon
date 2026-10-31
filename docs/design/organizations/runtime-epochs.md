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
This connects the coordinator to its retained owners. Complete runtime caller
coverage and live supplier qualification remain required; raw operations outside these boundaries cannot
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

Original consent and selected-authority records use internal version 2 with an
`epoch` field holding this exact binding. Version 1 or a missing binding may be
decoded for historical custody, but cannot bind a new root or authorize use.
Capture reads the binding from the actual current owner before its first SQL
read. Code issuance, original-authority validation and selected-authority use
require that same current owner. Refresh and exchange preserve the protected
binding; they cannot replace it from configuration or a new request.

The explicit async task scope or synchronous worker scope supplies the owner.
When both are present they must refer to the same work. A missing, closed,
unbound or foreign owner refuses. Spawned tasks still require explicit ownership
transfer. Data-only shape checks and deserialization do not establish current
authority. Tests with serialized epoch metadata alone cannot substitute for
actual live witness acquisition in the native caller tests.

The common synchronous/asynchronous refresh-grant validation used by authenticated
introspection and token consumers checks the original binding even for an
unselected parent token. Selected metadata must carry the same version-2 binding;
a selection without original authority refuses. This check precedes grant-store
liveness checks and does not replace current membership, recipient, root, sender
or signed-content validation. The public signed-content verifier remains a
content-correspondence check with those separate caller preconditions.

These protected-field checks are implemented. Complete runtime caller coverage
still requires the enclosing entrypoints and their qualified suppliers. No new JWT,
authorization-details or introspection profile field is introduced; the internal
epoch is not serialized into those existing public representations. Their
standard/profile conformance remains separate from this internal record version.

Consent capture, Token Exchange selection and introspection reuse the existing
epoch-bound owner before opening their primary connection. Acquiring another
local permit inside these consumers is insufficient: the witness would not own
that connection's later cleanup. Own-resource current-state evaluation also
requires its supplied admission to be the current task's exact owner. Missing
ownership or another Environment refuses before these primary queries. The
enclosing runtime entrypoints must establish this owner before earlier token or
browser-store operations; consumer reuse alone does not complete that integration.

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

Temporary administrative grants retain the original consent's exact epoch in
immutable internal authority metadata. Activation and replay require the actual
current owner; selection and current-state validation independently compare the
grant's binding. A new original authorization cannot upgrade a retained grant.
Missing bindings remain decodable for historical custody and authenticated
read/revocation, but cannot authorize selection or activation replay. Present
bindings must be well formed and agree with the record Environment. Nonsecret
export retains this field exactly; import is still inactive and never fills it
from destination configuration. This implements the temporary-grant part of
ORG-R12/R17/R19, ORG-G08/G10/G11 and ORG-P09/P10/P11/P12/P13; enclosing runtime
admission, independent supply and full recovery qualification remain separate.

Historical parsing is independent of live authorization. Version-1 original and
selected records without epochs and version-2 records with exact matching epochs
can be structurally checked at their recorded issue time without opening a live
witness scope. That check returns no root or permission. Live consumers continue
to require version 2 and the actual current admission. In particular, export and
inactive import of a delegated invitation cannot require its old epoch to remain
active, and cannot fill or normalize missing historical fields.

Invitation authority now captures a versioned epoch binding before creation
reads. Both operator and delegated invitations compare that binding on every
live use and issuance replay. Its recipient challenge, registration and recovery
requests retain the same epoch through their immutable, scoped invitation foreign
key. Runtime column privileges forbid changing that reference or the parent
binding; startup preflight verifies those privileges. Every child creation,
delivery and acceptance/completion path loads and checks that parent before using
its capability. No child can acquire a new epoch by retrying or by changing its
recipient/root. Historical read and terminal revocation remain separately
authorized; they do not revive capability use. Export retains the original binding
and inactive import preserves it without assigning destination authority.

This normalized representation avoids divergent copies of the parent binding.
A missing historical binding cannot serve. A present binding must have the exact
Environment and supported version. Database ACL, actual epoch retirement, replay,
child delivery/acceptance, historical custody and removed-check regressions are
required for ORG-R07/R12/R16/R17/R19, ORG-G07/G08/G10/G11 and
ORG-P07/P09/P10/P11/P12/P13. Enclosing runtime and supplier qualification remain open.

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

## Reusing the enclosing HTTP admission

The own-resource route must reuse an already entered, live witness admission
before DPoP, session or token-store work. It must match the Environment and the
route's capacity class. Ordinary work cannot borrow the revocation reserve, and
snapshot work cannot substitute for either. A foreign, unbound, closed or
thread-only scope refuses without falling back to a fresh local permit.

A detached resource worker explicitly carries that same owner and enters its own
task scope. The enclosing coordinator remains responsible for durable completion;
the inner route never completes, rebinds or upgrades the witness. Requests without
an enclosing task retain the existing local capacity mechanism, which cannot
satisfy the protected epoch requirement. This is a caller-integration step, not a
production supplier constructor. The enclosing startup/admission boundary and
qualified independent store/history/recovery supply remain required.

Actual HTTP token issuance and resource consumption, separate fresh work slots,
epoch retirement, foreign Environment, capacity confusion and removed-owner
regressions cover this integration for ORG-R10/R13/R17/R18/R21,
ORG-G04/G06/G10/G11/G12 and ORG-P02/P06/P08/P12/P13/P14/P15.

The browser authorization and consent middleware also captures the explicit
ordinary epoch owner before it detaches its worker. It re-enters that scope while
polling the handler, independently of its existing browser response budget.
A changed Environment or capacity class refuses before browser/store work. The
browser worker cannot infer epoch ownership from a cookie or consent payload.
Tests retain the original browser workflow and add retirement between display and
approval, under real witness slots. Shared runtime-authority SQL acquisition and
the earlier enclosing middleware remain separate caller-coverage obligations.

Shared runtime-configuration and client-projection reads must retain the current
Organizations owner during pool acquisition, SQL cancellation, protocol draining
and pool return. Their existing DCR admission is independent and is retained too
when both scopes apply. Successful inner cleanup must precede releasing either
capacity; uncertainty closes both affected local classes and keeps the witness
pending. Ordinary reads outside an Organizations scope keep the DCR adapter's
existing behavior. A missing async task in a synchronous thread scope refuses.
This covers these shared reads; it does not qualify every raw primary caller or
background authority writer. ORG-R19/R21 and ORG-G10/G11 remain open for that
full-domain integration and supply; this component contributes to ORG-P12/P13/P14.

Consent, reauthentication-login and logout-confirmation storage use the same
admitted primary adapter for create, load and single-use transitions. The bounded
continuation transaction borrows that owned connection, preserving its Environment
lock, retention/rate limit and read-committed counts. Its statement budget may
shorten but never lengthen a stricter configured deadline. Cancellation and lost
acknowledgement keep actual connection cleanup under the request owner. Expiry
cleanup and the complete primary writer/supplier inventory remain separate.
This extends ORG-R09/R10/R17/R19/R21 and ORG-G04/G05/G10/G11 coverage under
ORG-P05/P06/P08/P12/P13/P14 without claiming full composed proof discharge.

These browser storage mutations explicitly admit their autocommit statement or
transaction commit under the same closure lock as the request owner. A commit
admitted before closure may finish afterward; newly attempted commits refuse.
There is no database I/O under that lock, and cleanup remains owned in either
case. The bounded prune-only commit uses the same boundary. This local admission
check does not replace epoch/current-state authorization or independent history
qualification.

Browser continuation tests that reach protected authority require a real witness
scope. The finite-body test keeps raw incomplete TCP submissions before store
work, while its normal display/approval path uses the actual owner. The known
closed-pool case tests reloading runtime configuration against the same unchanged
stores and live epoch; it is not store restoration, rewind reconciliation or
permission to clear uncertain pending work. Store-response loss and cancellation
remain separate recovery cases requiring complete enclosing runtime integration.

An admitted finite operation can transfer its `Work` into the owned execution
coordinator before polling its store future. Response-waiter cancellation then
drops only the join handle; the worker retains the witness and performs explicit
completion after all retained store and cleanup owners finish. The result cannot
escape before that completion. Panic, closed admission or uncertain cleanup keeps
the durable slot pending and closes local admission. This preserves the existing
failure rule rather than clearing a slot on a client disconnect.

This finite-operation API requires a materialized result: every store operation
and any stream producer must finish inside its future. A lazy HTTP body that will
access stores after return violates the caller precondition and cannot be used
by the eventual router adapter. Full HTTP body/stream lifecycle integration and
the qualified production admission factory remain separate. Actual SQL execution,
response cancellation and a removed-worker negative control contribute to
ORG-R19/R21, ORG-G10/G11 and ORG-P12/P13/P14; they are not a composite discharge.

The finite coordinator enforces one absolute 30-second deadline, starting before
worker creation and including execution, retained-owner cleanup and witness
completion. Timeout closes local admission and leaves any unconfirmed durable
slot pending. Dropping the response waiter cannot reset or extend the deadline.
It is not the snapshot stream coordinator. The historical browser-capacity fault
fixture isolates its pre-authority, unscoped failed-store path; its healthy
Organizations requests now use separate actual witness admissions. That fixture
does not prove reconciliation after epoch-owned response loss.

The acquisition execution entrypoint transfers a fresh local permit into an owned
worker synchronously, before awaiting control connection or witness acquisition.
Its response handle may be dropped without polling; that does not cancel the
worker. One absolute 30-second deadline covers connection, admission, operation,
retained cleanup and completion. Connection/acquisition failure or timeout closes
the affected local class. Before a successful live acquisition, no selected-store
operation is polled. The control future may only open the independent runtime
link; it cannot substitute primary/token work or serialized metadata for admission.

This closes the response-waiter ownership window around acquisition. It does not
construct a qualified production control supplier or permit restored stores to
serve. A complete router adapter must bind Environment, route capacity, actual
supplier and materialized/streamed response lifetime before using it.

The HTTP execution adapter owns acquisition, handler execution and polling of the
response body in the same admitted scope. Ordinary/revocation responses are
materialized within the existing 64 KiB Organizations representation bound and
exposed only after owned completion; in particular token bytes cannot escape
earlier. Snapshot responses relay frames through one bounded slot and publish
trailers and successful end-of-body only after all
store/cleanup owners and the durable slot have completed. It removes a declared
Content-Length on streamed responses so transport framing cannot report success
before this terminal check. A failed producer, panic, deadline or uncertain
completion produces a body error, including after a buffered final frame. HEAD,
204 and 304 responses wait for completion before exposing their headers because
HTTP transports need not poll those bodies. Informational/upgrade responses are
unsupported and refuse; this adapter cannot transfer untracked upgraded I/O.

The whole operation starts its absolute deadline before acquisition: 30 seconds
for ordinary/revocation work and one hour for the separately admitted snapshot
class. Body progress has a 20-second bound. A disconnected receiver stops further
body polling, drops the producer, and waits for retained actual cleanup owners;
it does not cancel the owned coordinator or infer completion from the socket.
An uncooperative body poll cannot be interrupted by a Tokio timer; supported
handlers, bodies and cleanup must yield with bounded work per poll. Frame memory
and total payload bounds remain the producers' versioned contracts; the adapter
does not admit unbounded producers or buffer a complete 64 GiB snapshot.

This component contributes to ORG-R17/R19/R21, ORG-G10/G11 and
ORG-P08/P12/P13/P14. Router coverage, actual supplier qualification, store rewind
detection, current independent history and restore/cutover remain required before
production activation. The adapter does not introduce a qualification flag or
make serialized configuration authoritative.

Management Organizations routes reuse an enclosing owner only when the actual
matched Environment and route's ordinary/revocation/snapshot capacity match.
Malformed path scope or an existing foreign/closed owner refuses before authority
reads, with no fresh-permit fallback. The detached snapshot producer explicitly
re-enters its retained scope and keeps the same owner through live page checks,
SQL rollback and pool return. The enclosing HTTP coordinator must include this
producer in durable completion; returning headers alone is insufficient.
These ORG-R17/R19/R21, ORG-G10/G11 and ORG-P08/P12/P13/P14 caller changes still
require the qualified production factory and restore/current-history integration.

Invitation and identity-envelope delivery must reuse the actual current epoch
owner before opening their primary connection, including delegated root reads.
A separate local permit cannot account for delivery cleanup in the enclosing
witness. A cancelled response waiter may leave pool return running; that owner
must still prevent durable completion. This contributes to ORG-R13/R14/R19/R21,
ORG-G04/G10/G11 and ORG-P07/P12/P13/P14. Actual TLS delivery and controlled
pool-return regressions exercise this boundary. Production startup and complete
background-writer admission remain separate requirements.

Management runtime-command reconciliation has two explicit entrypoints. The
legacy global sweep may run only outside every Organizations owner scope. An
Environment-scoped sweep requires a live epoch owner for that exact Environment
before acquiring its primary connection, and its locking query selects only that
Environment. Each pass keeps the existing 100-command limit and atomically commits
the failed-unconfirmed transitions with their audit records. The owner must still
admit that commit; connection return remains owned after response cancellation.
A missing, foreign, closed or thread-only owner refuses without a global fallback.
The scoped scheduler path selects this entrypoint explicitly. Global scheduler
admission and complete writer coverage remain separate integration obligations.
These changes contribute to ORG-R19/R21, ORG-G10/G11 and ORG-P12/P13/P14; they do
not reconcile uncertain witness work or establish restore qualification.

Local credential Environment resolution, password verification/currentness,
credential-state reads and one-time recovery-token redemption now use the same
admitted primary adapter. Recovery commits and password currentness updates
check the existing closure boundary before committing. Periodic continuation
expiry cleanup retains its connection through actual rollback/drain/pool return,
keeps stricter statement budgets, and checks commit admission. Its blocking
store workers and counter reads capture an explicitly entered async owner.
These caller changes preserve ordinary behavior outside an Organizations scope;
they do not establish the background scheduler's enclosing witness or qualify
its suppliers. Actual primary return/cancellation, one-time redemption and
removed-adapter regressions contribute to ORG-R19/R21, ORG-G10/G11 and
ORG-P12/P13/P14. Complete writer coverage and production activation remain open.

Upstream authentication's connection reads, identity/projection transaction and
post-commit failure audit also retain the enclosing owner. A scoped caller must
match the request's Environment before its primary reads or writes. The identity
transaction checks commit admission and finishes owned connection cleanup before
creating a browser session. Closure or uncertain cleanup cannot produce a success
cookie; a committed identity remains preserved for a later authorized retry.
Ordinary unscoped authentication keeps its existing behavior. These changes
contribute to ORG-R02/R12/R14/R19/R21, ORG-G02/G04/G08/G10/G11 and
ORG-P02/P07/P09/P12/P13/P14. They do not qualify the enclosing production supplier,
the external identity provider or the full set of primary writers.

OAuth issuance and revocation audit inserts use the same admitted primary adapter
as their Environment lookup. The insert checks the exact scoped Environment and
commit admission, and retains actual connection cleanup after cancellation.
This contributes to ORG-R16/R19/R21, ORG-G09/G10/G11 and ORG-P10/P12/P13/P14;
its successful write alone does not establish complete token publication or
independent-history correspondence.

Upstream refresh resolves its authenticated client only within the actual owner’s
Environment when a scope is present. Outside that scope the existing unique-client
requirement remains. Both account-link query variants check the exact Environment
before SQL and retain their admitted connection through cleanup, including an
empty result and a cancelled response waiter. No refresh credential or linked
identity can be selected from a foreign owner. This implements part of
ORG-R02/R14/R19/R21, ORG-G02/G04/G10/G11 and ORG-P02/P07/P12/P13/P14; enclosing
admission, complete refresh mutations and independent supply remain required.

Refresh rotation and last-use persistence share one owned primary transaction.
It locks current configuration, profile and linked identity before the generation
compare-and-swap, admits commit only while the same Environment owner is open,
and waits for actual cleanup before returning a successful refresh response.
Closure before commit rolls back the replacement; a lost response after commit
preserves the committed generation and never retries it implicitly. This extends
the refresh part of the same R/G/P mapping above; no external issuer or restore
qualification is inferred from it.

### Profile resolution in an owned Environment

ORG-R19/R20/R21, ORG-G10/G11 and ORG-P03/P12/P13/P14 require every
profile lookup made inside an Organizations task to select the Environment
from its live epoch owner. Issuer text is not a substitute for that binding.
Downstream, upstream and default queries, including locked transaction and
observational variants, apply this predicate in SQL; a foreign issuer resolves
no profile. Invalid or missing epoch bindings inside an entered scope refuse
before the query. Ordinary unscoped OAuth callers retain their existing lookup.
The upstream pool entry point must retain the same owner through actual pool
return, and all pool variants check admission again before returning policy.
This caller integration is not supplier qualification or composite discharge.

### Upstream logout incident authority

ORG-R15/R16/R19/R20/R21, ORG-G10/G11/G13 and ORG-P03/P06/P10/P12/P13/P14
require logout recovery state to retain the current Environment owner through
SQL and cleanup. Creation and each lifecycle transition commit their audit in
the same transaction. A callback consumes only a still-pending incident and
checks expiry in that atomic update; concurrent or repeated consumption cannot
return a second successful redirect. A store failure returns unavailable before
redirect or volatile relay publication. A missing ordinary legacy session context
may still omit a persistent incident, but an entered Organizations scope cannot.
Expiry reconciliation updates at most 100 incidents per call with matching audit
rows. Unprocessed pending incidents still impose their recovery policy; batch
limits never allow a connection that was blocked. Foreign scoped queries refuse
or return no incident, and every commit requires open admission. These changes
do not qualify production supplier selection or independent restore history.

## Runtime client reads

Entered runtime projection, client-credentials identity, federation list,
authorization-client and authority-fingerprint reads must resolve the supplied
issuer to the owner's exact Environment in the same transaction. A missing,
foreign or ambiguous issuer refuses before returning client data. Explicit client
Environment arguments must also match. Unscoped startup reads retain their
ordinary behavior; startup itself still needs the qualified production boundary.

Pool-based identity and federation reads retain an admitted connection through
transaction completion and actual pool cleanup, including cancellation. The
existing projection path rechecks admission after cleanup. Caller-supplied
transactions retain their enclosing ownership obligation. These changes address
ORG-R10/R13/R19/R21, ORG-G06/G10/G11 and ORG-P02/P06/P12/P13/P14; they do not
qualify the enclosing supplier or discharge a composite obligation.

## End-user profile reads and mutations

Subject/issuer and object-ID profile reads inside entered Organizations work
must bind the row to that owner's Environment. Locked profile reads and default
profile creation apply the same rule, so a caller cannot update or create a
foreign user's profile by supplying its UUID. Ordinary unscoped management and
startup behavior remains unchanged. Pool-based reads retain admission through
actual cleanup and recheck it before returning a result; caller-owned transactions
retain their separate commit/cleanup obligation.

This closes the shared profile helper boundary for ORG-R01/R10/R19/R21,
ORG-G06/G10/G11 and ORG-P02/P06/P12/P13/P14. It does not qualify an enclosing
management operation, production supplier or cross-store restore.
