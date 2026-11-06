# Management transaction ownership

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: implementers and security reviewers

Management transactions borrow a connection owned by the enclosing operation.
The shared connection facade validates any explicit Organizations task and keeps
its admission through acquisition, primary observation, SQL protocol cleanup and
pool return. Borrowed SQLx transactions retain their existing rollback-on-drop
semantics; the outer connection owner then drains that rollback before returning
the socket. No unsafe self-reference, detached raw transaction or second local
admission is introduced.

Every shared commit checks current local admission before sending COMMIT. A
commit already admitted before class closure may finish while its owner remains
retained. Closure before admission refuses the commit and leaves SQLx to queue
rollback. The caller passes the completed commit result and its owned connection
to the common finalizer; the finalizer awaits actual connection cleanup and
rechecks the explicit scope before returning. Early returns and cancellation
drop the connection through its existing owned cleanup path. No raw-pool retry
or successful response clears uncertain durable work.

Bootstrap retains its existing READ COMMITTED isolation and common advisory lock.
Ordinary unscoped management and bootstrap still use the same connection facade.
Authentication, transaction authorization, audit writes, SQL ordering, conditional
updates and post-commit runtime synchronization retain their existing contracts.
Admission failures use HTTP 503 `temporarily_unavailable`. Shared SQL error
conversion also uses 503 for connection loss, temporary server unavailability,
pool exhaustion and bounded lock/query timeouts. Other SQL errors remain 500;
existing explicitly handled conflicts and validation errors keep their meanings.
The management error envelope, request ID and no-cache headers are preserved.
The SQL failure response includes `Retry-After: 1` for temporary unavailability.
This is not a statement that a failed write rolled back: uncertain writes are
never replayed by the error converter. Callers must use the operation's existing
idempotency/reconciliation contract when deciding whether to resend a mutation.

Database diagnostics contain the request ID, source file/line, SQLSTATE when
available and temporary/permanent classification. They do not contain SQL text,
parameters, database error detail, credential material or a database URL.

## Transaction start and quiet cleanup

Start transactions through the admitted connection's `begin` method; the owned
publication guard uses its tracked `begin_raw` variant. Do not erase the owner
to `PgConnection` before starting a transaction. The raw accessor is for SQL
execution and operations inside an already tracked transaction.

SQLx 0.8.6 increments its transaction depth only after consuming the BEGIN reply.
The connection therefore records an unresolved BEGIN before polling it and clears
that flag only after success. A cancelled/failed BEGIN prevents new work on that
connection; its cleanup retains admission and sends the defensive ROLLBACK needed
even when the driver's depth is still zero. This is volatile connection ownership,
not a business-state journal or restoration mechanism.

Ordinary autocommit reads do not send ROLLBACK. Cleanup queues any known driver
rollback, drains the protocol, restores session settings and performs its existing
authority check before returning the connection. Only an unresolved BEGIN needs
the extra defensive ROLLBACK. The finite cleanup deadline and fail-closed handling
of uncertainty are unchanged. No SQLx/PostgreSQL warning filter is added; exceptional
lost transaction replies can still produce a notice during defensive cleanup.

This implements transaction caller ownership for ORG-R19/R21, ORG-G10/G11 and
ORG-P08/P11/P12/P13/P14. It is not complete management read/writer coverage, a
multi-Environment authorization design, production supplier qualification or
production mounting. A single Environment owner cannot authorize changes to
other Environments or global administrative authority. Those enclosing scope
requirements remain before activation.

Shared management reads use the same retained connection for acquisition,
observation, query completion and actual pool return. List and optional-row
helpers preserve SQL errors as a separate result so existing validation and
not-found responses retain their meanings; admission or failed cleanup instead
refuses with 503. Typed scalar lookups and the SQLx-returning tenant lookup keep
the same lifetime explicitly. Federation list handlers delegate their unchanged
SQL to this common read boundary. Cancellation cannot finish durable work while
the real return hook is pending, and a lost socket closes its owning class.

These lifetime changes do not grant access: existing team/Environment filters,
session checks and pagination remain required. Global and multi-Environment
scope design, complete entry-point ownership and supplier qualification remain
separate activation prerequisites. Focused read regressions exercise successful
and invalid-input queries, real return cancellation, closure, connection loss,
ordinary unscoped operation and unchanged visibility filters.
