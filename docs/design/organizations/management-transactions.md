# Management transaction ownership

Last updated: 2026-11-01

Status: active plan

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
Admission failures use HTTP 503 `temporarily_unavailable`; existing SQL failures
retain the management error envelope.

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
