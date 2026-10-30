# Organizations HTTP Boundary

Last updated: 2026-10-30

Status: active plan

Owner: Engineering / Verification

Audience: implementers, reviewers, operators

## Scope and delivery dependencies

This implements details of ORG-R01, ORG-R11, ORG-R15, ORG-R20, ORG-R21 and
ORG-R22, addressing ORG-G03, ORG-G11 and ORG-G14 and contributing to ORG-P01,
ORG-P03, ORG-P06, ORG-P12 and ORG-P13. The adopted Organizations contract
remains authoritative. This document does not declare an enabled public API or
discharge a proof obligation.

The current private candidate mounts operator configuration and bounded list
routes with strict input/preconditions, authentication, transaction ownership
and finite admission. Business mutation/read/export routes and their complete
activation conditions remain separate integration work. Operator provisioning and delegated business operations
remain distinct boundaries; an operator session never becomes a business token.

## Identifiers and preconditions

Management paths identify objects by their plain immutable UUIDs, scoped by
Team, Environment and authorization domain. External organization identifiers
appear as exact UTF-8 values in request/response bodies and OAuth details; they
are never parsed as path object UUIDs or normalized. Body input cannot select an
actor, an authenticated binding or an authorization ceiling.

An organization representation has a strong version tag consisting of its
canonical UUID, a dot, and its positive decimal revision, enclosed in quotes.
For example, `"11111111-1111-4111-8111-111111111111.7"`. The revision is never
reused for a changed representation. Every representation field change must
advance it. Tags are validators, not additional object identifiers.

Updates require one exact strong version tag in `If-Match`. This single-version
restriction is an Aegaeon concurrency policy, additional to RFC 9110 strong
comparison semantics. It permits the requested revision to be bound to the
mutation receipt before a retry reads changed state. Wildcards and omitted
preconditions return 428; weak tags never match and return 412; malformed,
multiple or duplicate field values return 400. A well-formed tag naming another
object or a stale revision returns 412, after authorization. Leading zeroes,
uppercase UUID spellings, nil UUIDs, zero and overflowing revisions are not
canonical version tags. No rejection may disclose a resource before authority
has been checked.

Each mutation also requires one `Idempotency-Key`, 1–128 printable ASCII bytes
with no whitespace. The authenticated actor, current internal client
registration (for delegated requests), domain, operation, requested revision,
semantic body and reason determine replay identity. Neither a body-supplied
actor nor the transport request ID supplies authority. A replay rechecks
current authority before consulting its receipt. Equal keys with changed
payloads conflict; response loss does not authorize another effect.

## Finite input profile

The shared boundary constants are: 65,536 JSON body bytes, ten seconds absolute
body-read time, 1,024 bytes per version precondition, 128 bytes per idempotency
key, and at most 100 entries per query page (default 50). These are implementation
limits, not claims of maximum-load performance. Duplicate JSON members, unknown
fields, non-UTF-8 bodies, control characters and over-limit input refuse before
mutation. The HTTP adapter must enforce these limits before allocating its
decoded representation or starting database work.

Admission must precede database-using middleware and body reading. Ownership
must persist through actual worker/connection cleanup, including caller
cancellation. A response deadline does not prove that a database connection has
returned to its pool. The preceding registration-update implementation provides
the tested ownership pattern; its budget does not automatically cover these
new endpoints. Concrete admission, statement, query-response, outbox and
retention budgets must be implemented and tested before route activation.

`organizations::request_work` supplies four nonwaiting process-wide request
leases, independent of caller or Environment identifiers. The adapter must
acquire a lease before reading a body and pass it to every database acquisition.
The pool must have an acquisition timeout of at most 30 seconds. Cancelling a
caller does not cancel an opaque pool acquisition or free its lease while
connection hooks still run. A checked-out connection retains the same lease
until pending SQL, queued rollback, setting restoration and pool-return hooks
finish. Failed cleanup closes the connection instead of reusing it.

Cleanup has one non-rescheduling owner. If runtime shutdown or cancellation
interrupts that owner, or transport closure fails, server termination is not
confirmed: close the affected admission class until process restart. Drop the
remaining transport without reusing the unconfirmed connection. A new runtime in the
same process must not reopen that budget. Cancellation of an unfinished pool
acquisition worker during runtime shutdown also closes the affected admission
class. Normal caller cancellation continues
to retain its lease through completed rollback and pool-return hooks.

PostgreSQL limits are at most five seconds per statement, one second per lock
wait, ten seconds idle in a transaction and twenty seconds per transaction.
Stricter existing settings are preserved; all four original settings are
restored before reuse. These limits require PostgreSQL 18 and apply to SQL work,
not a guarantee of network-outage recovery time. A stalled cleanup retains its
lease and eventually stops further admission; it does not fall back to an
unbounded connection path. The caller still owns commit and authorization.
The private configuration routes mount this primitive with the reserved
revocation slot and response deadline described below. Their configuration
receipt bound does not establish business audit retention or full recovery
qualification.

## Initial management configuration endpoints

Public management JSON follows the existing camelCase field convention: `id`,
`environmentId`, `domainId` and `administratorId` contain plain UUID values.
The native receipt/authorization serialization is a separate internal contract.

All routes are beneath `/api/v1/teams/{team}/environments/{environment}`.
`POST /organization-domains/default` accepts only a reason and initializes the
disabled default domain with the owner's explicit configure grant.
`POST /organization-domains/{domain}/operators` creates an explicit grant;
`PATCH /organization-domains/{domain}/operators/{grant}` updates its active flag
and capabilities with `If-Match`. These requests carry `Idempotency-Key`.
`GET /organization-domains/{domain}/operators` lists operator configuration only,
with current `configure` authority. It requires an interactive session; the
mutation-only CSRF precondition does not apply to this read. `pageSize` defaults
to 50 and must be a canonical integer from 1 through 100. `pageToken` is a
versioned, bounded cursor tied to the Environment and domain; it supplies no
authority. Every page rechecks current permission. UUID keyset pagination gives
current pages, not a frozen multi-page snapshot. Revoked grant identities remain
visible to an authorized configurator. Business members and audit export are
not included. Read bodies must be empty.

A separate `POST .../operators/{grant}/revoke` accepts only a reason and version
and can only deactivate the grant, using one reserved admission slot. Ordinary
configuration uses the four-slot admission pool. The reserved slot does not
promise availability if the database or session store is unavailable.

An interactive management session and the existing Origin/CSRF controls are
mandatory. API keys are refused before database authentication work. Session
lookups retain the request lease through the actual blocking store worker,
including after response cancellation. Session identity and expiry are checked
again before commit; active principal and Team topology remain locked in the
same transaction as the operator grant. A revocation observed before either
session check refuses the request. A session revoked after the last check may
have an already admitted transaction finish; this is not an atomic transaction
across Redis and PostgreSQL.

The outer boundary admits before body reads, enforces the 64 KiB/ten-second
input profile and a 30-second response deadline, and applies no-store to every
response. Database work uses the admitted connection and SQL budgets. Deadline
expiry may occur after commit; the original idempotency key recovers the result
subject to current authorization. Error responses disclose no raw SQL/store
error. Configuration does not itself enable business access or issue tokens.

## Required evidence

Exercise matching and stale versions, another object's validator, weak and
wildcard tags, multiple/duplicate headers, decimal overflow, noncanonical UUIDs,
empty and over-limit keys and JSON bodies, invalid UTF-8 and duplicate members.
Mounted tests must then prove authenticated success, cross-scope refusal,
revalidation before receipt replay, rollback on every error, response-loss
recovery and retention of admission through cancelled storage work. These
separate layers must be connected before any API-complete claim.
