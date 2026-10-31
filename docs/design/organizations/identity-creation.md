# Retained identity creation

Last updated: 2026-10-31

Status: active plan

Owner: Engineering

Audience: implementers, operators and security reviewers

## Scope

This refines [permanent subject history](permanent-history.md) for ORG-R02/R14/R16/R19/R21,
ORG-G02/G04/G09/G10/G11/G13 and ORG-P02/P06/P07/P10/P11/P12/P13/P14/P15.
Management create, invitation and CSV connect this boundary to owned primary
transactions. Registration, upstream callers and restoration acceptance
remain incomplete. Ordinary unscoped behavior remains unchanged.
An entered but invalid Organizations scope never selects ordinary behavior.

Reserving a fresh owner before every INSERT is insufficient. A confirmed primary
rollback must permit an authorized retry using the same owner, while a deleted
identity must never be recreated from a permanent subject reservation. Creation
therefore has its own retained operation, separate from the current user row and
from the immutable owner/subject history.

## Operation identity and payload

An operation binds its exact Environment, creation kind, operation UUID,
authenticated actor binding and digest of its normalized nonsecret payload.
The independent witness allocates one random owner UUID once. Management callers
retain their explicitly supplied, validated subject. Registration and upstream
JIT receive one generated plain UUID subject from this retained allocation.
Existing identities and imported subjects are never renamed by this mechanism.

Management create, invite and CSV import require one canonical UUID in the
`Idempotency-Key` header when Organizations work is selected. Reject missing,
duplicate, nil or malformed values before reservation. This is an Aegaeon
management profile, not an OAuth/OIDC field or a claim of an IETF extension.
Creation kind separates otherwise equal keys; a CSV operation additionally binds
the complete normalized batch and stable row positions. An operation cannot be
rebound to another actor or payload. Current lifecycle permission is required
on every attempt and in the primary mutation transaction.

Invitation registration uses the already authenticated identity-request UUID and
its invitation/delivery/policy bindings. Upstream creation uses the exact current
Environment, connection/registration generation, issuer and upstream subject
binding. A new browser authentication request must resolve that same retained
creation operation; it must not allocate another owner just because its request
UUID changed. Email never supplies either identity or operation equality.

The canonical payload format is versioned and length-delimited, and includes all
nonsecret fields that affect creation. It excludes passwords, proof secrets,
tokens and private keys; no fast password digest is retained. A password may be
chosen again after a confirmed rollback before credential creation. After commit,
registration replay still verifies the exact current credential and identity
revision using the existing bounded password verifier.

## Attempt states and primary receipt

The independent record is permanently one of `reserved`, `retryable` or
`committed`, and retains the original owner, subject and payload binding. Each
attempt binds the exact durable work UUID, epoch, slot, generation and service
principal. A different work cannot take over a reserved attempt while its owner
is pending. Returning an HTTP error, reaching a deadline or closing a socket
does not release that attempt.

Reserve owner/subject and the creation record atomically before the primary
mutation transaction. Then reauthorize, reload current policy and insert the
identity plus an immutable operation receipt in one owned primary transaction.
The receipt binds the same operation, actor, payload, owner and subject. Duplicate
or conflicting receipts cannot silently overwrite either identity or payload.
Audit and any credential/invitation changes commit with that receipt.

Only confirmed absence of a started primary write, or completed primary rollback
and connection cleanup, can mark the attempt `retryable`. Retry keeps the same
owner and subject. It cannot use an old error response as evidence of rollback.
A successful primary commit is followed by independent `committed` recording
under the same owner, before a successful result is exposed. Durable work
completion refuses any still-reserved creation attempt. Cancellation, process
loss, transport uncertainty or failed final recording leaves pending work.

A committed operation never becomes retryable. A replay checks its exact primary
receipt and current identity under current authorization. Missing, deleted or
inconsistent current data refuses without recreating the identity. A different
actor or payload receives a generic conflict, without the retained identity or
history contents. A successful replay does not mint another activation secret.
An already consumed one-time result uses the existing explicit credential
issuance/recovery operation; it is not recovered from a hash or silently reissued.

CSV creation reserves its bounded batch in one independent SQL statement before
the atomic primary transaction. All row receipts and users commit together.
Independent final recording also uses one SQL statement for all rows. An error
rolls back the complete statement; an uncertain reply still retains pending work
for reconciliation. No partially accepted batch is reported as success.

## Recovery, capacity and trust boundary

Primary commit with an uncertain acknowledgement is reconciled against the
immutable primary receipt and current independent intent while the affected
authority is fenced. Clearing a pending slot is not recovery. The actual old
work must be confirmed ended and the selected primary state must be qualified
as current before recording committed or retryable disposition. A restored old
primary copy lacking a receipt cannot establish that creation never committed.
Retired-epoch attempts require this explicit maintenance reconciliation and
cannot resume through an ordinary runtime call.

Independent owner, subject, operation and attempt history survive every supported
primary/token-store restore. Neither service role may delete or reassign them.
Provisioning and maintenance use distinct fixed functions and the existing exact
catalog, authenticated connection and drained-fence checks. The initial limits
are 500,000 retained creation operations per Environment, at most 32 attempts per
operation, and one million retained creation transition records per Environment.
These are additional upper bounds; the existing million-entry permanent-history
limit can refuse earlier. Exhaustion refuses without truncation or eviction.
Existing per-work concurrency, statement and total deadlines also apply.

The independent adapter uses a kind (`management_create`, `management_invite`,
`management_csv`, `registration` or `upstream`), a 32-byte selector digest, a
32-byte actor-binding digest and a 32-byte payload digest. All three digests use
lowercase 64-character hexadecimal transport. Their canonical input encodings
must be fixed by the respective caller before integration. The selector does
not become a public object identifier. The witness assigns a separate random
operation UUID and stores an optional requested subject; `NULL` requests one
generated UUID subject. Replay compares the requested mode and bytes too.

Every reservation consumes one event and reserves capacity for its eventual
retryable/committed event. New reservations require
`events + reserved_attempts + 2 <= 1,000,000`; finishing consumes the retained
credit. Thus exhaustion cannot prevent an already reserved attempt from recording
its terminal disposition. Exact replay consumes no event or attempt. A fence
stops new reservations, but the exact pending owner may still record its existing
attempt's outcome before durable completion; otherwise fencing could never drain.

The version-four physical catalog allows at most 512 entries and reads a 513th
sentinel to reject excess. Its reserved-work index bounds the completion lookup
to the exact Environment/epoch/slot/generation/work identity; completed history
does not require a full scan on every release. A version-three client is not
qualified for the extended catalog. Provisioning must preserve all earlier
authority, pending-work and permanent-history rows before switching clients.

A witness receipt is not management authority, upstream identity proof, complete
restore acceptance or supplier qualification. Real caller refinement must show
that rollback/finalize functions are reachable only after their stated primary
outcomes. The production factory must cover every creation path and require the
same qualified primary/control supply before this feature can ship.

## Required evidence

### Management create binding

For the selected Organizations profile, require exactly one `Idempotency-Key`
containing a nonnil lowercase hyphenated UUID, without whitespace normalization.
The ordinary unscoped API keeps its existing behavior. Authenticate the human
management session and current lifecycle permission before any reservation;
service API keys do not gain lifecycle authority through this mechanism.

Each SHA-256 input starts with the exact ASCII domain below followed by one NUL
byte. UUIDs use their 16 network-order bytes, integers use unsigned big-endian
encoding, and strings use a four-byte byte length followed by exact UTF-8 bytes.
Optional strings use byte zero for absent, or byte one followed by that string.
All normalization and existing size validation precede encoding.

| Digest | Domain | Ordered fields |
| --- | --- | --- |
| Selector | `aegaeon-creation-management-selector-v1` | Environment UUID, kind byte `1`, idempotency UUID |
| Actor | `aegaeon-creation-management-actor-v1` | team UUID, tenant UUID, Environment UUID, human administrator UUID |
| Payload | `aegaeon-creation-management-create-v1` | required subject, optional email |

Session secrets and timestamps are excluded so that the same human can retry
after a fresh login, subject to current authorization. This encoding applies to
management create only; invite, CSV, registration and upstream callers require
their own complete canonical contracts before integration.

### Management invitation binding

Invitation uses the same management key and actor encoding, with selector kind
byte `2`. Its payload domain is `aegaeon-creation-management-invite-v1`, followed
by normalized required subject, optional email and optional requested TTL.
The TTL uses byte zero for absent, or byte one followed by a positive eight-byte
unsigned big-endian number of seconds. Reject requested TTLs outside the existing
300–604,800 second credential bounds before reservation. Otherwise an impossible
payload could permanently reserve an unusable subject.
The current TTL policy is reloaded inside the primary transaction; effective
policy values are preconditions, not a replacement for the client's original
payload binding. A policy change cannot silently rebind the requested operation.

The owned transaction holds current human authority, Environment/tenant/issuer
and `environment_policies` row locks through commit, then rechecks TTL policy,
then creates the retained owner, profile, activation token, audit and primary
receipt together. Construct the response from the exact new token row inside
that transaction, without loading unbounded credential history or querying after
commit. Expose the initial `200` result only after independent committed recording.
Do not retain the activation secret in the operation, receipt or audit.

A committed replay rechecks current authority and the current nondeleted user,
then returns `409 one_time_result_unavailable`. It never mints or reconstructs an
activation secret. The administrator can use the explicit activation issuance
operation after reading the current user. A deleted user returns `404`; missing
or altered primary receipt evidence refuses and leaves work pending. A confirmed
rollback permits an exact retry with the retained owner. Unscoped invitation
behavior remains unchanged. This is an Aegaeon management profile.

### Management CSV binding

The selected profile admits 1–100 normalized rows under the existing 2 MiB HTTP
body bound, five-second independent statement limit and thirty-second owned work
limit. Stop parsing before adding a 101st row. Invalid keys, subjects, email sizes
and requested TTLs outside 300–604,800 seconds refuse before retaining any owner.
The ordinary unscoped API retains its existing behavior.

Use the management selector domain and actor digest above. Selector fields are
Environment UUID, kind byte `3`, idempotency UUID and zero-based row index as
u32 big-endian. Do not include the batch digest in the selector: changing any
batch field under the same key must conflict with its retained first row.

The batch digest domain is `aegaeon-creation-management-csv-v1` plus NUL, followed
by activation-enabled byte 0/1, optional requested TTL (0 or 1+u64 big-endian),
row count u32 big-endian, then each original CSV record number u64 big-endian,
normalized subject string and optional normalized email. String encodings match
management create. Each row payload hashes `aegaeon-creation-management-csv-row-v1`
plus NUL, the raw 32-byte batch digest and its zero-based row index u32 big-endian.
Row order, blank-record positions, activation choice and requested TTL are bound.

One immediate primary permit spans atomic batch reservation, primary mutation,
cleanup and atomic independent final recording. The independent adapter invokes
existing fixed functions within a single parameterized SQL statement, bounded
by 100 inputs; it does not broaden database privileges or change catalog shape.
All returned operations must be distinct and uniformly reserved or committed.
A malformed, mixed or inconsistent result requires reconciliation.

The primary transaction rechecks current human authority, locks the current
Environment/tenant/issuer and any required activation policy, and creates every
user, profile, activation token, audit and primary receipt together. A failure
on any row rolls back them all before recording retryability for the complete
batch. A token-free committed replay returns the current users with `200`; a
batch that originally issued activation tokens returns `409
one_time_result_unavailable` after current authorization and user checks. No
secret is recovered or reissued. A deleted row returns `404` for the whole
batch. Uncertain primary/final acknowledgement leaves all work pending.

### Primary receipt and outcome producer

The protected primary receipt is immutable and unique both by
Environment/operation and by owner UUID. It binds the exact kind, selector,
actor, payload, original subject, owner, attempt, epoch and identity revision at
creation. Its foreign key targets permanent owner history, so user deletion
cannot erase the receipt. Runtime access is read plus a fixed append function;
direct insert, update, delete, truncate, ownership and trigger bypass refuse.
Physical catalog, maintenance inventory, migrations, schema snapshot and
provisioning checks must include this table and function together.

Only the implementation that owns the primary transaction may construct a
primary outcome. It reauthorizes, creates the identity/profile/audit, appends
the receipt, admits commit and confirms commit and connection cleanup before
returning committed evidence. Only an explicitly confirmed rollback followed by
confirmed cleanup permits retryable evidence. An error from commit never implies
rollback. Cancellation anywhere leaves the independent reservation pending.

All clones of one durable work share one immediate, nonqueued primary-creation
permit. It spans current independent-state refresh, primary transaction, cleanup
and independent final recording. Otherwise two same-work callers could report
one rollback after the other had committed. A canceled or uncertain permit owner
closes local admission before releasing the permit. Refresh checks operation and
attempt against the retained receipt before any mutation; an already committed
operation takes the verified replay path. An unexpected primary receipt under a
still-reserved independent attempt requires fenced reconciliation, never a
retryable disposition. CSV uses one permit for the complete batch.

Committed replay checks the exact retained primary receipt and current user,
under current authorization, without inserting either. A subsequently renamed
user returns its current representation; the original receipt remains unchanged.
Missing/deleted users or missing/mismatched receipts refuse. The primary receipt
contains no password, one-time activation secret or retained response credential.

Management create returns `201 Created` for a newly committed identity and
`200 OK` for an authorized committed replay of the current representation.
This profile choice distinguishes creation from the result of a later POST,
consistent with [RFC 9110 sections 15.3.1–15.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.1).
It does not define a standard Idempotency-Key extension. A replay whose user is
deleted or absent returns 404; missing or inconsistent receipt evidence returns
503 and requires reconciliation. Normalized email is limited to 1 MiB before
canonical encoding, in addition to the existing HTTP body limit.

The primary receipt digest uses domain `aegaeon-creation-primary-v1` plus NUL,
Environment UUID, operation UUID, a length-prefixed kind string, selector/actor/
payload digests as 32 raw bytes each, owner UUID, length-prefixed original
subject, attempt as four bytes, epoch UUID and identity revision as eight bytes.
All numbers are positive and within the stored signed SQL ranges. The fixed
append function recomputes this digest and verifies the current user's exact
Environment, owner, subject and identity revision before insertion. A repeated
append must match every immutable field. Read-only replay validates the same
digest without requiring the current subject to equal its historical value.

### Acceptance

Exercise normal creation and exact replay, concurrent same-operation requests,
actor/payload/Environment confusion, permanent collisions, confirmed rollback,
commit acknowledgement loss, cancellation and process loss at every cross-store
boundary, primary and independent-store failures, partial CSV finalization,
deletion followed by replay, restored old primary data, retired epochs and all
finite bounds. Retain negative controls removing owner reuse, attempt ownership,
receipt matching, current authorization and committed-state protections. Bind
transition/refinement proofs, actual restricted-role SQL and HTTP callers,
supplier assumptions and installed artifacts. Component success alone discharges
none of the 15 composite Organizations obligations.
