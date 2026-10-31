# Retained identity creation

Last updated: 2026-10-31

Status: active plan

Owner: Engineering

Audience: implementers, operators and security reviewers

## Scope

This refines [permanent subject history](permanent-history.md) for ORG-R02/R14/R16/R19/R21,
ORG-G02/G04/G09/G10/G11/G13 and ORG-P02/P06/P07/P10/P11/P12/P13/P14/P15.
It defines the next implementation boundary; the creation callers and restoration
acceptance are not yet implemented. Ordinary unscoped behavior remains unchanged.
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

CSV creation reserves its bounded batch before the atomic primary transaction.
All row receipts and users commit together. Independent final recording may be
interrupted, so partial finalization retains the complete operation and pending
work for reconciliation. It never reports a partially accepted batch as success.

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
