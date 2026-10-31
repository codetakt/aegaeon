# Independent permanent subject history

Last updated: 2026-10-31

Status: active plan

Owner: Engineering

Audience: implementers, operators and security reviewers

## Scope and authority

This contract refines the already selected independent PostgreSQL witness for
ORG-R02/R16/R19/R21, ORG-G02/G10/G11/G13 and ORG-P02/P06/P08/P10/P11/P12/P13/P14. It retains the
merged permanent ownership foundation: a globally unique owner UUID belongs to
one Environment forever, and an exact `(Environment, subject)` belongs to one
owner forever. A deleted current identity never frees either reservation.
Subjects retain the existing 1–255 ASCII-byte, non-NUL grammar and byte equality.
Organization external identifiers remain separate arbitrary UTF-8 strings.
Legacy owner UUIDs, including a nil UUID accepted by the existing foundation,
are preserved; this ledger must not rename them or impose a new UUID version.

The ledger resides in the independent control database and outside primary and
token-store restore procedures. It extends the existing protected owner and
separate runtime/maintenance roles. Neither service role receives table access,
arbitrary SQL, deletion, reassignment or forced completion capabilities. This is
an implementation of retained history, not qualification of nonrollback storage.
Production activation still requires authenticated supply, restore exclusion,
complete runtime coverage and detection of unexpected primary/token-store rewind.

## Initial history and retained journal

A namespace is enrolled only under its exact drained fence, operation UUID and
control revision. Enrollment fixes its issuer host, adoption receipt, exact raw
manifest/inventory digests, expected owner/reservation counts and canonical
history digest. The version-one subject-ownership manifest, source custody and
completeness validation remain authoritative; an empty list or a current-primary
query is not independent evidence of complete history. Fresh namespaces require
an explicit fresh-history receipt under the same boundary. Issuer bytes are
preserved, without case conversion or normalization.
The initial supplier accepts issuer hosts up to 1,024 UTF-8 bytes. An oversized
legacy input remains retained and refused, never shortened or renamed.

Enrollment creates an incomplete namespace. The maintenance importer submits
at most 256 canonical entries per call, never more than 1 MiB of encoded input,
under that same fence and operation. Entries first enumerate all owners by UUID
bytes, then reservations by exact subject bytes. Every subject must reference a
previously retained owner in that Environment. The database records immutable
sequence numbers, entries and cumulative digests. A batch commits entirely or
not at all; an exact repeated range may be reconciled from retained entries,
while a changed entry, gap or conflicting predecessor refuses. A lost response
requires inspection of the same namespace and range, never a new enrollment.

The initial counts and digest must match before sealing. Until then, no runtime
history operation can succeed. Incomplete imported reservations remain retained;
there is no discard-and-reassign path. Sealing does not activate an Environment
or certify the external completeness assertion. Its retained manifest identifies
the separately reviewed source and acceptance evidence.

Each entry encodes its kind (one byte: owner 0, reservation 1), owner UUID (16 raw
bytes), then subject length (unsigned 32-bit network order) and exact subject
bytes. An owner entry has length zero. The initial digest is SHA-256 of the UTF-8
bytes `aegaeon-permanent-history-v1` followed by one NUL byte, Environment UUID
bytes, issuer UTF-8 length (unsigned 32-bit network order) and issuer bytes.
Each next digest is SHA-256 of the preceding 32 digest bytes, unsigned 64-bit
network-order sequence number (starting at 1), and the entry encoding. SQL and
Rust must agree with independently calculated fixed vectors. This digest binds
ordered contents; it does not prove authenticity, freshness or completeness.

Each immutable journal entry also retains its authenticated service principal,
operation UUID, recorded time and preceding digest. Runtime additions retain
the exact epoch, work UUID, slot and generation; baseline additions identify
their enrollment operation. Before/after sequence numbers are the entry sequence
minus one and the entry sequence. These fields commit with the reservation and
are returned only through the maintenance inspection boundary. They identify the
actual service operation, not an inferred human actor. Primary identity audit
must retain its separate authorization and user/request context. The canonical
ownership digest excludes these newly recorded operational fields, so it can
still be compared with the independently retained ownership source. It does not
authenticate the provenance fields in isolation.

The first implementation supports at most one million total retained entries per
Environment, including initial and subsequent reservations. The existing 1,024
Environment control-store bound also applies. Capacity never evicts historical
entries or allows reuse. Inputs outside the supported finite limits refuse
before mutation and retain the old state. Large imports proceed in finite
batches with the existing statement, lock, transaction and caller deadlines;
no caller may turn a timeout into a completed import.

## Runtime use and failure ordering

Runtime reads and additions require a sealed namespace and the exact current
durable admission: Environment, deployment, active epoch, slot, generation,
work UUID and authenticated login. The authority row lock serializes these
operations with fencing and admission release. A fabricated, foreign, completed,
reused or retired admission refuses. History data alone never authorizes a user.

Before a primary operation creates or renames an identity, it must append the
owner and requested subject to the independent history. Existing exact mappings
are idempotent; any owner/Environment or subject/owner conflict refuses atomically.
The append has one durable result and advances the journal only for genuinely new
entries. It precedes the primary transaction. A later primary failure preserves
the reservation: availability does not justify returning an identifier to a free
pool. Caller cancellation or uncertain acknowledgement retains the witness
admission until actual work completion is established through the owned boundary.

Before restoring or activating primary data, maintenance compares its complete
permanent owner/reservation set against this current sealed ledger under a drained
fence. It must preserve independently retained entries absent from an old backup;
it cannot union permissions or recreate a deleted current identity. Complete
identity/status, authorization, revocation and credential reconciliation remain
separate acceptance requirements. A matching ownership digest cannot substitute
for those requirements or serve as a general store-rewind detector.

## History through owned runtime work

The live work coordinator and its local owners share one authenticated control
connection and the exact opaque durable admission acquired before store work.
Only that acquisition can construct a history handle; no serialized epoch or
separate local permit can supply it. History checking and reservation accept an
explicit expected Environment and refuse another scope before issuing SQL.
They use the same service principal, work UUID, slot and generation as completion.

Every operation retains its local owner through actual completion, including
when its response waiter is cancelled. The shared connection serializes history
calls and final slot completion. At most four history workers per admission may
be active or queued; capacity is claimed before the subject copy and spawn and
retained through actual completion. Exhaustion refuses without closing otherwise
healthy work. A history call has a ten-second total deadline,
including queueing, with the existing five-second SQL limit inside it. Input
validation precedes spawning or allocation of a subject copy. A confirmed SQL
refusal is a normal failed operation; it does not remove earlier reservations.
Transport loss, malformed acknowledgement, panic or deadline closes local
admission and retains durable pending work. Completion waits for all history
workers as well as primary/token-store owners; dropping a handle never releases
the durable slot. This is ownership propagation, not automatic retry.

The runtime owner offers only exact ownership checks and append-only reservation.
It cannot inspect another operation, enroll or seal history, change ownership,
activate authority or select another connection. Primary identity creation and
rename must still call it at their explicitly specified ordering boundary, and
failed primary writes must preserve a recoverable operation/owner identity.
Adding this handle does not claim that those callers, production activation or
unexpected store-rewind detection are integrated.

## Existing-owner subject changes

A subject change in explicitly admitted Organizations work first validates the
target Environment. A read/lock-only primary transaction authorizes the current
administrator and loads the nondeleted user, then rolls back and releases its
owned connection. This observation does not authorize the later write. The
same live admission checks the exact old subject/owner against independent
history and reserves the requested subject for that existing owner. Reservation
precedes the primary mutation transaction; the preliminary read transaction
does not create, rename or grant anything.

The mutation opens another owned primary transaction, rechecks administrator
authority and current user existence, updates the subject and writes its audit
event, then checks commit admission. A later denial, audit failure or rollback
leaves the reservation intact. Repeating the same owner/subject can recover
without allocating a new identity. A conflicting permanent owner or subject
returns the existing generic ownership conflict; missing history or unavailable
supply refuses without exposing history contents. Email-only updates do not
add reservations, but still retain their scoped connection and commit boundary.

An absent Organizations scope retains ordinary management behavior. An entered
but missing, foreign or closed witness binding never falls back to that path.
Production activation must supply this boundary to every required route; this
caller change does not itself install the production HTTP factory. User creation
has a separate operation/owner recovery problem and cannot infer permission to
recreate an identity merely from a retained subject reservation.

## Required implementation evidence

Exercise actual restricted roles, immutable history, exact case distinctions,
ASCII control bytes, the 255-byte boundary, retained nil legacy owners, identical
subjects in different Environments, owner reuse across Environments, partial
batches, conflicting replay, concurrent insertions, cancellation, response loss,
capacity exhaustion, initial sealing, retired admissions and restored old primary
rows. Preserve failed runs and matched old-code or mutation controls. Check the
compiled physical catalog, Rust call prerequisites, SQL transaction effects,
supplied store configuration and installed distribution. Transition-model proofs
remain separate from supplier and same-system composition. No new composite
proof discharge or shipment status follows from these component checks alone.

The native batch and page adapters call the unconditional production functions
in `crates/pure/src/organization_history.rs`. The registered
`organization-history-bounds` Kani group checks all unsigned 64-bit inputs against
independent 128-bit sum/difference oracles, including zero, exhaustion and
overflow/underflow. It addresses finite input/page arithmetic only. It does not
prove SQL refinement, source authenticity, journal immutability, caller coverage,
recovery or the nonrollback supplier. Actual database boundary and mutation
controls must accompany those scoped proof results.

## Maintenance command and custody

The separate distribution command `aegaeon-organization-history` exposes
`import` and `inspect` against the independent witness. It never activates
authority, changes current primary identities or clears pending work. Both
operations require the exact current drained fence, operation UUID and revision,
an explicit Environment/deployment, verified CA/hostname and maintenance login.
The URL uses `AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL`; ambient PostgreSQL
settings and implicit destinations remain refused. The existing observation and
fencing command keeps its shorter deadline.

Provision `db/organization-witness/schema-v3.sql` after versions one and two,
using the separate provisioning authority while service clients are stopped.
The successor catalog has 223 entries, including the exact column collations,
fixed history functions, constraints, indexes and grants. Both maintenance
commands and runtime clients require this catalog; an older or altered catalog
refuses. The migration does not enroll or seal existing namespaces. Retain their
authority rows, epochs, admissions and transition history before enrollment.

Import requires independently expected raw manifest/inventory hashes and an
explicit local `source-id=path` mapping for every manifest source. References
inside the manifest remain labels and are never opened as paths. Retain and hash
all bytes before opening a control connection, validate the existing manifest /
inventory union, and import canonical batches under the same fence. Source
custody is evidence retention, not automatic approval of its completeness
assertion. A repeated attempt uses a new private output directory and the same
operation/inputs; it reconciles existing entries rather than starting a new
enrollment. Sealing requires exact counts and the complete expected digest.

Use the existing descriptor-relative artifact custody: an owned 0700 output
parent, one exclusive parent lease, fewer than 64 existing parent entries, a new
0700 attempt directory, exclusive 0600 regular files, no symlink/hardlink inputs,
and non-overwriting publication. Manifest and inventory limits are 64 MiB and
256 MiB; at most 256 mapped sources share a 64 GiB total byte bound. Every copy
checks its declared length and hash while reading, including growing inputs.
The source/build record must match the actual executable; retain the exact
reviewed dirty-input record when its labels require one. Source labels remain
separate from proof of their origin and correctness.

Inspection streams at most one million current journal rows in pages of 256
into a private artifact bounded to 2 GiB. An incomplete enrollment is reported
with `sealed: false`; inspection does not finish it. Import first compares the
complete retained prefix with the canonical plan, then resumes at its actual
sequence. This also supports previously committed batches of another size. Check every page's fixed namespace, counts and head,
contiguous sequences, linked entry digests and final digest. Retain original
ownership and operational provenance fields. Only a complete checked artifact
receives a final receipt; interruption leaves the partial files. Standard output
contains bounded status/count/digest metadata and no subjects, credentials or
source paths. Database success with missing output is an uncertain
acknowledgement, so recovery observes the same operation and current history.

The distribution wrapper supplies an independent 3,600-second process deadline
and a 30-second kill grace for blocked filesystem I/O. Individual SQL/connection
budgets remain those of the witness adapter. An in-process timeout alone cannot
bound a blocked filesystem operation. Actual release tests must exercise TLS,
roles, private paths, source mismatch, partial import/replay, altered retained
history, process interruption and lost acknowledgement. This command is a
maintenance history component; complete restore and production activation remain
separate required work.
