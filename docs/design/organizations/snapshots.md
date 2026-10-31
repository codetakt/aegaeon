# Consistent Organizations snapshots

Last updated: 2026-10-31

The management client reference exposes the snapshot as a `ReadableStream`,
without eagerly buffering the transfer as JSON or text. Cancelling that stream
propagates to the HTTP response. The stream is raw transport, not an accepted
snapshot: consumers must enforce the limits, custody and terminal-manifest
verification below. The bounded native receiver remains the supported workflow
for preparing import input. HEAD returns headers without opening a transfer.

Status: active plan

Owner: Engineering

Audience: Implementers, operators and security reviewers

## Contract and scope

This implements ORG-R17 and contributes to ORG-G10, ORG-P10/P11/P12/P13/P14/P15.
A snapshot is a complete, versioned view of one authorized domain at one
PostgreSQL MVCC snapshot. Live audit pagination is not a backup. No page may
silently omit an oversized, unsupported or unparsable retained row.

The transfer includes the domain, registered targets, role definitions, client
bindings, operator grants, organizations and tombstones, memberships including
removed rows and incarnations, invitations and their delivery/status history,
recipient challenges, identity requests and administrative-grant history,
immutable audit, delivery state and command receipts. Identity dependencies
include all retained owners referenced by those records, their permanent subject
reservations, and minimal current identity state. No unrelated domain's rows are
included. The namespace and dependent registration/configuration identities are
explicit dependencies, not newly imported authority.

Permanent owners and subject reservations remain private tables. The restricted
runtime receives explicit EXECUTE on `organization_snapshot_history_v1`, which
selects only owners referenced by the exact Environment/domain and at most ten
rows per call. The supplier has a fixed search path, checked owner and body,
closed collection names and cursor bounds; PUBLIC and maintenance execution are
refused. Its scope parameters are not authentication: the HTTP boundary must
still check current Export authority. Forward migrations retain all prior
migration bytes, existing rows and grants.

Ordinary export is not credential transfer. Password hashes, client secrets,
usable invitation capabilities, invitation/proof verifier hashes, delivery
credentials and OAuth bearer/root credentials are excluded through explicit SQL
projections. A restored invitation or grant never resumes its old authority.
Nonsecret root references and idempotency bindings remain in administrative-grant
history; omitting them would lose the original grant/receipt correspondence.
Current states and identifiers are retained as historical data; fresh consent,
invitation issuance and credential reset are separate authorized operations.

## Version-two transfer

Use UTF-8 JSON Lines: exactly one header, ordered section/row records, and one
terminal manifest. The header identifies version, snapshot UUID, exact scope,
capture time. The namespace is a dedicated section. Each row includes its section and unambiguous
key. Every section, including an empty one, has a count and SHA-256 in the terminal
manifest. Hash exact transferred bytes with explicit lengths and a version/section
prefix; do not normalize strings or reserialize JSON in a verifier.
Version two uses the existing `subject_ownership::history::HashChain` framing
and algorithm with collection name `aegaeon-organizations-snapshot-v2:<section>`.
Its initial domain, per-row index and terminal count are hashed as specified by
that implementation; the section checksum is not SHA-256 of concatenated JSON. A whole-file
SHA-256 binds the locally retained artifact. Checksums detect changes relative to
the retained manifest; transport authentication and explicit import adoption
remain separate requirements.

A transfer without its terminal manifest is incomplete. Recipients retain the
partial artifact and error, and restart a new snapshot. No importer accepts a
prefix, unions different snapshots, guesses absent rows, normalizes identifiers,
or treats a checksum as permission to activate data.

Version two adds explicit absent client registrations and support-provider
connection projections, and expands current client dependencies to every retained
reference. All 22 sections remain mandatory. See the exact reference and absence
contract in [import preparation](import-preparation.md). Version-one bytes remain
retained evidence; this receiver requires re-export before preparation and never
invents missing dependency state.

## Runtime boundary

The mounted export endpoint requires a current human session and the domain's
explicit Export capability. Authentication and authorization occur on the live
primary before any disclosure and at each bounded output page. The data reader
uses a separate owned repeatable-read, read-only transaction. It never evaluates
current authorization against the older data snapshot. Revocation or supplier
failure terminates the transfer without a completion manifest.

The export worker has a separately admitted finite lifetime and connection
budget: the existing 20-second transaction boundary must not be silently raised
for ordinary mutation requests. One export per process, at most two owned SQL
connections, a one-hour absolute lifetime, a 20-second output progress deadline,
5-second individual queries and 1-second lock waits are the initial export
profile. A row is at most 256 KiB, a fetched page at most ten rows, and the whole
transfer at most 64 GiB. A section is limited to one million rows. Limits refuse
the whole snapshot; they do not truncate it. Large historical inventories outside
this profile require a separately supported migration path before activation.
Worker cancellation, pool cleanup, response loss and release of the admission
permit must be tested against actual suppliers.

The output deadline leaves ten seconds before the default 30-second database
idle-in-transaction timeout for rollback and protocol cleanup. Equal deadlines
can let PostgreSQL terminate the connection first, leaving completion unconfirmed
and closing snapshot admission until restart. Stricter database settings remain
in force; they are never raised to preserve export availability. A transport
failure still closes admission when completion cannot be confirmed.

GET `/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/snapshot`
returns `application/x-ndjson`; HEAD checks authorization without starting a
transfer. Both reject query parameters and nonempty bodies. This is an Aegaeon
management transfer protocol; it adds no OAuth/OIDC grant or standards
conformance claim. The worker owns one data connection and borrows at most one
ordinary connection for current authority. A single buffered page applies
backpressure; it reserves output capacity before checking current authority.
Snapshot-specific SQL deadlines never extend ordinary mutation deadlines, and
cleanup retains the admission lease until protocol/pool return completes.

The header and each page are emitted only after the current live authorization
check. The final manifest is emitted only after the reader reaches every section,
verifies counts/budgets and successfully ends its transaction, followed by a final
live authorization check. The local verifier independently checks the native hash-chain framing and
retains the exact bytes, including number lexemes and whitespace. A checksum
result explicitly does not authorize import. The local receiving tool must write a private exclusive
partial file, verifies all counts/hashes, fsyncs it and its directory, and only
then publishes the completed artifact. It never overwrites a prior snapshot.

The standalone Unix receiver is `scripts/organization_snapshot_receive.py`.
Supply `--base` as the exact HTTPS domain management URL above without `/snapshot`,
`--session-file` as the private management session JSON used by the audit consumer,
and `--state` as an existing private directory (0700). It validates TLS, refuses
redirects and retries, enforces a one-hour total and 30-second record-progress
deadline, and writes a new 0600 partial file. It checks the complete format and
requested scope, synchronizes the file, publishes without replacing an existing
snapshot, and synchronizes the directory before reporting `durablyRetained`.
The result includes the whole-file SHA-256 and `importAuthorized: false`.

The directory admits at most 64 entries, including retained partial files.
Failure retains the partial artifact for inspection; starting again creates a
fresh snapshot. A crash during no-overwrite publication may leave two names for
one inode. Strict private-file verification refuses that ambiguous link state;
an operator must reconcile the retained names before acceptance. No retry
overwrites a prior file or automatically removes retained evidence. The verifier
`scripts/organization_snapshot.py` can independently inspect a completed file.

## Import and restore dependency

Import is initially an inactive, exclusive maintenance operation into a compatible
empty scope. It validates the complete artifact and dependency identities,
reports rejected rows, and reconciles permanent owner/subject and external-ID
history against independently retained current history. Same-ID conflicts are
not renamed or overwritten. Existing unrelated scopes and history remain intact.
A protected credential-transfer facility is outside this ordinary format.

Activation and restore require a separate nonrollback authority-epoch mechanism,
old-root invalidation, shadow comparison and a single authority switch. That
mechanism must be specified and implemented before import activation is exposed.
A counter restored in the same database does not satisfy this dependency.

## Evidence required

Bind actual native/HTTP tests to the release artifact. Test concurrent mutations
while reading a fixed snapshot, exact UTF-8/case distinctions, cross-domain
refusal, revocation during transfer, truncated/corrupt/duplicate/mixed artifacts,
maximum rows/bytes, interrupted storage, cleanup and restart. Negative controls
must detect a read-committed mixed snapshot and omitted retained identity history.
This design is not an implementation or proof-completion claim.
