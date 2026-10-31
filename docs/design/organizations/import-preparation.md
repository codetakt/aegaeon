# Inactive Organizations import preparation

Last updated: 2026-11-01

Status: active plan

Owner: Engineering

Audience: Implementers, operators and security reviewers

## Contract

This refines ORG-R17/R18/R21 and ORG-G10/G11, contributing to ORG-P10/P11/P12/P15.
The input is the complete version-two [snapshot](snapshots.md), retained through
authenticated transfer. Preparation is separate from activation. An integrity
receipt neither establishes the source's authority nor authorizes database writes.
The caller explicitly selects the expected Environment, domain and whole-file
SHA-256 from its retained transfer record. No field within the file selects a
destination, database, executable, credential or path.

## Native input boundary

The native incremental reader consumes one bounded UTF-8 JSON line at a time.
It retains the exact data bytes for hashing and staging, including number lexemes,
whitespace, case and Unicode. It refuses duplicate decoded JSON keys at any depth,
unknown envelope fields, noninteger/out-of-64-bit numbers, NUL, excess depth,
noncanonical UUIDs, unexpected scope/version, reordered or repeated row keys,
missing sections in the manifest, inconsistent counts/digests/length, a missing
terminal manifest, trailing bytes and a whole-file digest mismatch. Empty
sections still have explicit terminal counts and digests.
The JSON integer domain is `i64::MIN` through `u64::MAX`, matching the audit
writer's accepted values. PostgreSQL bigint authority fields retain their own
stricter signed range; a large audit value must not silently narrow an unrelated
revision, timestamp or count field during preparation.

Bounds are 320 KiB per line, 256 KiB per data value, 4 KiB per decoded key,
32 nested JSON containers, one million rows per section and 64 GiB per artifact.
The line bound is enforced before parser allocation. Live callers must also
supply deadlines and exclusively own their stream and output storage. Reading
from a network socket without an external deadline is not a supported caller.

Rows returned before the terminal manifest are **untrusted preparation input**.
They may only enter private temporary staging, never active runtime tables or
external side effects. Every error poisons the reader, including errors after
previous rows were returned. A complete receipt is available only after the
manifest, EOF and explicitly expected whole-file digest all match. Integrity is
distinct from row schema, cross-row/dependency validation and current-history
reconciliation; those checks must follow before a prepared import is accepted.

## Source inspection in PostgreSQL

The source inspector consumes one dedicated connection with finite query, lock,
idle and absolute transaction deadlines. It creates an empty session-local table
before entering a repeatable-read, read-only transaction: PostgreSQL rejects
temporary-table creation inside a read-only transaction. All input insertion is
then restricted to that temporary table. The transaction always rolls back and
the owned connection closes, including after a failed manifest or source check.
This temporary state cannot become an active import or be reused by another job.
Insertion uses parameterized batches of at most ten bounded rows; no input
selects SQL identifiers or syntax.

Version-two inspection checks closed top-level row columns and scalar types,
scope singleton dependencies, canonical row keys, exact external-ID uniqueness,
retained organization/owner/invitation references, current-subject reservations,
accepted-challenge correspondence and client-registration identifiers. It reports
the first rejected contract or dependency, without echoing private input into
ordinary logs. Input and failed inspection artifacts remain with the caller.
Operator idempotency receipts preserve the existing nil-UUID sentinel for an
absent client registration; member receipts require a nonnil registration. This
exception applies only to the stored receipt discriminator, never object identity.
Historical nested authority and target compatibility are additional checks;
passing this source graph inspection is not full semantic adoption.

Source rows additionally reuse the normal object, membership, role, operator,
client-target, delivery-policy, enrollment-policy, support-policy and temporary
administrative-grant validators. These checks reject unknown enum values,
duplicate role/capability lists, illegal key syntax, overlong external IDs,
invalid timestamps and malformed historical delivery bounds. Historical grant
validation checks its captured bindings and original lifetime; it does not require
that the old grant still be live, nor does it revive it. UTF-8 external IDs remain
exact bytes. Nested invitation/root provenance, complete dependency semantics and
inactive target reconciliation remain additional work before import activation.

Inspection requires an explicitly provisioned finite local staging-storage
budget and an outer process deadline for filesystem I/O. The transfer byte bound
does not by itself bound PostgreSQL relation/index/WAL overhead. Deployment
qualification must measure and enforce that storage envelope before exposing a
supported import operation. Source inspection returns target-dependency and
activation flags as false. It performs no writes to application tables.

## Historical row validation

Nested invitation authority is decoded using its producing types. A typed
round trip must preserve its JSON value, so unknown nested fields and duplicate
set entries cannot disappear during decoding. Operator invitations retain a
nonnil Team/operator grant and positive grant revision; delegated invitations
use the existing nil/zero discriminators and retain the original root and selected
membership bindings. Historical validation evaluates captured lifetimes at their
issue times. It does not require current liveness or create a usable credential.
Recipient challenges preserve their scoped identity, authentication time and
recipient expiry. Enrollment history distinguishes registration, recovery,
pending and completed outcomes; unmatched pending recovery requests remain
valid opaque history and do not disclose account existence.

A rejected row reports its one-based physical JSONL record number (including the
header), fixed section name and contract category. It never prints the row key,
subject, recipient or source data. The retained input identifies the exact row
for authorized offline diagnosis. Structural provenance is not proof that a past
caller authenticated; target history reconciliation and artifact-bound caller
proofs remain necessary.

## Local artifact custody

Local inspection retains input in a new directory beneath an existing private
directory owned by the current Unix user. Directory and file modes are exactly
0700 and 0600. Input must be an owned regular file with one link, no final
symlink, and at most the declared transfer size. Nonblocking open prevents a
substituted FIFO from hanging before type validation. JSON never selects paths.
An exclusive nonblocking parent-directory lock admits one inspection at a time;
the parent retains at most 64 entries including failed attempts. Exhaustion
refuses before a new attempt directory is created, with no automatic deletion.

The tool copies into an exclusive partial file, checks the caller's separately
retained whole-file digest, synchronizes both file and directory, then passes
those exact retained bytes to the native inspector. Output uses directory file
descriptors, not subsequent pathname resolution. Before publication it checks
the retained descriptor's identity and bytes again. Source and receipt are
published without replacing existing names and synchronized before success.
Failure leaves existing/partial evidence. A source file without a completed
matching receipt is not a successful inspection. The output directory is
exclusively owned by this operation; same-user mutation is not authorization.

## Inspection command

The distribution includes `aegaeon-organization-import-inspect`. It takes
`--snapshot`, `--expected-sha256`, `--environment-id`, `--domain-id`, a new
`--output-dir`, and `--tool-source-record`. Optional `--target-runtime-role` runs the explicit maintenance target preflight.
The closed source record names the
actual executable SHA-256 and reviewed Git tree/commit; a dirty source additionally
requires `--dirty-input-record` with the exact recorded digest. These labels do
not independently prove that the executable was compiled from that source.
Build provenance and independent review remain required evidence.

`AEGAEON_DATABASE_URL` must name an explicit host, login role and database.
A `host` query parameter is permitted only for a private owned Unix-socket
directory with authority host `localhost`. TCP always requires verified TLS
including the hostname, even when the URL requests weaker TLS. The only other
query parameters are `sslmode`, `sslrootcert`, `sslcert` and `sslkey`, each once.
Ambient `PG*` settings, implicit password files, alternate destination parameters
and SQL startup options are refused. Credentials do not appear in arguments or
error reports. Provision a dedicated staging database/role with CONNECT and TEMP
privileges and no application-table privileges. Query/lock/idle/transaction
budgets are capped at 5 seconds/1 second/30 seconds/1 hour without increasing
stricter existing positive settings; acquisition is capped at 10 seconds.

The distribution launcher applies an independent one-hour process deadline,
TERM followed by KILL after 30 seconds. A direct unwrapped binary requires the
same external deadline, and neither deadline makes uninterruptible kernel I/O
recoverable. The operator must qualify filesystem durability, finite storage
quota and recovery before production use. Successful inspection leaves
`source.jsonl`, `receipt.json` and the exact tool records. Failed or interrupted
attempts retain their partial artifacts. Retry uses a fresh child directory;
there is no automatic deletion, resume, adoption or activation. A completed
receipt remains authoritative for inspection if stdout delivery subsequently
fails; command success is never a prerequisite for retaining its evidence.

## Dependency and activation boundary

The native target preflight uses an explicitly selected maintenance connection
and a fixed, execute-only supplier. No new table privileges are granted to the
maintenance or runtime login. It first validates the complete source, then checks
the target's compiled physical catalog and adopted namespace. All observations
share the same repeatable-read, read-only transaction, which always rolls back.
This is a point-in-time comparison, not a writer fence or activation receipt.

The first target profile requires an absent destination domain and already
reconciled Environment, namespace, permanent owners, complete subject history,
current identities and client registrations. It refuses UUID collisions,
missing or newer ownership history, identity drift and configuration mismatch;
it never creates identities or resolves differences by renaming or merging.
Fixed supplier selectors accept at most ten exact keys per call. Owner history
counts and individual reservation correspondence detect omitted later history
without exposing unrelated owners or permitting input-selected SQL. Primary,
statement, lock, transaction, source size and custody bounds remain mandatory.

Existing active local password credentials are classified without exporting
their verifier. Only the native Argon2id parameter profile is classed as
compatible; missing, ambiguous or unsupported credentials require separately
authorized reset or a separately qualified authentication integration. Inspection
does not claim to have authenticated a password or reset a credential. Target
metadata and credential readiness are separate results. Source integrity and
these point-in-time dependency observations still cannot authorize activation:
live writer fencing, final reconciliation and the independent epoch are required.

An import preserves object UUIDs, exact scoped external identifiers, permanent
owner/subject reservations, tombstones, revisions, receipts and audit history.
It cannot rename conflicting records, overwrite an existing scope, infer absent
history or union source/target privilege sets. Environment, namespace, clients,
configuration and administrator identities are explicit target dependencies.
Their existence alone does not prove semantic compatibility or adoption.

Credential verifier material is not present. Historical invitations, challenges
and grants retain their identifiers and recorded outcomes but cannot regain
authority. Fresh invitation issuance, consent and credential reset require
separate authorized operations. No preparation option bypasses this boundary.

Before activation, a stopped-writer final snapshot must be reconciled with an
independently retained current history and a nonrollback authority epoch. The
target starts inactive. Single-authority cutover, old-root invalidation, bounded
crash reconciliation and shadow comparisons are mandatory. A counter restored
with the application database is insufficient. Until the epoch supplier and its
recovery contract are implemented and validated, no activation command is exposed.

## Verification

Exercise the actual native consumer with native exporter output and an independent
format implementation, including maximum integer and UTF-8 distinctions. Retain
corruption, truncated/trailing, duplicate-key, scope, ordering and bounds tests;
verify errors poison already partially consumed input. Source/artifact binding,
private-file custody, target suppliers, semantic validation and epoch/cutover
proofs are separate obligations. This document does not discharge them.

## Retained identity dependency closure

ORG-R17/R18 and ORG-G10 require permanent owner history for every referenced
end user, even when that user never joined this domain or has since been deleted.
The version-one owner projection includes support-policy entitlements, delegated
invitation actors, member audit/receipt actors, memberships, recipient challenges,
identity requests and administrative grants. The source inspector independently
requires exact equality between that reference set and exported owner rows, with
complete subject reservations. A reference is scoped by Environment and domain;
a UUID alone does not authorize disclosure from another scope.

These are historical dependencies. Export and source inspection do not require a
currently live user or revive that user. Existing byte-exact subject reservations
and the absence of a deleted current identity remain significant at target
preflight. This correction keeps the version-one disclosure shape; it does not
make its remaining client/provider dependency or activation checks complete.

## Version-two registration and provider dependencies

The next complete transfer is version two, with distinct version-two hash-chain
collection labels and 22 mandatory sections. Version-one artifacts remain
retained evidence; they require a fresh export from the source before this
preparation path can accept them. Never relabel or fill missing dependencies in
an old artifact. The independent receiver and native reader reject an unsupported
version before accepting rows.

Client dependencies include registrations referenced by bindings, introspection
recipients, retained invitation actors, recipient challenges, administrative
grants and member audit/receipt actors. `client_dependencies` contains the current
nonsecret registration projection for each referenced UUID still present in the
same Environment. `client_absences` explicitly records each referenced UUID
absent in that Environment. These two sets must be disjoint and exactly cover
the retained references. External identifier reuse under a new UUID is never a
replacement for an absent registration. Target preflight requires those UUIDs to
remain absent globally, or the exact current projection to match; it never
creates a registration or copies its credentials.

`connection_dependencies` covers the providers in the current support policy.
Each row has `id`, `environment_id`, `present` and `configuration`. An absent
provider has `present: false` and null configuration. A present provider includes
only its registration UUID, Environment/configuration version, connection
identifier/type, issuer URL, upstream client ID, authentication method, status
and deletion time. Encrypted client secrets are never selected. Source references
and target projections must match exactly, including absence. Retained inactive
policy references are historical data and grant no access. Fresh support use
still requires current provider configuration, account-link authentication and
explicit authority. Ordinary import never restores account-link credentials.

These additions close the enumerated registration-reference omissions. They do
not authorize activation, restore old roots, replace writer fencing, or establish
whole-product proof discharge. Reconciliation must run again under the eventual
exclusive cutover boundary before activation.

## Timestamp fidelity

Native export fixes UTC and ISO/YMD presentation inside its separately owned
read-only transaction. Paging rejects a changed presentation setting. These
transaction-local settings do not change connection defaults after completion.
The existing version-two format continues to use RFC3339 timestamp strings.

Retained RFC3339 offsets are compared as instants only for explicitly typed,
top-level database timestamp columns (`created_at`, `updated_at`, `recorded_at`)
in their defined collections. Source bytes and digests remain unchanged. Exact
comparison still applies to identifiers, subjects, all other strings, integer
epoch fields and nested audit payloads. A different instant is a real conflict.

Source validation rejects nonzero sub-microsecond precision before preparation;
PostgreSQL timestamp storage cannot preserve those values exactly. Extra trailing
zero fractional digits remain representable. This refines ORG-R17/R18/R19/R21,
ORG-G10/G11 and ORG-P11/P12/P13/P14 without authorizing activation or changing the
separate requirements for current credentials, independent stores and cutover.

The storage precision follows [PostgreSQL 18 date/time types](https://www.postgresql.org/docs/18/datatype-datetime.html).
Offset interpretation follows [RFC 3339 section 4.2](https://www.rfc-editor.org/rfc/rfc3339#section-4.2).
These input/storage restrictions are an Aegaeon snapshot profile, not a claim
that RFC 3339 itself limits fractional timestamps to microseconds.
