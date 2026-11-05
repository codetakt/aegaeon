# Current-state comparison for primary restoration

Last updated: 2026-11-04

Status: historical record

Owner: Engineering

Audience: implementers and recovery operators

## Superseded operational design

This page records predecessor behavior and its source-scoped evidence. Its
control-store, paired-seal, generic history-replay and credential-cutover commands
are not shipped or supported by the current implementation. Use the
[current generation contract](runtime-generation.md) and
[restore runbook](restore-runbook.md). Predecessor code retained under test-only
modules is not a production fallback. Historical test results below do not prove
the replacement implementation.

## Responsibility revision — 2026-11-05

The [adopted recovery rules](recovery-responsibilities.md) are the successor
design. The mechanisms and results below describe the existing implementation
and its historical validation, not a requirement to preserve volatile state or
implement application-level WAL/PITR. The [workplan](recovery-workplan.md) tracks
the replacement; legacy guards are test-only after their consumers migrated.

## Authority and supported operation

This refines ORG-R17/R18/R19/R21, ORG-G10/G11 and
ORG-P08/P11/P12/P13/P14/P15. The independent subject journal preserves permanent
identity, but is not a journal of all membership, consent, configuration or
credential revocations. A fresh authority epoch cannot make an old database
current. A checksum of an old backup is insufficient.

The first restoration comparison requires the actual selected primary to remain
available under its existing incarnation and a drained deployment/child fence.
All runtime and maintenance SQL logins must already be disabled with passwords
removed, their sessions drained and their configured service processes stopped.
The offline control administrator checks the retained parent/child store identity
and WAL floors against the actual source connection. Source replacement, restart,
rewind or an unavailable source refuses this operation. It must not switch to the
restored database as its source of current authority.

The destination is a separate, explicitly selected cluster. It remains offline,
with its old service credentials excluded. A full PostgreSQL backup restored into
that destination can then be compared with the fenced source. Ordinary exported
organization snapshots omit credentials and cannot substitute for this full
primary comparison. Restore tooling must retain backup secrets privately.

A disaster recovery path without this source requires independently current WAL
or equivalent complete authority evidence, including revocations; it remains a
separate implementation obligation. The source observation does not prove that
an administrator never rewrote data. Administrative rewrite exclusion and the
independent control-store custody requirements remain supplier prerequisites.

### Conditions that keep the deployment stopped

The current recovery command cannot establish current authority when its pinned
primary is unavailable, has restarted into another incarnation, or has been
rewound. This includes an ordinary PostgreSQL restart: equal cluster IDs and a
newer WAL position alone are not accepted as continuity evidence. The runtime's
separate [drained store continuity protocol](store-continuity.md) can accept a
restart before a new recovery operation is fenced, using durable post-work seals.
It does not rebind an already fenced recovery source or resolve uncertain work.
Restarting only the Aegaeon process against unchanged stores is also supported.
Do not substitute a backup, update a checkpoint manually, or erase unfinished
owners to make a rejected recovery proceed.

Loss or rollback of the independent control store also prevents reactivation.
So do missing retained operation inputs, unconfirmed exclusion of old writers,
or a destination missing accepted data. Preserve the fenced state and the
rejected operation's evidence. The available-current-source forward recovery
in [serving recovery](serving-recovery.md) handles interrupted cutover; it does
not repair any of these missing authority premises. Supporting primary loss or
restart during uncertain work or a fenced recovery requires a separately
implemented and qualified complete recovery chain,
including independently retained current WAL or equivalent evidence, before
relaxing these refusals. The feature does not promise availability after that
class of store failure.

## Complete content comparison

Compare every ordinary table and partition leaf in the `aegaeon` and `public`
schemas, including Atlas history, identity/password and encrypted credential
records, membership generations, tombstones, consents, configuration, attributes,
LTI histories and operation/audit receipts. Reject other application schemas,
foreign/materialized/unlogged relations and large objects. The offline operator
also refuses logical subscriptions and extensions other than `plpgsql`/`pgcrypto`,
which could introduce background writers outside the service inventory. Partition parents are
not counted twice. Views contain no independently stored rows.

Use two read-only repeatable-read transactions with fixed UTC, ISO/YMD,
PostgreSQL interval, hexadecimal bytea and float presentation. Compare exact
column names/types and per-table length-framed, byte-sorted JSON row digests and
counts. Sorting uses the C collation, preserves duplicate rows, and does not
normalize case or Unicode. Sequence definitions and last-value/is-called states
are compared separately. These are content observations, not a replacement for
the compiled schema/function/role catalog validator.

Bounds are 512 relations, 1,024 columns per table, one million rows per table,
1 MiB per encoded row and 64 GiB across one database observation. SQL statements
have a 60-second deadline, lock acquisition five seconds, temporary sort files
1 GiB and the entire operator ten minutes. Exceeding any bound refuses; no sample
or partial digest is accepted. Receipts contain counts and digests, never row
contents or credentials. Unknown/missing/extra data refuses.

## Operator entry

The recovery package also provides `aegaeon-organization-restore-inspect
--config FILE --output NEW_DIRECTORY`. Configuration version one contains
`operation_id`, `fence` (`deployment_id`, `operation_id`, `revision`,
`state_sha256`), `stores` and `services`. Store order is independent control,
current source, inactive target, with the exact identity, connection and
`old_logins` fields of the recovery operator. The control connection alone may
use the existing local peer profile; source and target require verified TLS.
The service identities may not possess the control administrator's OS identity.

All configuration, CA and credential files and their parents remain under
private root custody. The command reads the current fence state; a supplied
hash does not replace that lookup. Obtain the post-recovery state through the
existing read-only runtime inventory command. An unchanged old recovery input
hash normally describes the previous pending state and must not be reused.
The new private output contains `comparison.json`. It contains no credential
or content row and grants no later write capability.

## Completion and remaining cutover

The operator holds the exact independent fence while comparing, rechecks source
incarnation and WAL floors, actual exclusions and service termination before
reporting success, and closes both database transactions. It retains the control
state digest, exact store identities and content digests in a private new output
directory. A lost response is not activation permission. No pending work is
cleared and no store selection or authority epoch changes.

Successful comparison still requires native catalog/history validation,
credential/key compatibility, fresh runtime credentials, a fresh empty token
store, retired old authority and one selected destination under the independent
CAS protocol. Normal startup must enforce those results. The comparison receipt
has `activationAuthorized: false`; it cannot be replayed as an activation permit.

## Required regression evidence

Use actual PostgreSQL backup and restore. Preserve exact ASCII/UTF-8 identifiers,
case and Unicode distinctions, deleted identities, revoked memberships, audit,
attributes, LTI history and credential rows. A backup taken before a revocation
must fail against the later fenced source; the final backup must pass. Changes,
extra/missing rows, sequence rewinds, unsupported relations, source incarnation
changes, unsafe settings, concurrent workers and exhausted bounds must refuse.
Run the same mismatch assertion with comparison removed as a negative control.
These component tests do not discharge the composite restoration obligations.
The packaged root fixture also stops the actual source, requires inspection to
fail without a comparison receipt or control-state change, then starts it again
and requires the old incarnation to remain rejected.

The forward migration `20261105000000_organizations.sql` preserves
the external identifier's original 1–256 UTF-8 byte and no-control-character
predicate in a flat conjunction. PostgreSQL expands `BETWEEN` into a nested AND
tree, but reparsing a `pg_dump` constraint flattens that tree. The previous strict
catalog therefore rejected an otherwise equivalent restored constraint. The new
migration makes the source and restored physical definitions identical without
normalizing arbitrary SQL or relaxing the catalog comparison. Historical
migrations and identity/data rows remain unchanged. The required upgrade test
performs an actual dump/restore, compares data, immutable migration receipts and
physical catalogs, and checks the same identifier boundary cases.
