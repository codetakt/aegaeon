# Upstream Identity Provisioning Upgrade

Last updated: 2026-10-01

Status: current implementation baseline

Owner: Engineering

Audience: operators, reviewers

## Coordinated deployment

Stop or drain upstream login traffic and all old callback/configuration/management writers before
resuming with the new release. Mixed writers retain the old automatic merging behavior; the schema
default safely labels their new links `legacy_unreviewed` but cannot prevent the old merge itself.
Apply `20261001090000_account_link_provenance.sql` and
`20261001091000_upstream_subject_reservations.sql` with the release migration set and its `atlas.sum`
before starting the new binaries. The account-link provenance migration adds provenance/revision
only; it preserves existing user subjects, link keys, ownership and encrypted refresh-token bytes. The reservation
migration takes a migration-only lock on end-user writes and must execute as one transaction
(Atlas file transaction mode; use `psql -1` for an isolated manual test). No production
migration or account changes follow automatically from installing source code.

Inventory configuration versions, including inactive versions that might later be activated.
Replace enabled `reuse_existing_email` with `reject_existing_email` through the normal reviewed
configuration/activation flow. This policy refuses case-insensitive email matches with non-deleted
local accounts; it does not promise database-wide email uniqueness. Disabled legacy values remain
readable. Restart pending upstream
logins after the coordinated rollout; admitted legacy-policy callbacks on new binaries refuse new
provisioning. Test a fresh identity and a repeat exact-link login in the target environment.

Use `psql "$AEGAEON_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f scripts/operations/upstream_identity_inventory.sql`
with a read-only database role. The script reports aggregate known enabled-legacy policy counts,
noncanonical policy review counts and binding-provenance counts, before or after migration.
Review all noncanonical policy candidates before cutover, including inactive and disabled versions.
These are present values other than the exact strings `reject_existing_email` and
`reuse_existing_email`: whitespace-wrapped values, explicit null and non-string values are included.
A missing value retains the allowed default and is not flagged. The known-legacy diagnostic accepts
ordinary surrounding spaces only; the conservative review counts also catch tabs, newlines and
Unicode whitespace without reproducing the runtime parser's trimming rules. Counts may overlap;
a review candidate does not by itself establish invalidity or account ownership. In particular,
a whitespace-wrapped `reject_existing_email` needs review but is not classified as legacy reuse.
The script does not expose raw subjects, emails,
credentials, environment identifiers or documents. Zero counts do not establish account ownership
or prove absence of cached/in-flight legacy requests; inventory all running writers separately.

## Reserved subject allocations

The exact `upstream:v2:` namespace has a permanent environment-scoped allocation reservation.
An AFTER trigger covers callback, management creation/invitation/import and subject updates,
including old writers. An actual new allocation conflicts even if the earlier row is deleted or
renamed. Unchanged subjects, ordinary profile updates and status changes remain permitted. Moving
away from a reserved subject does not release it; returning to that subject is a new allocation
and is refused even for the former row. Reservations also survive hard deletion of an end-user row.

Migration reserves each distinct existing key in this namespace across all statuses without changing
any existing user or link or choosing an owner for duplicate historical strings. Reservations store
allocation only, with no trust classification. Different environments have separate reservations;
this does not establish non-reassignment across environment or issuer lifecycles. Database
administrators must preserve the constraint and trigger boundary.

## Historical obligations

New JIT users receive opaque `upstream:v2:` subjects and insert-only creation. Email matches refuse
provisioning and never select an existing account. Explicit privileged linking remains available.
Random-subject and concurrent link conflicts require a fresh login and leave no orphan user.

Existing links remain usable under the exact-link path, including `legacy_unreviewed` links.
Historical binding review and enforcement, refresh/callback checks tied to current binding revisions,
and remediation of previously issued sessions/tokens are separate unfinished work. Do not treat
this rollout, administrator provenance, or a successful test as closing those obligations.
No automatic historical re-attestation or invalidation is performed by these migrations.
All-subject non-reassignment, prior rename/deletion history and issuer/environment lifecycle
obligations remain separate; the reservation guard covers only the new namespace.
