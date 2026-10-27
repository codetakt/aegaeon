# Upstream Identity Provisioning Upgrade

Last updated: 2026-10-13

Status: current implementation baseline

Owner: Engineering

Audience: operators, reviewers

## Coordinated deployment

Stop or drain upstream login traffic and all old callback/configuration/management writers before
resuming with the new release. Mixed writers retain the old automatic merging behavior; the schema
default safely labels their new links `legacy_unreviewed` but cannot prevent the old merge itself.
Apply `20261013090000_account_link_provenance.sql` with the release migration set and its
`atlas.sum` before starting the new binaries. This forward migration adds provenance/revision
only; it preserves existing user subjects, link keys, ownership and encrypted refresh-token bytes.
No production migration or account changes follow automatically from installing source code.

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

## Subject ownership boundary

New JIT users retain the existing opaque `upstream:` plus UUIDv4 subject format and insert-only
creation. This change introduces no subject reservation table or ownership authority. Permanent
issuer-scoped subject ownership, rename/deletion history and namespace lifecycle admission belong
to the shared subject-ownership work; they remain open for this release. Randomness and refusal
of a live-row collision do not establish historical non-reassignment.

## Historical obligations

Email matches refuse
provisioning and never select an existing account. Explicit privileged linking remains available.
Random-subject and concurrent link conflicts require a fresh login and leave no orphan user.

Existing links remain usable under the exact-link path, including `legacy_unreviewed` links.
Historical binding review and enforcement, refresh/callback checks tied to current binding revisions,
and remediation of previously issued sessions/tokens are separate unfinished work. Do not treat
this rollout, administrator provenance, or a successful test as closing those obligations.
No automatic historical re-attestation or invalidation is performed by these migrations.
All-subject non-reassignment, prior rename/deletion history and issuer/environment lifecycle
obligations remain separate.

Earlier unmerged candidates used a dedicated `upstream:v2:` reservation migration. Those files are
not part of this release. Any isolated database built from such a candidate must be retained for
review or rebuilt from the release migration set; do not treat its migration ledger as a released
upgrade path or delete its historical reservations to force migration success.
