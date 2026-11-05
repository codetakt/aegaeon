# Organizations storage migration

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering / Verification

Audience: operators, implementers and reviewers

## Supported upgrade

The starting database is published main
`46eaed0497fc2005cc10dc483803c108df68865b`, with 24 migrations including attribute
mapping and LTI. The PR adds one migration:
[`20261105000000_organizations.sql`](../../../db/migrations/20261105000000_organizations.sql).
All 24 published SQL files remain byte-identical. The final inventory has 25 rows.
Intermediate development schemas are not supported upgrade targets.

One migration is appropriate because the Organizations schema, durable protocol
state and runtime selection must be deployed together. Each function is installed
with its final definition; intermediate catalog replacements are omitted. Named
components within the file support focused tests and source checking, and cannot
be applied as independent deployment migrations. There is no requirement to keep
an implementation attempt's schema or checksum as an accepted product version.

1. Stop and drain the application writers for the selected database. Keep the
   operational backup and existing migration ledger.
2. Validate the packaged inventory and use the provisioned migration login.
3. Apply the directory using normal linear Atlas migration and the `public`
   revisions schema. No non-linear execution, skipped revision or ledger editing
   is required for this upgrade.
4. Apply the runtime grants and run the final binary's namespace/catalog checks.
5. Complete the selected-state runtime activation and readiness checks before
   exposing traffic. DDL success alone does not complete runtime activation.

Atlas applies the new file transactionally. A failed installation leaves the old
schema, application data and revision inventory intact; after correcting the
external cause, the same source can be applied normally. Runtime credentials
cannot apply the migration. Controlled restore/reset activation follows the
[responsibility rules](recovery-responsibilities.md), rather than replaying later
credentials, ownership or revocations from audit.

## Checks

`organizations-catalog-upgrade` installs the exact published 24-file baseline and
seeds identity/ownership, password credentials, attribute provenance and LTI data.
It verifies a normal upgrade, preservation of existing data and ledger hashes,
fresh-install equivalence, `schema.sql` equivalence, and logical dump/restore
correspondence. Durable runtime tables and lifecycle definitions are compared too.
An injected late DDL failure must roll the entire new migration back, followed by
a successful ordinary retry of the same SQL. The old published checker is a
negative control; the final checker must accept. Corruption cases retain scope,
constraint, index, trigger, role, row-security and revision checks.

The compiled Rust checker independently binds final function bodies, the complete
revision inventory and physical-contract digest. A successful SQL check alone does
not establish runtime correctness, provider qualification or product proof.

The final consolidated upgrade and fault/retry tests pass locally
(`flqcd0xixbn0k9hwwjas4ab630a0q8a8`), including the explicit initial-install
policy. Current runtime and distribution evidence is tracked in
[implementation status](implementation-status.md). No cloud deployment or
publication has been performed.

## PR structure

The local PR history is rebuilt from the published base into two review units:

1. Organizations implementation, its single schema, current runtime/operations,
   affected tests/models and behavioral contracts.
2. Final validation/status and Task 1b/Task 3 assurance handoff.

The first unit is deliberately cohesive: the final SQL inventory, compiled
catalog, store constructors and mandatory runtime depend on each other. Splitting
those into deployment commits would create unsupported intermediate schemas or
nonbuilding states. The second unit records the exact checked implementation
without adding another migration. The 20 predecessor development commits are
preserved privately, not retained as the final PR's fixup history.

Local history preparation does not publish or merge anything. Designated signing,
final-candidate CI/review and Draft restrictions remain; any temporarily unsigned
local commits must be re-signed and their trees checked before publication.
