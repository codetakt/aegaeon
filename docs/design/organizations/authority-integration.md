# Organizations Authority Integration

Last updated: 2026-10-30

Status: active plan

Status note: implementation in progress; delivery verification pending

Owner: Engineering

Audience: implementers, reviewers, operators

## Identity and history

This change implements ORG-R02 / ORG-G02 and contributes to ORG-P02 and
ORG-P13. PRs #167 and #283 describe one permanent subject ownership foundation.
The current-main port of #167 is the integration basis; #283 is not a second
foundation or a requirement to integrate unrelated attribute features.

The [independent permanent history contract](permanent-history.md) specifies
the retained ownership supplier needed before restore and production activation.
It preserves this foundation's identifiers and exact subject semantics.

Membership references `(owner_id, environment_id)` in
`end_user_identity_owners`. A current user may be deleted without destroying
membership history. The permanent owner and subject reservations survive.
Neither a retained membership nor a permanent owner authorizes access: current
active identity, exact subject, client registration, root authorization,
membership incarnation and current policy must still pass at each use.

Object UUIDs remain separate from exact external organization identifiers.
New object IDs use plain UUID representation. Legacy subject values and existing
external IDs are preserved without normalization, renaming or silent migration.

## Physical authority and migration

The native migration follows the ownership migrations. Membership uses a
permanent owner foreign key; it does not add a redundant key to `end_users`.
The eight new relations belong to the protected non-login subject owner.
Runtime grants permit ordinary reads and required inserts and column updates;
they do not permit deleting history, rewriting audit/receipts, replacing an
object's identity, installing triggers or assuming object ownership.

A forward catalog migration extends the observed physical contract, compiled
function correspondence and Atlas revision inventory. Previous ownership
migrations and adoption receipts remain unchanged. Existing deployments stop
and drain runtimes before migration and resume only with the matching server
and checked grants. Adding tables is not permission to trust an old physical
contract or to bypass namespace validation.

The current-main composition also includes the client-secret-slot and client
DPoP-minimum migrations. Earlier unpublished catalog candidates did not list
those prerequisite revisions and correctly refused the composed history.
Forward replacements preserve the preceding migration files and pin the exact
combined history at each separately installable stage:

| Stage | Required final catalog | Revision inventory |
| --- | --- | --- |
| Permanent subject ownership | `20261029052000_subject_prerequisite_catalog.sql` | 19 |
| Native Organizations authority | `20261029071000_organization_prerequisite_catalog.sql` | 22 |
| Explicit operator configuration | `20261030100000_organization_delivery_catalog.sql` | 25 |

Apply the complete selected stage before provisioning its runtime and adopting
history. Intermediate historical catalog definitions are not serving states.
Each replacement retains the same physical/function/privilege checks and adds
exact prerequisite revision identities and digests; unknown, duplicate,
incomplete or modified revisions still refuse. The compiled preflight uses the
matching final definitions for the selected stage. No fallback bypasses the history check.

The expanded physical contract includes organization columns, constraints,
indexes (including the partial single-default-domain index), triggers, relation
ownership and runtime/maintenance privileges. Restricted
runtime credentials are used for normal regressions. Administrative fixture
credentials are reserved for controlled corruption and whole-fixture teardown.

## Required evidence

Run normal creation and delegated mutations with the restricted runtime, then
delete a current identity and confirm retained owner/membership history while
authorization fails. Reject owner reuse in the same or another Environment,
cross-Environment membership references, dangerous table/column grants and
altered physical constraints and indexes. Exercise migration from the exact predecessor
with old migration bytes and adoption receipts retained. A deliberately restored
current-user foreign key must fail the deletion/history regression.

These finite tests do not discharge ORG-P02 or ORG-P13. Authenticated HTTP,
token/root integration, restore epochs and the full delivery proof remain
separate required work.
