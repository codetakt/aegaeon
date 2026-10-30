# Organizations Implementation Status

Last updated: 2026-10-31

Status: active plan

Owner: Engineering

Audience: implementers, reviewers

## Current review candidate

The candidate now includes authenticated configuration and member APIs, original
authorization ceilings, selected-organization Token Exchange, matching JWT and
introspection data, DPoP resource enforcement, invitations, registration/recovery,
delegated management, explicit administrative access, audit delivery and complete
nonsecret snapshots. External identifiers remain exact scoped strings; public
object identifiers are plain UUIDs. Permanent subject ownership uses the merged
foundation, with forward catalog migrations preserving earlier migration bytes.
All feature enablement remains explicit and defaults to disabled.

Source and target import inspection are implemented in the native library and
distribution CLI. They check artifact integrity, row semantics, retained subject
history, exact registration/provider dependencies and native credential format
compatibility through restricted maintenance suppliers. Version-two snapshots
retain absent registrations and historical actors without rebinding identifiers.
Inspection never activates authority or writes application tables. A separate
maintenance command now prepares a complete inactive copy with an atomic receipt,
exact operation replay and guards against ordinary configuration/mutation.
Credential migration/reset, independent nonrollback epoch and single-writer
cutover remain unfinished. See [import preparation](import-preparation.md) and
[the inactive import contract](import-activation.md).

The retained inactive-import source tree
`1a186c8d40ef29a5d5802aaaae112b1a97e2f385` passes database-test compilation,
strict Rust packages, both Clippy inventories, hooks and four native import tests
plus the pre-migration fixture. All 4,544 source entries and 4,156 production
release inputs match their builds. The actual preparation distribution passes
12 transport/custody/recovery conditions, including verified TLS, process kill
during a blocked write, lost commit acknowledgement and same-operation recovery.
Its preceding tree `a4e87ea6934d7f18ec472fb808d842c47448fb2d` passes 835 standard
database/Redis tests plus one pre-migration test; the subsequent production change
corrects the preparation connection's application name and adds concurrency and
invitation-history regressions. Exact inventories and supplier cleanup are retained.
These inventories overlap. The earlier read-only inspector also passes its
14 transport/custody/recovery conditions. None establishes full Organizations
assurance. An actual old admission predicate fails the same inactive-activation
regression. The stopped 49-to-51 migration retains every prior migration byte and
old data column, with no implicit import operation or grant.

The snapshot OpenAPI now agrees with format 2 and its 22 sections, including
absent registrations and provider dependencies. Five interface tests and four
generator tests pass; the new regression fails against the former description.
The generated interface and its SDK assurance hash are updated together.

Negative controls detect missing historical authority validation, omitted owner
or registration dependencies, accepted provider drift, inconsistent snapshots,
revoked export disclosure and stalled HTTP bodies. Failed initial executions
remain retained, including corrections to test setup and cleanup observation.
Arithmetic component proofs do not establish the 15 composite Organizations
obligations: new composite discharge remains zero and product assurance is not
established. Shipment requires the unfinished runtime paths, their composed
formal/security evidence, CI/review and the existing independent release gate.

The independent control-store component now provides serialized transitions,
permanent epoch retirement and durable pending admissions with one executable
owner each. Its operator command exposes status, initialization and fencing;
it cannot activate serving authority. Typed epoch bindings and the owned-work
coordinator cover primary cleanup and scoped Redis drivers. An uncertain reply
never clears pending work. See [runtime epochs](runtime-epochs.md). Runtime
caller coverage, protected-record integration, independent current history,
store-rewind qualification and actual restore/cutover remain incomplete.

The browser/proof worker successor
`f10ad71cd6cfbe88a1d7da1ab61168798afe9196` carries an explicitly entered
admission through 18 additional browser/OIDC, step-up, client-assertion and AS
DPoP workers. Seven build/schema/claim gates, hooks and 2,993 ordinary tests pass
with 898 declared skips. The two actual Redis reply-loss regressions and their
pre-migration fixture pass; reverting the AS worker reproduces premature witness
completion while the browser control still passes. All 4,573 source entries and
4,184 production inputs match, including the schema-guard manifest's server
executable and the witness launcher. These are component results; the complete
enclosing runtime and protected-record/supplier qualification remain open. They
do not close the retained historical full-suite cleanup failure or establish
new composite proof discharge.

The retained component tree `d12b887ad38a30049f238269d1c8980aaad9ff74` passes
four build/lint gates, 2,992 ordinary tests with 886 declared skips, four witness
tests and seven Redis-driver tests. The native groups each include a separate
pre-migration fixture and overlap other inventories. All 4,563 source entries
and 4,174 production release inputs match their builds; the actual operator
distribution passes 24 TLS, role, durability, deadline and recovery conditions.
Three production transition Kani checks pass in partial scope. Actual guard
removal reproduces premature completion after a committed Redis mutation loses
its reply. These component results do not discharge a composite obligation.

The cleanup successor `e7f1a60fd9376f1dc15d0e74e00fe5cbb3e7fbf6` additionally
bounds protocol/pool cleanup to 30 seconds and passes all 13 request-ownership
tests plus pre-migration. Its actual silent-transport regression fails when the
deadline is removed. Closed admission remains mandatory after uncertain cleanup.
Snapshot progress ends at 20 seconds, before the default 30-second database idle
expiry; the earlier equal-deadline failure and its resulting refusals are retained.

The async ownership successor `0e707f3854cbab548f8258fd1ae4f49abed6554c`
passes 2,993 ordinary tests with 890 declared skips and the complete standard
inventory of 845 database/Redis tests plus pre-migration. It also passes all
25 own-resource HTTP cases. Explicit token/code store scopes carry admission
through their blocking workers, and returned code-exchange locks retain it
through synchronous, asynchronous and detached release. Actual guard removals
reproduce premature lock completion and erroneous HTTP 200 after a lost token
read acknowledgement; their positive regressions pass. Earlier replay-worker
and source-scoped standard evidence remain separately retained.

The integrated tree `8323e0b0005e14c39c8e76024e5c084d3b4cb19f` additionally
preserves Unix/TCP proxy support and separate random witness-role credentials.
Seven build/schema/claim gates and hooks pass. All 4,568 source entries and 4,179
release inputs match; the actual witness CLI passes 24 conditions. Focused
TCP witness, returned-lock and token-response-loss groups pass with separate
pre-migration fixtures and complete supplier cleanup. These overlapping results
do not establish full runtime coverage, supplier qualification or shipment.

The resource-worker successor `f9172ce928a972638d0525816763875727f802fa`
covers the full detached own-resource worker and its browser invitation CSRF
store. CSRF generation and one-use consumption now use bounded Redis drivers
and retain the same admission. It passes 2,993 ordinary tests with 892 declared
skips, 847 standard database/Redis tests plus pre-migration, and 27 own-resource
HTTP tests. These inventories overlap. Actual removal of the two CSRF worker
owners makes both lost-reply regressions incorrectly return HTTP 200 on the next
healthy request; the repaired paths remain closed with HTTP 503. The controls
observe committed Redis mutations and complete supplier cleanup. This expands
caller coverage; complete runtime epochs and restore qualification remain open.

The owned-work successor `9ed453fba28de346d3772035b5546b45178a763c`
binds the live epoch before any owned store work and closes local admission on
failed acquisition, abandonment or cancelled completion. Destructors never
release durable slots. Seven build/schema/claim gates and hooks pass, together
with six actual TCP witness tests plus pre-migration. Each of two separate
guard-removal controls produces two expected failures and one passing control;
all suppliers are removed. All 4,570 source entries and 4,181 release inputs match.
This also retains the fatal-response repair: a real PostgreSQL FATAL response
invalidates its connection without retrying or clearing pending work.

The preceding tree `281b334cc7a78232d4ebf6b698d949f2866ad848` passes 2,993
ordinary tests with 896 declared skips. The successor changes test cleanup and
the runtime-link hash manifest; its production server and witness executables
are byte-identical. The broader local regression retains an existing public-JWK
migration fixture failure while waiting five seconds for database backend exit.
Its cause remains under investigation; this is not a passing full regression.
These results do not establish complete runtime coverage, restore qualification
or a new composite proof discharge.

The sections below retain earlier component observations. Their statements about
missing integration apply to the named historical candidate, not this current
implementation summary.

## Native authority foundation

The local implementation contains a Rust authority model and transaction-scoped
PostgreSQL persistence for domains, organizations, roles, memberships, audit,
outbox obligations and idempotency receipts. It includes original authorization
ceilings, scoped access decisions, delegated role assignment checks, monotonic
state transitions, tombstones and serialized last-administrator checks.

Command entrypoints require an already authenticated and authorized caller.
They are not HTTP authentication endpoints. Delegated commands recheck the
actor's active identity and current membership inside the mutation transaction,
including on receipt replay. Both roles added and roles removed must be within
the delegate's assignable set. The transaction owner must roll back on error.
The internal client registration UUID binds grants, audit and receipt namespaces;
the same public client identifier under a new registration cannot reuse them.

Initial authority snapshots support at most 256 organizations and 32 audiences;
each domain has at most 64 role definitions and a selected privilege set has at
most 256 entries. Role/privilege keys contain 1–128 ASCII alphanumeric or
`._:-` characters. Exceeding a bound refuses the snapshot; an integration must
not silently truncate authority or convert a refusal to an unrestricted token.

## Executed validation

The earlier native candidate `535c31a351e8984225542ff822cdc2a1ef5dd31a` was built with the repository's pinned Nix toolchain at
base `4476e94d4058d4de811bc958c0e8c26a90d97732`. Ten model/authorization tests and
seven PostgreSQL tests pass. The database tests exercise actual concurrent
last-admin removal, cross-Environment foreign keys, external ID reuse after
deletion, outbox failure rollback, stale revision/removal, creation receipt
replay/conflict, suspended-actor replay and stronger-role stripping.
The final candidate also passes all 552 selected standard PostgreSQL, Redis,
DCR and mixed-store tests. Those include the seven new PostgreSQL tests above;
the focused and standard counts are not disjoint. The same final binary and
2,254 source files were matched for both executions, and their isolated
containers and volumes were removed successfully.

The supplemental and server inventory Clippy gates pass. Documentation checks,
strict existing proof-reference checks and the existing runtime drift checks
pass; the latter checks do not establish formal verification of this new module.
Earlier local lint/document failures and the initial nine- and fifteen-test
executions are retained separately from the final native candidate.

## External identifier repair

The subsequent ORG-G01 repair maps to ORG-R03/ORG-R08 and the associated
ORG-P01–ORG-P04 work units. Selection validates an opaque external string and
resolves it using the authenticated Environment, domain and registered audience.
The repository holds domain/target/organization locks until the transaction ends.
Lookup alone does not authorize membership or replace caller authentication,
original ceiling, current client policy and root-liveness checks.

Access decisions retain the stored external identifier and require it during
current-state checks. Their authorization-detail output preserves it exactly.
Old internal snapshots missing that identifier are rejected; there is no
prefix-decoding fallback. No persisted user or organization ID is renamed.

The full server test package passes 23 focused Organizations tests: 13 pure
authority tests and 10 actual PostgreSQL tests. These include the earlier 17
and six added regressions, not 23 additional proof obligations. The new cases
exercise ASCII/UTF-8 preservation, UUID-looking external strings, exact case and
Unicode distinctions, same IDs in different domains/environments, wrong target
and scope rejection, membership ceilings, tombstones, target-lock contention,
store failure and recovery. Three new pure regressions fail against the unchanged
predecessor production modules. This negative control is retained separately.

This establishes the local selector/repository/decision behavior on the retained
test artifact, not HTTP or token integration. JWT and introspection correspondence
remain part of ORG-G01's open delivery exit. New formal discharges remain zero.
The selected development lint inventory and formatting checks pass. An additional
strict all-target lint attempt is blocked by two unchanged upstream test warnings
in current main; it is not reported as a passing strict gate.

## Successor configuration implementation

The current private successor composes permanent subject ownership and the
Organizations physical catalog, followed by explicit operator-grant storage.
The stopped 18-to-20 migration preserves existing IDs, subject history,
organization records, audit/outbox/receipts and all 18 preceding revision rows.
It creates no operator grants automatically. The old current-user membership
foreign key negative control still rejects the deletion that the corrected
permanent-owner relation permits.

The operator storage and command candidate passes 50 focused Organizations
checks, including bootstrap serialization, exact capabilities, current identity,
revision/retained-identity bounds, receipt replay and injected outbox failure.
Removing the actual current capability check causes the replay-after-revocation
regression to fail. These counts include earlier tests. Subsequent HTTP and
receipt-capacity extensions are under active validation on separate artifacts.

The successor mounts four explicit management configuration routes using human
sessions, CSRF, admitted connections and current permission checks. Default
domain bootstrap remains disabled. This local route composition does not enable
organization token issuance or claim complete authenticated business operations.
OpenAPI and management JSON use the shared management conventions and plain UUID
object identifiers. The full protocol, invitation, delegation, support and
restore delivery conditions below remain open. New composite proof discharge
remains zero; three accepted arithmetic component checks do not discharge those
composite obligations.

## Current-main composition and bounded configuration reads

The operator configuration successor adds authenticated `GET` pagination with
current `configure` checks, scope-bound cursors, strict queries and no-store
responses. The retained read artifact passes 55 overlapping Organizations
checks, strict package lint, exact OpenAPI generation, two OpenAPI security/schema
checks and 19 SDK source-contract checks. Invalid nonempty read bodies and
prefixed object path identifiers return the declared JSON error envelope.

The first whole mixed-store sweep failed 71 of 121 cases because existing tests
replaced validated configuration or identity services without revalidating the
namespace. The first fixture correction passed 115 and failed six; the remaining
configuration and application-pool fixtures are corrected in the next candidate.
Original failures remain evidence. Production namespace checks were not removed.
Structured test events now distinguish parent results from child-process output.

The new composition starts from actual main `4476e94`, retains its metadata and
CI changes, and includes the prepared registration/currentness/client-snapshot/
DPoP prerequisites, separate Request Object and TLS fixes, and ownership/ID work.
Its initial full migration setup refused the omitted prerequisite revisions.
The three forward catalog replacements documented in the authority integration
record preserve all preceding migration bytes. Actual stopped 22-to-25 upgrade
preserves identity/history and organization/audit/outbox/receipt rows and all
22 preceding revision rows; it creates no operator grant automatically. The old
current-user foreign-key negative control still rejects identity deletion.

The first complete composed sweep executed exactly 691 cases: 679 passed and
12 failed. All 12 failures were fixture integration defects: administrative
corruption attempted through restricted connections, identity service/configuration
replacement after namespace validation, an issuer-move assumption rejected by
permanent ownership, incomplete migration prefixes used for current startup,
and an application-store fault placed before runtime admission. The original
failures remain retained. After those fixture corrections, all 377 PostgreSQL
and 167 mixed-store cases pass, plus the pre-migration case. The earlier Redis
145 and standalone DCR one pass remain scoped to their preceding artifact;
these groups were not rerun after test-only changes. All 4,272 tracked files in
the corrected composition match its build source before one subsequent wording
correction in this authority integration documentation.

## Target configuration successor

Two additional authenticated configuration operations read the current domain
and register an exact audience under its domain ETag. Current configure authority,
immutable Environment/domain assignment, atomic revision/audit/outbox/receipt,
32 retained targets and a 48 KiB serialized-target limit are enforced. Domain
enabling, client authorization and protocol advertisement remain separate work.

The target candidate passes 60 overlapping Organizations checks, including five
new restricted PostgreSQL/HTTP cases for exact Unicode/case and Environment
separation, conflicting target claims, replay after revocation, audit rollback,
revision exhaustion and count/encoded-byte limits. Strict package lint, exact
OpenAPI generation, two OpenAPI contract tests and 19 SDK contract checks pass.
All 4,275 tracked files match that build source before subsequent documentation
updates. The initial hook run rejected relative wording in the integration
record; the corrected documentation hook passes. The actual current-configure
guard-removal mutation produces two intended failures (native revoked-actor
receipt replay and HTTP 200 instead of 403), with 58 other Organizations cases
passing. Its initial recording/setup error is retained and excluded as evidence. These finite observations
do not establish shipment or accepted composite proof discharge, which remains
zero.

## Client configuration successor

Retained client bindings record the immutable registration UUID and exact public
identifier. Configuration creation/update checks the Environment's current
registration and declared targets. Active bindings require a confidential,
authenticated, DPoP-required Token Exchange client. Deletion/re-registration of
the same public ID never reassigns a binding. Dedicated revocation remains
available after client deletion and ordinary receipt exhaustion. Each domain
retains at most 64 bindings; target sets and pagination have separate count and
encoded-byte bounds. Configuration API responses use plain object UUIDs.

The final client candidate passes 65 overlapping Organizations checks, including
five new native/HTTP regressions, and the supporting namespace/history groups.
Strict lint, generated OpenAPI, two schema/security checks and 19 SDK contract
checks pass. All 4,282 tracked files match its build source before this status
update. The initial spelling check detected PostgreSQL's truncated generated
constraint name; an explicit short name and observed successor catalog correct
it. The first OpenAPI test retained the earlier response inventory; its expected
client response schema and count were updated. Both failures remain retained.

Actual stopped 25-to-27 upgrade preserves existing identity/history, organization,
operator, audit, outbox, receipt and preceding revision rows, with no automatic
client bindings. Removing only the actual DPoP minimum check makes the policy
regression fail as expected (64 other Organizations cases pass). The negative
artifact retains the preceding equivalent constraint name; the final positive
artifact uses the explicit name. Both owned suppliers were removed. These are
component/integration results; no new composite proof discharge or shipment.

## Integration dependencies and remaining work

1. Integrate permanent subject ownership and the accepted namespace preflight.
   The native migration adds an Environment/user composite key; the ownership
   foundation's fixed physical catalog must account for that schema change, or
   the final membership reference must use its permanent ownership relation.
   Do not skip namespace preflight or loosen its catalog checks to enable this
   feature. Current main does not yet contain that foundation.
2. Add authenticated operator/delegated HTTP boundaries, scoped configuration,
   client/target authorization, bounded database operations, conditional
   requests and audited activation. Native commands alone do not provide them.
3. Capture ceilings at original authorization and bind them to the actual root,
   client, DPoP key and identity; preserve them across refresh. Integrate selected
   organization issuance, JWT/response consistency, authenticated introspection
   and resource-side checks. Existing unsupported detail types remain rejected.
4. Implement invitation issuance, protected delivery, recipient proof, atomic
   one-use acceptance and inviter-authority rechecks. Implement bounded
   administrative access with original authentication freshness and reason.
5. Integrate user lifecycle/recovery, role-definition changes, export/import,
   migration/rollback and client validation. A global security suspension must
   remain possible even when it removes an organization's effective last admin;
   audited recovery and the resulting organization behavior need end-to-end tests.

SCIM provisioning and AuthZEN adapters remain separate future integrations.
The native model alone enables no HTTP route, OAuth advertisement or organization
token issuance. The successor configuration routes above remain a private
implementation under validation; OAuth advertisement and organization token
issuance are not enabled. Full Organizations delivery, production activation, protocol
conformance and product assurance remain incomplete.

## Original authorization successor

The explicit Organizations grant request is captured before consent and rechecked
at approval. The actual code issuer binds approved internal metadata to the
original refresh root, original authentication time and DPoP key; code redemption
and refresh preserve the private ceiling and public grant detail. JWT parent
tokens carry the same approved public detail. Legacy grants receive no inferred
Organizations authority. See [the detailed contract](original-authorization.md).

The v9 local candidate passes database compilation, strict packages, supplemental
and server inventory Clippy. Seventy-one focused Organizations tests and the
existing namespace/history/restart supporting groups pass. Actual issuer tests
pass 97 cases with one existing ignored case. Removing the issuer approval/root
binding guard from the actual source causes the two required refusal regressions
to fail; the other 95 pass. All 4,293 tracked source files and executable bits
match the pinned positive build before this status-only update. The complete
standard suite passes 705 tests plus one pre-migration test, with exact
inventories and removal of owned PostgreSQL/Redis suppliers. These overlap the
focused tests. Earlier failures are retained.

The browser consent producer exists, but public RAR admission remains disabled
until the selected-token and current-state consumers are complete. This is not
completion of ORG-G05, new composite proof discharge or a shipment claim.

## Explicit introspection recipient successor

Exact targets now carry at most eight explicit RS registrations, each bound to
its immutable registration UUID and exact public client ID. Authenticated
configuration replace/revoke routes require current configure authority, CSRF,
If-Match, reason and idempotency; domain revisions invalidate prior ceilings.
Revocation retains admission and receipt capacity after ordinary exhaustion.
A terminal domain revision also refuses new original authorization.
See [recipient configuration](introspection-recipients.md).

The v5 candidate passes 75 focused Organizations tests and all supporting
namespace/history/restart groups, strict packages, both Clippy gates and hooks.
OpenAPI tests2 pass. The earlier SDK19 success statement was unsupported for
this recipient revision: its retained run failed on Python imports and its
OpenAPI source pin was stale. The selected-token successor corrects that pin
after reviewing the two added recipient routes and passes all19 SDK contract
tests (org-selected-sdk-v2.log). The actual eligibility-guard removal
negative passes74 and fails the one expected refusal test. All4,300 source files
match the positive artifact before this status update. The stopped27-to-29 Atlas
upgrade preserves all27 preceding revision rows/migration bytes and retained
identity/authority data; existing targets receive no recipients.

The broader v4 run passes708 standard tests plus pre-migration1 and fails one
HTTP fixture that attempted to acquire all admission slots before preceding
rollback cleanup. The v5 fixture waits within2seconds for cleanup and passes.
This is not a complete standard run on the v5 artifact. Earlier failures remain
recorded; source/caller/recipient token enforcement and RAR activation are still
separate work. New composite proof discharges remain zero.

## Selected-token currentness successor

The selected Token Exchange path now resolves the exact opaque external ID in
its original Environment/domain, retains the original root, authentication time
and privilege ceiling, requires DPoP, and emits an RS256 JWT lasting at most five
minutes. The atomic token-store commit rejects changed output authority. JWT
claims, response details and private metadata must agree. JSON and signed
introspection require current primary authority and the exact configured RS
registration. Generic resource and offline introspection paths refuse these
credentials. See [token enforcement](token-enforcement.md).

The v17 candidate passes 82 focused Organizations tests, supporting
namespace/history/restart groups and the pre-migration test. Database and strict
builds, both Clippy gates and hooks pass. All 4,316 tracked files match the
artifact before this documentation update. Issuer tests pass98 with one existing
ignored case; form tests pass6. Currentness-guard removal in the actual source
causes the membership-cancellation and recipient/domain-revision cases to return
an incorrect active result, while the sender/store case still passes. These are
overlapping component inventories, not new composite proof discharges. The
complete standard inventory records715 passes and one DB-cleanup deadline
failure, plus pre-migration1. Its cause is unknown; it is not treated as repaired
or discarded. The own-resource successor adds diagnostic state without changing
that cleanup deadline.

The composed tests exposed a real shutdown bug: a cancelled connection-cleanup
owner recursively scheduled itself. Cleanup now has one non-rescheduling owner;
unconfirmed termination closes the affected admission class until process
restart. The PostgreSQL shutdown regression passes; restoring only the old
production cleanup implementation makes that regression abort with stack
overflow. Earlier fixture/build/SDK failures and diagnostic logs are retained.
Test teardown observes actual permit release as well as pool closure.

Public RAR configuration remains disabled. Browser consent integration,
Aegaeon's own resource consumer, invitation/delegation/support access,
export/import/recovery, complete formal obligations and shipment evidence remain
open. Implementation, test success, proof discharge and shipment are separate.

## Own-resource successor

The dedicated GET/HEAD Organizations context route checks resource DPoP,
original-root liveness, the signed/stored selected authority, canonical own
audience, explicit management target and current primary authority, and requires
organization.context.read. It rejects generic route use, foreign targets, missing
metadata, replay, cancelled authority and unavailable primary stores. Request
admission remains held through actual cleanup and caller cancellation.

The final v6 candidate passes86 focused tests, all supporting groups, and the
complete standard720 plus pre-migration1. DB build, strict packages, both Clippy
gates and hooks pass. All4321 tracked files match the tested artifact before
this status update. These inventories overlap and are component evidence.
The selected-stage cleanup failure remains in its original record; passing this
successor does not identify its cause. Public browser RAR activation is still
closed. The subsequent Redis implementation addresses unbounded synchronous
connection setup and proof I/O before activation; this v6 result does not claim
that later repair is complete. New composite proof discharge remains zero.

## Redis operation and proof isolation successor

The token, authorization-code, replay and DPoP nonce stores now use an owned
asynchronous Redis driver behind their synchronous interfaces. A process admits
at most32 driver owners; setup and individual responses have5second deadlines,
and each connection has a30second total lifetime. Capacity remains owned through
actual runtime/transport cleanup, including uncancellable resolver work. No
uncertain update is automatically retried. See [Redis operations](redis-operations.md)
for supplier limits, including the unresolved adversarial peer memory bound.

The final v4 runtime passes87 focused Organizations tests/supporting groups,
6 dedicated Redis tests and the HTTP stalled-peer/cancellation/recovery test.
The complete standard inventory passes722 tests plus pre-migration1. These
inventories overlap. DB/strict/both Clippy gates pass. Hooks pass after correcting
a documentation status and regenerating its index; failed hook runs are retained.
All4327 runtime/source inputs match except those recorded status/documentation
updates. A matched negative replacing the resource's blocking proof worker with
inline verification still passes the6 Redis tests but fails the HTTP test with
actual executor starvation. No new composite proof discharge or public RAR
activation is asserted. Other browser stores and proof consumers remain part of
the next supplier review.
