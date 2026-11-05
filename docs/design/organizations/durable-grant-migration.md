# Atomic authorization and grant migration

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: implementers and reviewers

This is the next coupled part of REC-T05. S02/S04/S06 and S03/S20 already share
one-time publication boundaries in the Redis implementation. Replacing their
facades independently would split those boundaries. The selected PostgreSQL
implementation must preserve them as ordinary domain transactions.

## Required transaction boundaries

| Operation | Rows observed or changed in one transaction |
| --- | --- |
| Issue authorization code | Current PAR reservation and exact admitted request, JAR replay entry, state/nonce observations and the new code |
| Redeem authorization code | Exact code snapshot and expiry, code consumption, access token and bearer metadata, optional refresh family/node and OIDC client/session binding |
| Issue direct grant | Access token and matching bearer metadata, plus any required root/family binding |
| Rotate refresh token | Current family status and deadline, exact active parent, single-use transition, successor and its access token/metadata |
| Detect refresh reuse | Retained consumed-parent identity and current family revocation; later descendants cannot escape the family |
| Exchange token | Current subject/root and target binding, descendant deadline and new descendant publication |
| Revoke | Current ownership/client binding and affected root/family state; no authority inferred from a missing record |
| Complete device authorization | Current approved device grant, single consumption and the same grant-publication boundary |

The retained consumed-refresh node is a protocol replay defense with a bounded
family lifetime. It is not a database restoration history. Authorized PITR
selects the saved domain state; fresh-generation activation excludes credentials
from the previous serving generation without replaying later audit entries.

RP state and nonce values remain reusable. Their existing expiring observations
are diagnostic cardinalities, not AS-wide replay prevention, authorization
authority or a reconstruction history. The SQL implementation must not turn their
uniqueness index into a reason to refuse a distinct valid code.

## Storage and API rules

Use separately indexed current capabilities, grants, refresh nodes, token metadata
and session bindings. Key lookups bind namespace and a framed digest or domain
identifier. Preserve the existing validated payload codecs and compare the exact
admitted snapshot where the current implementation uses conditional publication.
Foreign namespaces, changed snapshots and unrelated parent/client identities
must fail before publication.

The production facades must be asynchronous. SQL work uses the selected shared
database and the caller's owned connection; no synchronous SQL bridge or second
checkout is introduced inside an active transaction. An opaque commit context
must establish that PAR/JAR/code/grant/session participants use the same selected
database and namespace. Backend mismatch refuses the operation.

An SQL uniqueness conflict, failed predicate or rolled-back statement publishes
no partial grant. Ambiguous completion is not automatically retried. Token strings
or response bodies are returned only after confirmed commit. A missing parent or
root rejects use; it cannot be reconstructed from an untrusted cache. Existing
domain idempotency, audit and external-delivery receipts remain distinct from
these protocol states.

Lock current roots/families before dependent rows in a documented order; competing
operations on unrelated grants remain independent. Normal validation uses indexed
reads, without a deployment-wide write lock or whole-store snapshot. Bound expiry
cleanup by batches and time. Do not introduce an unbounded cascade as the normal
cleanup mechanism for a root with many descendants.

## Implementation ToDo

- [ ] Inventory every code/PAR/JAR reservation, grant, refresh, exchange, revocation
  and OIDC publication caller and its existing conditional snapshot.
- [x] Add current-row schema, constraints, expiry/ownership indexes and transaction
  operations with explicit root/child lock order.
- [x] Move code issuance with PAR/JAR consumption together; test competing issue,
  wrong reservations and rollback before wiring production constructors.
- [x] Move code redemption with tokens, refresh roots and OIDC bindings together.
- [x] Move direct grants, rotation/reuse, exchange and revocation; retain exact
  client, subject, sender-binding and descendant-deadline checks.
- [x] Integrate device approval/consumption with the same grant publication.
- [ ] Replace synchronous facade callers, wire startup and bounded cleanup, then
  remove these families from the production Redis inventory.
- [ ] Verify directly affected SQL/HTTP races, failed/cancelled operations, reply
  loss, cross-namespace inputs, malformed snapshots and expiry after lock waits.
- [ ] Record stopped-worker upgrade and the still-required generation activation;
  remove old Redis continuity guards only when all authoritative families move.

Actual defects and these effective-model checks belong to PR #295. Task 1b/3 may
receive strict standards/refinement/composition and qualified provider/load work.
The finite tests cannot establish SQL/Rust refinement or the 10,000 HTTP requests/s
and p99 200 ms target. Existing proof registrations and sealed history remain
unchanged; this plan discharges no product obligation.

## Current adapter increment

The PAR adapter and native asynchronous authorize parsing first passed 22 affected
native checks and seven PostgreSQL/HTTP checks. The latter include competing
reservations/consumption, wrong-client refusal, corrupt bindings, missing storage,
rollback, expiry after a row-lock wait, actual HTTP persistence and retention of
the owned worker slot after its caller is cancelled. An initial new-test field
access compile failure is retained with its correction. The existing Redis PAR
authentication and Organizations PAR/JAR/consent routes also passed in that set.

The subsequent code/JAR adapter passes 55 affected native checks, twelve
PostgreSQL/HTTP checks and ten source guards, with development Clippy passing.
A thirteenth check now confirms direct JAR and pushed PAR code issuance through
the real consent handlers with PostgreSQL stores; rejected namespace admission
preserves the pending consent and successful issuance consumes only its inputs. The adapter adds separate
current code, JAR and diagnostic observation rows, typed backend commit contexts
and the following SQL boundaries:

- Signed PAR publishes its row and JAR replay entry together. A replay, collision
  or failed statement publishes neither partial result.
- Reserving PAR captures a digest of the exact stored payload. Resume and code
  issuance reject a changed payload; code issuance also checks the exact client,
  continuation, namespace and expiry while holding the PAR row lock.
- Code issuance consumes PAR and/or records direct JAR replay in the same SQL
  transaction as code publication and the existing observations. Expected late
  failures roll back the whole function block.
- The lock order is PAR, JAR, code, state observation, nonce observation. Expiry is
  rechecked after possible lock waits. JAR retention is rounded upward and kept
  through the final publication; delayed publication cannot shorten its window.
- Code reads bind the stored bytes, client digest and absolute expiry. A future
  grant commit must compare those exact bytes before consuming the code. The
  standalone consume adapter is not a substitute for that grant transaction.

All PostgreSQL facades reject synchronous access. They use the existing admitted
asynchronous connection owner and bounded SQL deadlines; they introduce no
blocking SQL bridge or automatic retry after ambiguous completion. One cloned
`PostgresGrantDatabase` supplies a process-local compatibility identity to the
participating stores. This identity is not durable recovery authority.

Production still selects Redis for this coupled group. Code redemption plus
access/refresh/OIDC publication, the remaining grant operations, startup and
cleanup wiring are open. Seven production Redis families remain; this adapter
increment does not close REC-T05 or permit removal of legacy continuity guards.
The checked code adapter used the prefix `20261105021000_runtime_security_catalog`.
The subsequent consent fixture uses the source-bound 82-revision prefix
`20261105023000_runtime_security_catalog`; its OIDC DDL is still under separate
implementation and is not covered by those code-publication results.

Observation writes can contend when many issuances reuse a value, and counting
their exact retained cardinality has a storage cost. Their production telemetry
and cleanup budget remain part of REC-T11; neither these functional checks nor
Clippy establishes the requested throughput or latency. SQL/Rust refinement, external-provider durability and whole-protocol composition remain Task 1b/3;
the directly affected concurrency, rollback and HTTP checks remain this PR.

The initial Clippy function-length failure was fixed by removing redundant Redis
string copies. A zero-test filter was rejected as evidence and replaced by the
seven exact state/nonce test names. The original records remain retained. That
code-adapter artifact used 81 Atlas revisions through its catalog;
this is source identity for these fixtures, not new recovery-history authority.

The consent fixture initially attempted to mutate an issuer still held by its
namespace permit. It now releases that test permit, installs the selected stores
and performs the real database-bound namespace validation again. The original
failure and the passing legacy/SQL consent routes are retained. OIDC session and
delivery adapters are being implemented next; atomic token publication remains
open, including exact code bytes, family/root liveness and the prepared OIDC sid.

## OIDC adapter checks

The OIDC adapter passes 25 directly affected native checks and five PostgreSQL
checks at the 82-revision catalog. The SQL checks cover 32 concurrent session
lookups and logout requests, exact prepared SID refusal, transaction rollback,
wrong-subject refusal, current-session replacement after logout, unavailable
storage, competing delivery claims, stale completion, malformed delivery state,
expiry during a real row-lock wait and 8,193-row bounded dependent cleanup with a
locked remainder. Suppliers were stopped. The first module-path compilation and
Clippy inventory failures remain retained with the corrections; a premature test
runner invocation failed before starting suppliers and is not test evidence.

The delivery adapter reuses the existing parent/recipient/owner transition kernel.
It locks the current parent and recipient in PostgreSQL, samples the database
clock after the locks, and validates the monotonic send deadline again after
commit. It preserves domain delivery receipts; no exactly-once network delivery
or provider durability claim follows. Cleanup deletes at most 4,096 selected rows
per statement without an unbounded cascading delete. Active-session lifetime and
bulk logout/client-list resource bounds remain REC-T11.

The next token increment adds current capability, refresh-family and exchange-root
rows with positive parent liveness. A token and its matching metadata occupy one
row. Publication transactions compare exact authorization-code bytes, persist the
initial family/tokens and bind the prepared OIDC SID before committing consumption.
Native SQL facades are being verified; production startup remains on Redis until
rotation, exchange, revocation, device grants and all callers migrate together.
The current uncommitted catalog is `20261105025000_runtime_security_catalog`
(83 revisions). Its existence is not evidence that this token increment passed.

## Current token authority increment

The native SQL token adapter now covers initial publication, exact-code redemption
with OIDC binding, access/refresh validation, refresh rotation and reuse denial,
client/subject revocation, retained-root checks, remint and exchange. Publication
returns credentials only after confirmed commit. Missing subject generations,
families or exchange roots cannot grant authority. A fresh grant cannot resurrect
old records whose current subject generation was lost.

Subject-wide revocation replaces one current generation under its subject lock;
ordinary issuance shares that lock and does not rewrite an existing generation.
This is domain revocation state in the selected database. It is restored by PITR
with the other domain facts; it is neither an independent recovery ledger nor a
claim that post-restore historical credentials remain revoked. Fresh serving
namespaces and lifecycle exclusion remain REC-T06. Subject-generation retention
and the cost of counting affected subject records remain REC-T11.

The adapter passes ten distinct PostgreSQL token checks through native artifact
`ljplps8b2cg0xd4yvq2y2avpdh4vwvfw`, including 32 concurrent code redemptions, a
32-contender refresh race, collision rollback, exact OIDC SID refusal, ownership,
subject-wide revocation, missing authority and one-connection retained-root
checks. Sixty-three affected native checks pass (58 store, three scope-owner,
two OIDC offline-grant checks; the latter overlap the OIDC inventory). Two existing
delegated-invitation HTTP checks also pass. These checks used the source-bound
83-revision schema, except the earlier token v3 artifact, which predates the
subject-generation column and is retained as historical evidence.

The cleanup/counter successor `bf3950kg64vjlgdfa75v072pf4j51jb6` passes three
PostgreSQL checks: 8,193-row bounded cleanup with a locked remainder and live
parents, reusable code observation counts, and code expiry after an observed
OIDC-binding lock wait. Cleanup removes at most 4,096 rows per statement, does
not cascade into live descendants and reports retained backlog. Native Clippy
passes for this source; suppliers were stopped after each run.

Bounded token inventory and direct subject/digest lookup are now being checked.
The new candidate uses the same current uncommitted migration version with an
additional inventory index; artifact source bindings distinguish these trees.
It examines at most 200 indexed candidate rows and returns at most 4 MiB of
serialized rows in a page. Inactive candidates still advance its cursor. A page
may be empty while providing a continuation, and the final continuation may lead
to an empty terminal page. Consumers must follow the returned token to completion.
Grant grouping uses refresh-parent digest then access digest; its cursor records
whether the current group has already been emitted, so groups do not duplicate
across page boundaries. This is a current-state inventory, not a snapshot across
concurrent changes. Legacy Redis compatibility still scans; production selection
must move before the SQL bounds can be claimed for deployed routes.

The first complete consent/code/refresh HTTP test aborted from test-thread stack
overflow. Its failure is retained. The fixture now boxes the endpoint future,
as HTTP framework dispatch does, and separates the redemption future from the
consent fixture. A successful rerun is still required; the failure is not counted
as HTTP acceptance evidence. Initial inventory Clippy warnings were addressed by
removing an unused import and boxing the inventory record variants.

Device-code consumption/publication, JWKS cache authority, production constructors,
lifecycle fencing, managed Redis removal and whole-route qualification remain
open. No 10,000 HTTP/s or p99 claim follows from these functional results.

The final token-v11 artifact `8m6ahkcrzn0dc5v74v2v97lk17d36xfl` passes all thirteen
native-SQL token checks, including the two inventory checks. Its selected filter
also runs one existing protected-header/token-client-assertion HTTP check (14
passed in that invocation; do not count it as a fourteenth token-store check).
The code observation counter check is separate. Clean Clippy is retained for the
boxed inventory candidate. The consent-to-refresh fixture then reached code and
OIDC publication but correctly issued no refresh token because its Environment
OAuth profile had not enabled that grant. The fixture now enables the same
registered grant in that profile; HTTP acceptance remains pending on a new build.

[Device grant migration](durable-device-grants.md) implements the remaining atomic
input-consumption boundary and is under verification. The current development
catalog has advanced to 84 revisions through `20261105027000`; this does not
change the immutable 83-revision token-v11 evidence.

The device-v4 successor passes the complete direct-JAR and pushed-PAR consent,
code redemption, persisted OIDC SID, refresh rotation and reuse-denial HTTP path.
Both unavailable namespace controls leave the inputs usable until an admitted
request commits. The earlier stack and profile-fixture failures remain retained.
The device adapter and its seven HTTP/regression routes also pass, alongside two
shared-cleanup regressions. See the [device evidence inventory](durable-device-grants.md#current-pr-checks).
These results complete the coupled adapters, not production selection, S05 JWKS,
lifecycle activation or REC-T06–12.

## Current coupled startup increment

The local server assembly now creates one `PostgresGrantDatabase` and clones it
into PAR, Request Object replay, authorization-code, token, device and OIDC
session stores. `TokenIssuer::from_postgres_with_ttls` validates the existing
lifetimes and constructs both token stores from that identity. This replaces
production Redis constructors for the coupled group. All ordinary security-store
Redis requirements are removed from the runtime preflight inventory; legacy
explicit constructors remain for existing fixtures. Organizations' old paired
store observation/witness still depends on Redis until REC-T06/T07 replace that
separate lifecycle mechanism. Empty ordinary Redis requirements do not remove
that remaining dependency or establish managed-service compatibility.

Library/binary Clippy passes cleanly in `a87i9m9khvylm7i02fh4pcd162farbla` and ten
production source guards pass. Native startup/config checks and the HTTP
consent-to-refresh flow using the new issuer constructor are pending. Earlier
statements that production still selects Redis describe the recorded adapter
stage; this section is the current selection status. No lifecycle generation,
PITR activation or load guarantee is established by this constructor change.

The coupled-v2 native artifact (`5his945s8h4kl0qkl5nl9g315ydjamp5`) passes the
full SQL consent/code/refresh HTTP fixture with `from_postgres_with_ttls`. Eight
configuration checks and one access-verifier check pass. The environment-inventory
check initially found the legacy witness's token URL read; it remains classified
until that reader is removed, and the corrected inventory passes three checks.
The final production Clippy result is clean. Test suppliers are stopped.
