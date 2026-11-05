# Organizations recovery design acceptance and review

Last updated: 2026-11-04

Status: future plan

Owner: Engineering / Verification

Audience: implementers and independent reviewers

This document reviews [the proposal](recovery-redesign.md) and assigns its future
implementation acceptance. Design review completion does not qualify code,
deployment suppliers or any of the fifteen composite proof families.

The user-selected 10,000 HTTP/s / normal-API p99 <= 200 ms target adds the
[performance design](recovery-performance.md) and
[numerical qualification gates](recovery-performance-qualification.md).
These are design requirements with unexecuted acceptance, not performance evidence.

## Superseded recovery proposal

The 2026-11-05 [adopted responsibility rules](recovery-responsibilities.md)
supersede this proposal. Per-operation independent journals, three-phase
confirmation, complete application redo and reproduction of volatile state are
not implementation requirements. Source inventories remain useful references;
the numerical budgets tied to that architecture are withdrawn. See the
[current workplan](recovery-workplan.md) for implementation status.

## Review corrections

| Finding | Rejected design shortcut | Required correction |
| --- | --- | --- |
| D01 | A primary transaction plus an asynchronous outbox establishes antirollback | Retain independent current acceptance records, gate unconfirmed primary state, and confirm before external publication |
| D02 | No receipt means no mutation occurred | Fence/resolve the original primary transaction before terminal abort; old workers cannot commit afterward |
| D03 | A single control read followed by a primary read proves currentness | Compare exact heads and monotonic reservation/fence revisions again after the consistent primary snapshot |
| D04 | Checking an epoch before writing excludes a concurrent old writer | Hold the primary epoch/attempt fence through commit; use an ordered quiesce/install/activate protocol |
| D05 | Every Redis entry is disposable after membership moves to SQL | Migrate all twenty surfaces, including session, one-use/replay, JWKS fingerprint and security rate-limit history |
| D06 | An organization ID completely defines an operation's conflict scope | Include shared subject/client/root, Team/Environment topology, predicate and cross-Environment dependencies |
| D07 | A journal digest and PITR backup recover every acknowledged operation | Retain complete protected recovery payload before confirmation; qualify baseline plus gap-free deterministic reconstruction |
| D08 | A recovered operation result may always be replayed to a client | Reauthorize receipt disclosure; preserve OAuth code/refresh/DPoP one-use and expiry contracts |
| D09 | External effects become exactly once with an outbox | Stable delivery IDs and receiver deduplication; preserve ambiguous outcomes; a lost upstream code exchange can require a new login |
| D10 | TTL/lease expiry frees pending work | Deadlines bound attempts only; Confirmed/Aborted require durable evidence and fences |
| D11 | Independent DB names or IAM token expiry provide writer exclusion | Separate restore custody; provider/resource binding; actual existing-session termination and reconnect refusal where required |
| D12 | All tests may use the historical activation fixture after schema v16 | Explicitly prepare the required seal; preserve absent-seal refusal and distinguish fixture setup from supplier qualification |
| D13 | Removing all STRLEN permission still isolates code-store behavior | Continuity also uses STRLEN; the code negative fixture permits only the exact continuity key while denying code keys |
| D14 | A metadata cache can replace all repeated catalog checks immediately | Establish DDL exclusion and schema/connection generation invalidation before reusing validation |
| D15 | Recovery preserves pre-restore token validity | Ordinary qualified failover can retain epoch; restore enters a fresh epoch and invalidates pre-restore credentials |
| D16 | An intent digest is sufficient to execute after coordinator loss | Retain complete encrypted intent before execution, or limit recovery to receipt reconciliation/safe abort |
| D17 | A runtime-supplied operation UUID or fresh epoch authorizes writes | A distinct coordinator installs exact primary attempt grants; protected functions, row locks and role permissions enforce them |
| D18 | Replaying SQL or expiring an Applied request safely restores state | Apply versioned complete change batches without new trigger/external effects; confirm existing receipts and use separate authorized compensation |
| D19 | Separate primary attempt installation is necessary on every normal mutation | Combine installation and effects under a restricted coordinator transaction; an absent attempt can still be terminally fenced by a tombstone |
| D20 | Environment-wide reservations can be optimized after delivery | Exact authority/operational dependency domains, compatible read handling and same-Environment load are initial acceptance requirements |
| D21 | Partitioning a lock removes all shared-state contention | Separate per-object anchors, collection versions, journal heads and lifecycle lock shards; qualify their actual contention and fence coverage |
| D22 | A scenario/smoke throughput report proves 10,000 HTTP/s | Preserve scheduled arrivals, endpoint/HTTP/protocol-operation units, prerequisite traffic, failures and generator saturation |
| D23 | Twenty configured URLs enumerate all authority namespaces | Include S12 authorization-source limiting, P13 continuation/budget SQL and B09 browser ownership; retain the twenty-setting count only as a declaration count |
| D24 | Connection/retention defaults are capacity evidence | Use explicit connection-time and payload-rate sensitivity, GC frontier and recovery envelope; validate on a bound environment before making claims |

These corrections are requirements of the final proposal. D01–D11/D14–D24 are
design interleaving/threat reviews, not executed production proofs. D12/D13 have
separate local fixture regressions; their success does not implement the proposal.

## Safety acceptance

| ID | Invariant and falsifying case | Inventory |
| --- | --- | --- |
| A01 | Same logical operation cannot apply its effects twice; concurrent/replayed attempts, lost primary and control replies | S01–S20, P01–P13 |
| A02 | No positive authorization or notification from Applied-but-unconfirmed state; pause between every commit/publication edge | P01–P10, B05/B06 |
| A03 | No old writer commits after its terminal fence, including a paused process resuming with an existing connection | P12, B07, every operational entry |
| A04 | A check started after successful revocation rejects old authority; race mint, refresh, introspection, own-resource access and membership changes | S02/S03/S07/S13/S14/S20, P01–P04/P07–P10 |
| A05 | Restoring an older complete store with extra unrelated WAL cannot restore accepted authority or erase one-use consumption | All authoritative surfaces and P11/P12 |
| A06 | No pending deletion from timeout, missing process, expired lease or missing receipt alone | P05/P12, B07/B08 |
| A07 | Two concurrent last-admin removals, invitation acceptances, refresh rotations and replay claims preserve aggregate constraints | S02–S04/S08/S19, P01/P02 |
| A08 | Scope isolation covers shared dependencies and denies cross-principal input/receipt reuse | All S/P entries |
| A09 | Expiry/GC cannot erase live replay, roots, permanent ownership or needed recovery records | B01, S01–S20, P03/P06/P11 |
| A10 | Cache loss/repopulation, missing JWKS history or reset rate limits cannot increase authorization | S05/S10/S12/S15 and optional caches |
| A11 | Incorrect TLS/resource/schema/role, reader endpoints and forged recovery/activation metadata refuse | P08/P12, all connectors and operators |
| A12 | Public failures/logs disclose no secrets; receipt replay obeys current authorization and unchanged protocol error semantics | All HTTP, CLI, diagnostics and artifacts |

For each mutation exercise failure immediately before and after reservation,
attempt installation, primary effects/receipt COMMIT, control confirmation,
response publication and outbox acknowledgement. Inject connection loss,
timeouts, cancellation, process KILL and recovery-worker loss. Retain the first
failure and explicit negative controls that remove the relevant guard.

## Availability and resource acceptance

| ID | Required observation | Bound and interpretation |
| --- | --- | --- |
| L01 | Idle and active PostgreSQL restart/failover reopens qualified scopes automatically | Provider availability plus bounded retry/reconciliation; no every-incident credential replacement |
| L02 | Lost COMMIT reply resolves from receipt without duplicate effect or false success | Separate HTTP timeout from finite recovery attempts; unresolved outcome remains visible |
| L03 | Redis restart/flush does not lose authoritative state after migration | Rebuild is bounded; evaluate cold-cache load against DB reserve |
| L04 | Ordinary saturation does not restart supervisors or starve revocation/reconciliation | Measure queue delay, reserved connections, pending age and class-specific progress |
| L05 | Disjoint scopes can progress while one operation is unresolved | Prove independence from the complete dependency set; shared-control outage is not an independent scope |
| L06 | Foreground/background/cleanup/store wait and retained owners stay within configured budgets | Include all replicas, blocking tasks, SQL locks, memory, output and retries |
| L07 | Pool/catalog reuse preserves role/schema fencing through reconnect and migration | Fail altered catalog, permissions and generation; do not rely only on cached readiness |

Choose capacity from the actual connection/worker inventory and workload envelope,
then qualify it. Record arrival rate, concurrency, success/rejection classes,
p50/p95/p99 latency, queue time, lock time, connection/catalog work, history growth,
GC and recovery time. The retained 16-concurrency report is diagnostic input, not
a benchmark or a throughput target. Do not perform a physical measurement
campaign as part of this design-only review.

## Recovery acceptance classes

| Class | Start condition | Required terminal evidence |
| --- | --- | --- |
| R1 | No-effect transient connection failure | Fresh authenticated current connection; no allocated mutation or leaked owner |
| R2 | Qualified ordinary primary restart/failover | Current writer excludes the old writer; accepted heads/receipts correspond; relevant pending operations terminal |
| R3 | Primary COMMIT acknowledged remotely but response lost | Exact durable receipt and matching control decision, or safe fenced abort where no effect is proved |
| R4 | Cache process/contents lost | Durable security state unchanged and fresh cache provenance; bounded recovery |
| R5 | Old snapshot or primary loss | Isolated restore, verified baseline, complete accepted payload replay, content/history comparison, old-writer exclusion, fresh epoch |
| R6 | Control anchor or decryption/recovery key lost | Serving remains fenced; independent-current-anchor/key recovery requires a separately qualified operator process |
| R7 | Remote non-idempotent request response lost | Local attempt fenced; remote outcome retained as unknown; no blind replay or fabricated successful login |

R5 is not satisfied by snapshot restore alone. R6 is not converted into R2 by
selecting a different database ID. R7 may complete by safely terminating the
local authentication attempt, without discovering the remote provider's outcome.

## Provider and migration acceptance

Qualify the selected RDS engine/minor version, region, Multi-AZ deployment type,
parameter values, TLS roots, actual runtime/admin privileges, primary endpoint,
resource identity, failover/writer exclusion and backup/restore permissions.
Test with the restricted runtime role, not an administrator. Explicitly evaluate
the current `pg_control_system`, catalog/role and OS-dependent operator assumptions;
where unavailable, implement a provider contract rather than suppressing errors.
AWS regional/minor-version availability is deployment input, not inferred from a
successful local PostgreSQL fixture.

Migrate every S/P row under one coherent cutover plan. Verify all fourteen named
binary entries plus default main, Python/shell/SQL operators, triggers and
detached workers. Old credentials must fail both new connection and existing
session paths after the relevant fence. Confirm complete identity/subject,
membership, revocation, refresh, replay and audit/history correspondence. Do not
enable source-loss reconstruction until every authoritative table and trigger
effect has a versioned complete payload policy and a restore test.

## Review completion and implementation handoff

The design is ready for a user decision when storage responsibilities, S/P/B and
operator scope, state transitions, read/publication ordering, fencing,
source-loss limits, provider assumptions and the acceptance cases above have no
unassigned design decision at the protocol-plan level. The performance supplement
fixes the requested throughput/latency target, numerical qualification profile
and sensitivity limits. Hardware sizing, actual capacity, provider execution,
implementation wiring and proof discharge remain unqualified. A sensitivity
case that cannot fit its declared connection/restore envelope is a failed plan
condition requiring revision before execution, not a successful design result.

Before implementation starts, bind this proposal and its inventory to the current
source and retained evidence. Keep the fifteen proof families, seventy-one
reference entries, twenty-two delivery units and existing 8,805-obligation
baseline separate. Task1b receives affected protocol/shared-store regressions;
Task3 receives state-machine refinement, caller/SQL/supplier composition, own
preconditions, artifact correspondence and independent security acceptance.
New atomic and composite discharge remain zero.

## Prior source and local fixture validation

This proposal was reviewed against candidate
`aa44e360d36ff7e91b65634f284e8eed9c853035`, tree
`73898744ebfdfbda00e7a3cf75d2cc792b1fd84f`, with three local Python fixture
repairs. No Rust, SQL schema, production ACL or supplier implementation changed.
The inventory's twenty settings match the configured source declarations, and
all fourteen binary file names plus default main match the listed entrypoints.
Source-anchor existence was checked; this is not dynamic caller coverage.
The subsequent performance design adds P13/B09 and expands S12; the prior
five-scenario fixture results below do not execute those changes or the new
three-phase/sharded design. Its earlier snapshot remains separately retained.

The two observed CI failures were reproduced locally: maintenance activation
without the v16 seal, and authorization-code STRLEN denial stopping earlier in
continuity validation. After D12/D13 fixture repairs, the focused SQL recovery,
packaged normal protocol journey, packaged code-STRLEN refusal, actual root
runtime recovery and actual missing-drain negative control passed. The code
negative control reached code publication, refused it and issued no selected
code. Python lint/format and documentation lint passed. Tests used the exact
published native package plus the changed fixtures, not a new Rust build.

An initial negative-drain invocation incorrectly supplied the normal operator
and failed because it successfully drained the connection. That orchestration
error, the original failures, a cancelled unnecessary build and tool-setup
errors remain in private evidence. The corrected invocation uses the existing
one-guard mutation package and detects the retained old Redis connection.

This local validation does not turn published run `41812455976` green. No full
suite, GitHub rerun, push, commit, AWS action or new proof execution was performed
for this review. PR #295 stays Draft at the candidate above. The restart record
locates the private source/evidence manifest and test logs.

Implementation order is the operation/attempt and history primitives, read gates
and fencing, all authoritative backend migrations, outbox/recovery, managed
adapter, then bounded admission tuning. Each component must retain the original
domains and failure observations. The current work stops at the design proposal;
it does not authorize starting those runtime changes or activating a deployment.
