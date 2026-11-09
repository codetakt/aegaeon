# Organizations candidate CI and review repair

Last updated: 2026-11-06

Status: current implementation baseline

Owner: Engineering / Verification

Audience: implementers, reviewers and operators

## Candidate and retained failures

Run [42012396090](https://github.com/codetakt/aegaeon/actions/runs/42012396090)
on `353a5a45a` passes DB Integration, dependency policy, supply chain and strict
Rust. The DB log contains zero `there is no transaction in progress` notices;
this is a different workload from the reported operational crash tests, not a
controlled estimate of their warning reduction. Copilot reports no findings.
Flake nextest passes 3,003 cases, fails the blanket ban on `crates/server/build.rs`
and leaves 135 selected cases unexecuted. The build script now extracts validated
SQL components and has no retired integration-fixture role. Inspect its contents
for every retired fixture marker, retaining the bans on retired seed modules and
binaries. Mutation controls must reject each marker reintroduced into the actual
build script. The failed run remains retained; complete successor CI is required.

On `b0706df1b`, run 41999718834 passes DB Integration again. Dependency Policy
and Supply Chain fail on RUSTSEC-2026-0441 (`pin-utils` unmaintained); the
lockfile repair and remaining audit coverage are recorded in
[Dependency Policy](../../policies/dependency-policy.md#organizations-ci-dependency-repair--2026-11-05).
Infrastructure run 41999718806 initially fails while downloading the AWS provider
checksum with HTTP 504, after its fixture checks pass. The one failed-job retry
at the same source succeeds. These are separate outcomes, not one clean first
attempt. Flake nextest passes 2,962 cases, fails two obsolete Redis-constructor
expectations and leaves 175 selected cases unexecuted. The corrected 59-case
source inventory checks the selected PostgreSQL constructors and retained
ownership order. Complete successor CI and review remain required.

Operational follow-up changes the common management SQL error boundary and
connection cleanup as specified in
[Management transaction ownership](management-transactions.md). The policy-read
regression terminates the actual blocked PostgreSQL query; the cleanup regression
captures actual SQLx notices, including an idle-ROLLBACK positive control.
Existing uncertain-BEGIN, admission retention, rollback, timeout and authority
closure tests remain required. Updated source guards follow the tracked BEGIN
facade and the selected PostgreSQL constructors; the previous Redis-constructor
expectations are not a production requirement.

## CI duration regression evidence

Normal PR run [41650755414](https://github.com/codetakt/aegaeon/actions/runs/41650755414)
at `fe722d830` and candidate run
[41990782770](https://github.com/codetakt/aegaeon/actions/runs/41990782770)
at `b9e1880d1` have the following observed job wall times:

| Job | Earlier PR | Organizations candidate | Candidate outcome |
| --- | --- | --- | --- |
| DB Integration | 21m26s | 51m38s | success |
| Flake Checks & Build | 29m24s | 63m21s | failure |

The DB service inventory grows from 724 to 1,325 cases; their reported execution
time grows from 13m59s to 37m23s. Release test compilation grows from 6m18s to
18m29s, release server compilation from 2m05s to 6m19s and native DB-test
compilation from 1m54s to 4m53s. Ordinary test execution is only 19.476s versus
30.753s before the candidate's failure. Preserve that failure and its unexecuted
checks. Source, runner and cache conditions differ: these observations establish
a regression worth repairing, not a controlled causal estimate or average.
The separately retained merge-queue run 41656703739 is not pooled into this PR
comparison. Aggregate job wall time is not CPU or billed usage.

The repair priorities are isolated DB-service shards with exact inventory union,
compile-artifact reuse with explicit source binding, and diagnosis of common
fixture cost. Any shards need independent PostgreSQL clusters because role tests
change cluster-wide state. Preserve every case, failure condition and Required
check. Do not increase build parallelism blindly on the memory-constrained runner,
weaken fault deadlines or rerun CI solely to obtain a favorable timing. No speedup
from these proposed changes has yet been established. The product's 10,000 req/s
and p99 target is separate and remains unmeasured.

## Earlier retained failures

Run 41990782770 on `b9e1880d1` passes DB Integration job 127122654857,
including 1,325 service-lane cases, SQL upgrade/model checks, packaged startup,
recovery/shutdown, 163 JWKS namespace cases, 11 fingerprint cases and Redis grant
correspondence. Flake job 127122654730 then exposes nine missing environment
reference entries: seven retained test Redis constructors and two legacy
observation fixture endpoints. Its workspace run passes 2,916 tests, fails the
documentation inventory and leaves 222 selected cases unexecuted. Document these
inputs with their test-only boundary; keep the exact inventory test unchanged.
Production runtime and SQL are unchanged. The failed run remains retained and
the next complete candidate CI must still pass.

Signed candidate `df595702e0985aacc9a3abaf8822d5b44fdcf5a4` is the
original Draft PR #295 baseline for this repair. PR Validation run 41944332555,
Infrastructure run 41944332322 and their original attempts failed. Their logs,
job inventories and Kani failure artifact are retained privately. Passing local
checks recorded before publication did not establish complete candidate CI health.

The first repair `18f45f712` passed the previously failing integrity/lint lanes.
Its PR Validation run 41952674270 then exposed the packaged LTI fixture's retired
Redis fault target in Flake Checks & Build and a repository-test stack overflow
in DB Integration Tests. Both failures are retained. The latter occurred after
691 PostgreSQL-only library cases and the separate registration case passed;
it aborted the 477-case mixed lane. Its missing correspondence artifact is a
consequence of that abort, not a separately waived result. F*, both Kani lanes,
strict Rust and VerifiedReqs integrity passed on this first repair.

The next signed repair `48a42d2bf` failed PR Validation 41960262040 in two
places: DB Integration job 127025083256 passed 690 PostgreSQL-only cases and
failed one lifecycle case with an unlabelled elapsed deadline; Flake job
127025083219 stopped on the client-registry environment inventory. The late SQLx
return/close race is independently reproduced with a controlled real SQL session;
the original log alone cannot identify which unlabelled wait elapsed. Initial
negative-control and subsequent test-development failures are retained.

PR Validation 41968034853 on signed `7944c4908` passed all 692 PostgreSQL-only
cases and the separate registration case, then aborted the mixed lane with a
stack overflow in `shared_redis_organizations_observed_cleanup_database_failure`
(job 127049895990). The same normal-stack failure is reproduced locally. The
concurrent cleanup future is boxed at its orchestration boundary, preserving
joined ownership and completion. Flake job 127049895754 independently stopped
after 778 passes on one old Redis-required expectation; that expectation is
updated to the selected PostgreSQL configuration contract. Its 2,355 unexecuted
cases are not counted as passes. Neither failure justifies increasing the test
stack or restoring the retired Redis requirement.

The affected configuration group exposed a second stale expectation locally:
the retained Redis constructor inventory was compared to the now-empty production
supplier list. Keep an exact seven-key legacy source inventory and separately
assert that the selected PostgreSQL runtime has no Redis suppliers. Unknown new
legacy keys still fail that inventory check. The initial wrong-working-directory
invocation and the subsequent real assertion failure are retained separately.

The operational publication also exposed a stale SDK project-source digest for
the regenerated management OpenAPI (Assurance integrity and VerifiedReqs jobs
127070317234/127070318300). Review the actual interface change together with the
management authentication and endpoint documents: explicit machine capability
plus domain Export, public service-principal ID, final credential locks and
post-lock expiry. Their three project pins and the SDK standards document revision
are updated together; human configuration/history/snapshot boundaries remain.
All 19 SDK contract checks and the complete `verified-reqs` derivation
`ns6wzrrnzhwb86gdnfhsxm7v3ds2wsx1-verify-reqs` pass. External source pins, contract
guarantees, profiles and `specified-not-attested` state are unchanged. This records
the interface for SDK reconciliation, not SDK implementation or proof attestation.

The failures have separate causes; no required check, test lane or failure result
is waived. This repair adds no migration file and makes no AWS change or
performance measurement. The target remains 10,000 HTTP requests/second and
ordinary API p99 at most 200 ms, without a measured claim.

Run 41976115979 on `03f052a3f` passes Assurance/VerifiedReqs but its Flake job
127076048692 rejects two expanded audit functions under the dedicated dev Clippy
inventory: `apply_grant_command` has 122 lines and delivery `transaction` has 105,
above the 100-line limit. Extract grant creation and final credential/session
revalidation into cohesive helpers. Keep authorization, row-lock order, receipts
and the final transaction unchanged. Both dev and release inventory checks and
the directly affected real PostgreSQL/HTTP regressions must pass; the separate
strict Rust result alone did not exercise this line-count gate.
Both inventories now pass (`3391igp8rihkyj51k60nsgf6fn47rnnm` dev and
`xp9mmrg342l7fpjgfqyjb0hmppjdq387` release). Five existing human audit/operator
regressions and the machine credential lock/expiry regression also pass on
`kmb4hlamibk5805n3i178vlgz7h82yx2-aegaeon-database-tests-0.0.0`.

The same run's DB Integration job 127076048656 passes 151 Redis cases, 694
PostgreSQL cases and the separate registration case. Its mixed lane completes
472 cases and fails five browser cases before their assertions because the
legacy step-up constructor asks for an unsupplied `AEGAEON_TEST_STEPUP_REDIS_URL`.
Bind that fixture directly to its existing `AEGAEON_TEST_REDIS_URL`, retaining
the same 300-second TTL, actual Redis adapter and namespace. All five browser
cases must execute successfully; no supplier skip or production Redis requirement
is introduced. Original failure logs remain retained.

The first corrected browser run passes five of six selected tests and exposes a
second stale fixture assumption: the capacity test waits for a TCP connection to
the legacy step-up store on ordinary authorize/consent, which no longer consult
that store when authentication is already satisfied. Keep session/rate fault,
cancellation and recovery cases. Replace the unused-store fault expectation with
actual listener assertions that authorize and consent complete without opening a
step-up connection. Preserve its initial peer-accept deadline failure separately;
do not lengthen that deadline or treat it as successful coverage.
The corrected native artifact
`rn1rabqnj1j8riadf7fiapgmabza989r-aegaeon-database-tests-0.0.0` passes all six
related browser tests with actual restricted PostgreSQL and Redis. The two
browser fixture files are its only executable-source differences from the
accepted management/runtime artifact; all owned suppliers stop successfully.

Run 41982443780 on `2034fb2a0` then exposes a source-inventory failure in
Flake job 127095802580. Workspace nextest completes 2,246 successful tests,
fails `management_app_state_handlers_remain_session_guarded` and leaves 891
selected tests unexecuted under fail-fast. The audit delivery handler now calls
the extracted `audit_identity` module; the inventory only resolves mutation and
snapshot helpers. Resolve the actual audit helper, requiring its human/session
and machine/team/capability markers plus both initial and final call sites.
Mutation controls must reject missing helper sources, calls and either identity
path. This remains a source inventory, not a control-flow proof; the actual
human/machine PostgreSQL and packaged HTTP checks retain their separate evidence.
All three affected inventory tests pass on
`ng30ymvxwkk8inw0mvaaxljkp510r8ml-aegaeon-database-tests-0.0.0`, including the
nine removed-call/identity-marker controls. Its only executable-source change
from the accepted browser artifact is this test inventory.

The same run's DB job 127095802556 passes 151 Redis cases, one pre-migration
case, 695 PostgreSQL cases, one registration case and all 477 mixed cases. SQL
upgrade/model checks, packaged startup and recovery/shutdown steps also pass.
The later Redis-only JWKS namespace runner incorrectly selects 13 PostgreSQL or
mixed cases: all 13 already passed in the preceding service lanes, then fail for
missing database inputs. The namespace run passes its other 163 cases.

Keep the PostgreSQL and mixed cases in their existing mandatory service lanes;
exclude their function prefixes only from the Redis-only namespace selection.
Use the identical selection for listing and execution. Source-inventory and
driver regressions ensure declared namespace cases remain selected and database
cases retain their service execution. Twenty-eight helper tests and 58 subtests
pass. The actual native inventory loses exactly those 13 duplicate wrong-supplier
selections, retaining all 163 namespace cases, which pass in an isolated network
namespace. The subsequent fingerprint runner's 11 cases and the 79 existing
Redis grant correspondence cases also pass locally. The initial failed run's
later missing correspondence artifact is retained as a consequential failure;
no required upload or failure gate is relaxed.

## Repairs and acceptance checks

| Failure | Repair and affected acceptance |
| --- | --- |
| Ordinary infrastructure/runtime supply still required retired Redis inputs | Align templates, delivery bundle validation and workflow fixtures with the ordinary PostgreSQL profile. Retain strict source contracts and negative supply tests; validate actual OpenTofu modules without plan/apply. Existing AWS Redis resources are not silently destroyed. These ordinary templates do not qualify an Organizations deployment. |
| Strict Rust rejected runtime schema extraction panics and fixed-size hash conversion panics | Extract and validate the same single-migration components at build time; copy the fixed digest slices directly. Missing/malformed components fail compilation. Run strict package Clippy and actual native/distribution compilation. |
| Kani linked native startup to its explicit OIDC session model | Exclude native constructors/startup from the model build; do not substitute a model for production PostgreSQL. Retain all selected decision harnesses and run the affected server groups. |
| Kani registry and failure capture were stale | Recognize the registered 61 required harnesses, including the four recovery preflight entries. Capture exactly one known Nix source root and reject ambiguity/escape. Exercise admission and capture regressions. |
| Runtime drift guard rejected reviewed source changes | Refresh the source hash manifest after reviewing PostgreSQL backend wiring, HKDF, and associated source deltas. This records source identity, not proof re-discharge. |
| PostgreSQL import/recovery lacked connection dependency access | Add only the ten non-secret column SELECT rights already present in schema.sql to the existing consolidated migration. Compare effective rights for the definer and maintenance roles across populated upgrade, fresh schema and dump/restore; secret columns remain inaccessible. |
| Lifecycle fixtures failed on CI password authentication | Give each isolated runtime role a fresh generated password and connect with it. Validate against a real PostgreSQL supplier using SCRAM over TCP, in addition to lifecycle lock/activation tests. |
| Four mixed PostgreSQL/legacy Redis HTTP tests ran in the PostgreSQL-only lane | Give these tests the existing mixed-supplier selector. Execute the actual signed-proof/PAR HTTP cases with both suppliers. Production stores remain PostgreSQL. |
| Packaged LTI journey injected session-read failure into retired Redis storage | Move the fault to the actual PostgreSQL browser-session table SELECT privilege, assert the effective privilege before each request, and preserve 503/no-publication plus same-intent recovery. Redis remains only for the legacy native fixture builder. |
| Concurrent invitation delivery and administrator recovery tests exhausted the default thread stack | Box the caller Future at the shared test-scope entry before entering nested witness wrappers, covering both direct and repository-helper callers. Poll on the same task, preserving concurrent SQL attempts, task-local admission, assertions and cleanup. Reproduce the aborts, then exercise the affected repository and issuer tests without increasing the stack limit. |
| Snapshot SQL test retained the predecessor's no-direct-read expectation | Match the adopted selected-database runtime's explicit ownership SELECT grant. Check current owners/subjects, refuse direct INSERT/UPDATE/DELETE/TRUNCATE on both history tables, and retain all scoped paging and invalid-input refusals. No runtime grant or migration changes. |
| Snapshot HTTP authorization always returned 503 from an entered snapshot scope | Run each live authorization check in its own explicitly scoped, owned ordinary task. Retain the parent snapshot admission through SQL cleanup; keep foreign/nested scope refusal and current-primary authorization. Check successful output, revocation, disconnect and stalled-body cleanup. |
| PostgreSQL session survived concurrent pool return and close | Use two fixed close passes after owned work drains; new acquisition stays disabled. The real-PG controlled regression fails on the old close with pool size 1, passes with size 0, then checks lock release and activation. Ten affected lifecycle cases pass with SCRAM authentication; no deadline increase. |
| Client-registry inventory excluded explicitly classified test store variables | Include the replay implementation and remove the contradictory test-prefix exclusion; keep complete literal classification. |
| Non-superuser administrator could not provision protected groups | Distinguish existing database-administrator capabilities from ordinary maintenance consumers; keep operational ADMIN-only authority refused. Fix the fixture's explicit migration-owner grant and exercise default/optional self-grants in the required catalog check. See [privilege boundary](managed-postgres-provisioning.md). |

The second repair is checked by catalog artifact
`dcvvx60bgvk81j90bczzwyc7spa2y400-aegaeon-organizations-catalog-upgrade`
(including both non-superuser installations and 16 exact privilege refusals),
packaged runtime `phb74rcszwj04krm4rlav9ll4sd30qcz-aegaeon-organizations-production-runtime`
and strict Rust `vasxbfq62n1mphyf1qp6dnrf7fwam00g-aegaeon-rust-strict-packages-0.0.0`.
The corrected environment inventory and removed-policy classification both pass
on `qdxyiy1sagzyxp9h5xlkrfml69zw16ky-aegaeon-database-tests-0.0.0`; the initial
additional unclassified legacy supplier failure is retained. Ten lifecycle cases
also pass on `83sc9mhp4yllh6lyyqgaxvbahjbvjn4j-aegaeon-database-tests-0.0.0`.
These local results do not replace fresh candidate CI.

## Review findings

Copilot review 5778238069 completed successfully on the published candidate. It
reported no concrete inline defect, but requested independent security/database
review and actual PostgreSQL lifecycle evidence for recovery and old-writer
exclusion. The latter is checked here. Independent acceptance and exclusion of
writers on a separate old cluster remain explicit operational/assurance boundaries;
static review or a database-local fence does not establish them.
Review 5778839612 on the first repair also completed successfully and reported
no concrete inline issue; it retained the independent acceptance requirement.

The review completed on `48a42d2bf` at 2026-11-05 03:20 UTC with no inline issue;
it still required independent security/database acceptance and operator restore
qualification. This is not approval or successful CI.

Five open inline findings came from CodeQL, not a failed Copilot service:

| CodeQL alert | Disposition |
| --- | --- |
| 209: clear-text packaged-test fixture credential | The real child process needs a short-lived test database credential. Create the file exclusively with mode 0600 inside a private temporary directory, retain cleanup on exit, and never publish its contents. This is explicit fixture custody, not application credential persistence. |
| 210: SHA-256 of legacy Redis machine secret | Retain the protocol-required Redis ACL hash encoding for this historical fixture. The input is a generated high-entropy machine credential, not a user password verifier. Replacing it with a password KDF would break the ACL protocol; production does not use this fixture. |
| 211: fixed packaged-test password | Generate a fresh fixture password for each test. |
| 212: literal invalid DPoP nonce | Retain this deliberately malformed negative-test input, which must be rejected without creating a nonce row. It is not an issued or accepted nonce. |
| 213: fixed browser-envelope salt/key test input | Generate the fixture key and derive wrong-key/digest controls by bit flips; preserve corruption and binding checks. Standard known-answer vectors are unchanged. |

Redis documents the ACL hash representation in its
[ACL SETUSER contract](https://redis.io/commands/acl-setuser/).
The repaired head also reported alert 214 on the lifecycle fixture's `CREATE ROLE
PASSWORD` statement. PostgreSQL stores a verifier in its catalog; an owned
PostgreSQL 18 check of the exact SQL template confirms SCRAM storage and a
successful SCRAM/TCP login, then stops the supplier. This is a false positive
about database plaintext storage, not a change to application credential policy.
The [PostgreSQL role contract](https://www.postgresql.org/docs/18/sql-createrole.html)
describes the catalog representation. Alerts 210/212 are classified as test-only;
209/211/213 are fixed by source changes, with the full CodeQL scan retained.
Alert 215 on `2034fb2a0` reports the same issue in the separate management-role
fixture. A fresh owned PostgreSQL 18 check executes that exact SQL template,
confirms a SCRAM verifier rather than a plaintext catalog value, authenticates
over SCRAM/TCP and stops the supplier. It is separately recorded and resolved as
a false positive. Copilot review 5780914025 on that head has no new inline
findings; its independent security/database and provider-qualification concerns
remain open under the existing handoff.

Security alerts are not suppressed merely to obtain green checks. Source fixes,
fixture-only exceptions and independent acceptance are distinct dispositions.

## Evidence and limits

| Affected check | Result |
| --- | --- |
| Populated 24-to-25 migration and catalog/column permissions | Pass: `w7a6asd61p86fkq55lwnf5h0h0sbdcjp-aegaeon-organizations-catalog-upgrade`; includes rollback/retry and real dump/restore |
| SCRAM PostgreSQL and mixed HTTP regressions | All 45 selected tests pass against `yw7msx4f6xs0hn7n2vxl95dwq6jywgg8-aegaeon-database-tests-0.0.0`; isolated suppliers stopped with no cleanup error |
| Browser envelope binding/corruption | One selected native test passes on the same artifact |
| Shared witness test scope and ownership read contract | 92 repository cases and one issuer case pass on `15lqj58pdj1gm51kqkn2s2y5pkx6b8dr-aegaeon-database-tests-0.0.0`; its one stale snapshot assertion is retained as a failure. The corrected snapshot case passes on `4w254n3kgllyz4dm83qqkas74nilfrly-aegaeon-database-tests-0.0.0`, including all eight direct-mutation refusals. These are 94 distinct affected cases across two bound artifacts; default thread stacks and all supplier cleanup checks pass. |
| Kani server groups | All 14 selected harnesses accepted, faults 0; partial run `run-omaug05s`, not the full gate |
| Actual packaged runtime | `iwd88wblr1jf1vf783vzbrl2z5pvwg2z-aegaeon-organizations-production-runtime` passes enabled/disabled startup, drain/maintenance, current-generation login, HEAD/GET export and refusal after durable grant revocation; no Redis supplier |
| Packaged LTI PostgreSQL session failure/recovery | `dvhiwlp5sl6668mg57pl2yjrqgs89ifi-aegaeon-lti-packaged-runtime` passes real TLS/Chromium signed GET/POST journeys, session-read refusal/recovery, revocation and seven startup refusals |
| Strict Rust | `r169d99cb5hj9lbvwabdw0jjsm9b7hri-aegaeon-rust-strict-packages-0.0.0` passes |
| Kani admission/capture helpers | 96 tests and 194 subtests pass; original failures retained |
| Infrastructure | Actual selected module validation/render/source contracts pass; no plan/apply or deployment |
| Source guards | All 41 linked and 13 monitored files match, including 16 critical files; strict proof-reference validation passes |

The repair evidence directory retains original CI logs, unsuccessful local
attempts, exact Nix artifacts, scoped Kani reports and owned-supplier cleanup
records. Later packaged HTTP and model results retain their own source bindings. No zero-test
filter is accepted. Kani results stay bound to their selected source snapshot;
later SQL/HTTP repairs require their own native acceptance and final candidate CI.

The frozen 8,805-obligation baseline is unchanged and new product/composite
discharge remains zero. [REC-H01–05](recovery-security.md#handoff-contract) retain
Task 1b/Task 3 standards, refinement, composition and provider qualification work.
Known functional defects remain the responsibility of this PR. Draft status,
signature requirements and ordinary merge admission remain unchanged.

The downstream local restart report and newly open operational defects are tracked
in [operational follow-up](operational-followup.md). They are not closed by these
CI repairs or by earlier component validation.

## Local duration follow-up (#312)

The candidate partitions the existing DB job into three concurrent service groups:
Redis, PostgreSQL and mixed PostgreSQL/Redis. The native package is built once in
that job and reused locally. Each group owns a unique Compose project, network,
volume set and dynamically assigned loopback ports. PostgreSQL and mixed groups
use different server processes and clusters; database names alone are not an
isolation boundary. There are at most three workers, two PostgreSQL containers
and three Redis containers. PostgreSQL-named tests include legacy Redis
observation fixtures, so that group also owns Redis; test names alone do not
determine supplier requirements. Existing job names, Required-check ownership, 60/120
minute limits, runner selection and Nix build capacity remain unchanged.

`ci/database-execution.json` retains the existing isolated-runner exclusions.
Discovery executes the actual packaged binaries with each original selector and
records target, profile, features, binary/build digests, source derivation,
configuration, driver digests and GitHub run/attempt/event identity. The producer
must match the current checkout's evaluated Nix output. Redis, pre-migration,
PostgreSQL (including cases without a `pg_` prefix), DCR, mixed, JWKS and fingerprint
selections are seven separate occurrences. PostgreSQL owns the single
pre-migration execution; mixed creates its own fully migrated restricted fixture.

The final always-run aggregate requires all seven exact test-name multisets,
five auxiliary obligations (fixture guards, SQL/models, packaged production,
recovery/shutdown and Redis-grant correspondence), and three supplier receipts.
Auxiliary runners retain their existing internal checks and failure semantics;
the aggregate records their owned commands, rather than claiming discovery of
all internal Python/model cases. Empty, omitted, duplicated, failed, cancelled,
unexpectedly ignored or foreign native occurrences cannot establish success.
A missing auxiliary, changed log, reused supplier, unconfirmed teardown or
incomplete run fails admission. Logs and incomplete receipts are uploaded even
when the job fails. Repeated invocation cannot replace an earlier receipt.

Compose teardown runs in a bounded finally path after startup, test or
cancellation failure only when the direct command group and every started
nested test owner have confirmed cleanup. Each nested owner creates an
unconfirmed receipt before launching its child and confirms cleanup only after
stopping its group. An incomplete, malformed or foreign receipt retains the
Compose project and its recovery information, and fails the lane. A failed
test whose process cleanup is confirmed may still release its suppliers.

Before any lane starts, all seven discovered suites and five auxiliary obligations
receive source/plan-bound `not_started` records. Initialization must complete before
supplier work starts. Lock acquisition is bounded to one second; the pinned
directory lock serializes an atomic, fsynced transition to `started` with a unique
invocation ID before
`Popen`; a second invocation cannot claim the same obligation. Final updates require
the same started invocation and never recreate a missing receipt.

The subject-fixture shell checks all expected lane receipts before either its
normal cleanup or EXIT cleanup. It conservatively retains the fixture when a
later suite is still `not_started`. Only the outer lane, after stopping the entire
command group, may accept an exact `not_started` record as evidence that a later
suite never started. Missing receipts always refuse cleanup; started obligations
must confirm process cleanup. The successful aggregate also requires started state,
the invocation ID and all existing completion, command, log and occurrence checks.
A cancellation after claiming but before spawning remains conservatively uncertain.
The protocol does not claim protection from a same-UID actor coherently forging
source-bound state. A cleanup exception can become the raised error while the
original work error remains in Python's exception context; these records do not
separately serialize both causes.

That decision also requires the original results directory to remain
available: missing parents, symlink replacements and directory identity changes
are lost evidence, not unstarted work. The outer controller captures the shared
directory identity before starting any lane; each lane holds an open directory
descriptor throughout its owned work and compares that original identity during
confirmation. A replacement empty directory cannot hide an unfinished receipt,
and a lane started later must still match the controller's original directory.

Cancellation handlers record requests without raising asynchronous exceptions.
Owned work checks those requests at explicit polling boundaries, while finalizer
entry, process registration, stop confirmation and result writing remain protected.
The packaged runtime retains ordinary groups until termination is confirmed and
refuses PostgreSQL teardown when that confirmation is unavailable. A successful
registered PostgreSQL start transfers to the supplier owner before a pending
cancellation is propagated. Cleanup failures retain the original work error and
write the available recovery information without publishing fixture credentials.

The namespace wrapper decides its terminal status after publishing its report and
exiting the pinned-receipt context. A cancellation observed at that completion
checkpoint preserves an existing nonzero status or changes success to failure;
at most one further write adds the cancellation to the report. Report I/O and
context-exit errors still fail the wrapper, and the additional write never clears
an existing work error. Signals arriving after the final checkpoint are outside
this finite cancellation boundary; no atomic return-and-signal guarantee is claimed.

The current-runtime fixture takes the same finite cancellation snapshot after its
result write and cleanup-scope exit. If that write missed a cancellation, one
additional write changes `passed` to false and records the cancellation before
propagating it. Existing work and cleanup errors retain priority, including when
that rewrite fails. No supplier stop or cleanup step is repeated. An I/O failure
can prevent correcting retained bytes; the fixture still fails, and a successful
report alone does not establish successful execution.

The recovery fixture bounds its direct I/O as well as its subprocesses. Its
generated administrator connection permits one local Unix socket, autocommit
and disabled TLS, with a five-second connection timeout. Each synchronous query
uses a five-second monotonic deadline and cancellation checks around generator
progress, including completion, with selector polling at 0.1 seconds. Abort
closes the client connection before propagating the original error; it does not
enter Psycopg's cancellation-and-drain wait. The maintenance advisory lock still
uses the same session throughout its active-worker check. Closing a client is
not independent evidence that a busy PostgreSQL backend has already exited.

HTTP readiness and token probes remain concurrent during the 45/120-second
outages, but run in owned process groups with total deadlines instead of an
unbounded thread join. Health requests also poll outstanding probe deadlines.
Only the fixed loopback endpoints are accepted; redirects are returned as their
original status, and bounded private results bind the requested endpoint and
completion time. All probe stops are attempted after failure; unconfirmed groups
remain registered and prevent supplier teardown. Initial credential-bearing DDL
uses the same owned command runner with a 180-second budget and retains partial
output in a private file on cancellation or timeout. Process-stop grace follows
the work deadline. These bounds assume kernel and local filesystem progress;
they do not establish recovery from an uninterruptible kernel operation, or
replace the separate real-supplier cancellation observations.

The Nix log observer's separate process group also has an explicit cleanup
receipt. The namespace owner passes a private directory and unique owner identity;
the observer records uncertainty before creating the group and confirms only
after stopping it. Before removing its scoped policy, the namespace owner checks
every receipt. Missing, malformed, foreign or unfinished evidence retains the
policy and recovery directory. Before any nested child can start, its identifier
is appended and fsynced to a separate registration ledger, then its unconfirmed
receipt is persisted. Registration, update and confirmation share a bounded
exclusive lock; at most 64 distinct invocations are accepted. Confirmation requires
exact agreement between the ledger and receipt names and a confirmed receipt for
every registration. A deleted individual receipt therefore cannot become an empty
successful inventory. The parent holds both the directory and ledger descriptors
through policy cleanup, and checks their pinned identities and the ledger's owner
header. Missing or replaced ledgers, zero/partial writes, duplicate registrations,
unknown files and a truncated ledger with remaining receipts all refuse cleanup.
A valid empty ledger with its original header is distinct from a zero-byte file.
This protocol does not protect against a same-UID actor coherently rewriting the
ledger and all corresponding receipts; it is an owned lifecycle evidence boundary,
not authentication against complete filesystem control. The parent's exit alone cannot confirm a nested
group's termination. These rules do not prove recovery after uncatchable controller or host
loss; retained numeric process IDs are diagnostic information, not permission
to signal a possibly reused process ID.

Successful teardown verifies removal of the owned containers, volumes and
network. Native child commands use owned process groups for cancellation; no
shared runner process group or Docker-wide cleanup is used. Docker log rotation
and per-obligation log bounds limit diagnostic storage. No artifact transfer,
shared mutable Cargo target directory or cached test-success receipt is added.

The inherited PostgreSQL startup guard waits for TCP readiness. The image's temporary initialization
server can answer Unix-socket `pg_isready` before it accepts the published TCP
connection. Version and authenticated-connection checks remain mandatory after
readiness. This addresses that startup race without retrying failed test cases.

Flake records the unchanged full Nix build command and timestamped stderr through
its completion, including output after nextest. These are log-delivery times,
not exact case durations, CPU time or inferred cache hits. Trace storage is
bounded and truncation is explicit. Build failure remains failure, with no retry
or reduced check inventory. Existing `--max-jobs 1 --cores 2` remains unchanged.
Compatible compilation reuse for the Flake tail requires this evidence before a
separate implementation is selected.

The 45-minute DB/pipeline and 90-minute Flake values in #312 remain targets.
Local functional validation cannot establish Hosted headroom. Compare ordinary
candidate and post-merge runs by source, event, runner, cache condition and
attempt, retaining failures and cancellations; do not rerun solely to obtain a
favorable timing. This independent follow-up must be based on successful main
and retain its own candidate validation.

PR #295 entered the merge queue at 2026-11-05 22:44:50 UTC and was removed at
23:07:37 UTC with `failed_checks`. Merge-group run
[42124120989](https://github.com/codetakt/aegaeon/actions/runs/42124120989), attempt 1,
at `8c337314170e064a6ca558447c80540ee81aad32` fails the PostgreSQL connection/authentication
probe before native DB tests. It is not a duration timeout or a successful
performance sample. The retained log does not establish the precise connection
failure cause; the startup-race correction does not by itself prove that cause.
The later TCP-readiness repair passed full candidate and merge-group validation.
PR #295 merged through the normal queue as
[`64333816a96c`](https://github.com/codetakt/aegaeon/commit/64333816a96c20f6f5f0b096448d7b93fe5b97b3).
The earlier failed execution remains separate from that successful successor.
