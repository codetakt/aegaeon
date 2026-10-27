# CI execution efficiency

Last updated: 2026-10-27

Status: current implementation baseline

Owner: CI / Automation

Audience: contributors, reviewers, repository administrators

CI optimization preserves the selected checks, test occurrences, proof
obligations, failure handling and source identity. A shorter successful job is
not an improvement if it stops executing an obligation. Required checks remain
the acceptance gate for PRs and merge groups.

## Current changes

Fuzz Smoke and Cargo Geiger use the existing runner disk-capacity guard. Cleanup
is skipped only when the workspace, runner temporary directory and Nix store
filesystems each have at least 80 GiB available. A missing Nix directory is
checked through its nearest existing parent. Insufficient or unreadable capacity
retains the original cleanup. The other security stages keep unconditional
cleanup; commands, toolchains, budgets, result checks and evidence recovery are
unchanged.

The main run [40158609276](https://github.com/codetakt/aegaeon/actions/runs/40158609276)
reported 86 GiB free before both jobs, with cleanup taking 108 seconds for Fuzz
and 235 seconds for Geiger. These observations motivate the bounded opt-in; they
do not establish maximum disk use or an overall CI speedup. Both jobs report
capacity after the security stage and before workflow output cleanup, including
on failure. That snapshot is not a peak measurement. Fuzz also retains its
existing receipt-bound internal cleanup and recovery.

OpenAPI dependency preparation and validation use a dedicated source boundary.
It excludes `.github/`, `ci/`, `scripts/ci/` and `tests/ci/` from the existing
build source, so changes confined to CI orchestration do not invalidate the
OpenAPI build. All other build inputs remain, including unknown new paths,
Rust and native sources, Cargo configuration, generated files, migrations and
fixtures. The existing exclusion of documentation is preserved. This filter
is local to OpenAPI; other Rust consumers keep their own source boundaries.

The OpenAPI command still compares both checked-in JSON artifacts and runs all
four original unit tests with the same locked Cargo commands, profile, features
and native toolchain. Changes to relevant inputs invalidate the check; stale
JSON and missing required native sources fail. CI orchestration retains its
own validation and the full lane selection. A future OpenAPI dependency on an
excluded directory requires revisiting this boundary before using that input.

The boundary is tested with file changes, additions and removals, and with the
actual package source. Local sandbox builds retained the same generated JSON
and test inventory; derivation comparisons confirmed reuse for CI-only changes.
These checks establish cache eligibility, not a measured reduction in Hosted
elapsed time.

The full-scope Kani derivation excludes only `docs/automation/`, `tests/ci/`
and `tests/constant_time/` from its existing source. Changes confined to these
CI documentation and helper directories no longer invalidate that derivation.
All other inputs remain, including Rust packages and build scripts, native and
generated sources, embedded WASM and other fixtures, Cargo configuration, proof
registries, citation data, tool packaging and unknown new paths. Other checks
retain their source boundaries and continue validating the excluded files.

Kani still executes its complete required and diagnostic selection when the
derivation builds. The Hosted wrapper continues reconstructing the retained
records against the current source and checking citations, including when Nix
reuses an output. Discovery freshness, dependency preparation, flags, deadlines
and rejection rules are unchanged. A future Kani dependency on one of the
excluded directories requires revisiting this boundary before using that input.
Source identity tests cover changes, additions, removals and near-prefix paths;
cache eligibility alone does not establish a Hosted elapsed-time improvement.

Nextest uses a dedicated dependency artifact with the same ordered OpenSSL
pkg-config input as its consumer. OpenSSL precedes Crane's zstd input in both
search paths. This avoids invalidating the AWS-LC build-script fingerprint solely
because the dependency producer used a different `PKG_CONFIG_PATH`. The source
build still selects static AWS-LC; this change does not select OpenSSL as the
cryptographic backend.

The shared server/Clippy dependency artifact is unchanged. Dependency preparation
retains its check, build and test-no-run commands, and Nextest still executes the
full workspace tests with the same profile, features and existing skips. The
additional artifact adds cold build and storage cost; reuse is not a previous
CI result, and one local comparison does not establish a Hosted speedup.

The `verify-jose` Nix check prepares the ten package/feature combinations used
by its Cargo tests in the dev/test profile. It selects `target/verify-jose`
before Crane restores the dependency products. Feature combinations remain
separate, and Cargo fingerprints determine reuse; changed inputs rebuild.
All 32 original Cargo invocations and the Python conformance check still execute.
The direct Hosted JOSE workflow is unchanged. Dependency preparation compiles
artifacts and does not supply test-result evidence. Populating this cache adds
compilation and storage; no reduction in initial total compute is assumed.

The JOSE Nix check and its dependency preparation exclude only
`docs/automation/`, `scripts/ci/` and `tests/ci/` from their source. Changes confined
to these orchestration paths no longer invalidate the check. Workflow files stay
in the source because Rust guards read them. All other inputs remain, including
Rust packages, build scripts, native/generated sources, vectors, fixtures,
verification scripts, other documentation and unknown additions. The full
32 Cargo invocations, Python conformance test, toolchain and failure handling
are unchanged. The excluded paths retain their CI validation; a future JOSE
dependency on them requires revisiting this boundary. Cache eligibility is
distinct from a measured reduction in Hosted execution time.

The JOSE verification job retains the first TLV parity output for the default,
entry-validator, FFI and strict FFI profiles. Its later profile report checks
the required producer outcomes and retained log digests instead of running those
four identical commands again. The strict `verified-claim` profile retains both
its original default-thread execution and its later serial execution: those
commands are different obligations. This reuse is confined to one job and does
not substitute results from another event or from the security/KMS suites.

The first invocations retain their order, feature flags and test arguments.
Missing, empty or changed output, unsuccessful producer steps and logging errors
fail the report; they do not trigger a replacement test. Each of the five profile
logs and the combined report remain available as artifacts.

The Hosted KMS parity job uses `run_oidc_kms_parity.sh --nix` to build or fetch
the current checkout's `oidc-kms-test` package. This package compiles the server
library test with default features plus `kms-aws`, the test profile and pinned
Rust/native tools. It retains the full verification source boundary. Cargo's
artifact messages must identify exactly one matching executable; its bytes and
build identity are recorded in a separate compilation receipt.

Only compilation is cached. Every attempt still checks the LocalStack endpoint,
executes the original exact test in the server package directory, and validates
one completed, non-ignored test. The execution log and receipt are fresh; a cached
binary is not a cached parity result. Missing or changed package bytes, build
failure, service failure, failed execution or incomplete output fail the job.
The original Cargo path remains available without `--nix`, including the real
AWS entry point. LocalStack success does not establish real AWS parity. Initial
cache population adds build/storage cost; no overall CI speedup is assumed.

The complete helper suite is divided into four whole-module groups:
`sanitizer`, `security-fuzz`, `dudect` and `other`. The new group contains
`test_dudect*` modules, including the actual collector/ACK regressions with
synthetic native inputs. It changes neither the samples in those fixtures nor
the complete discovery inventory. Fixture boundaries, fallback behavior and
occurrence-level receipt reconciliation remain in place.

The sanitizer supervisor uses `os.scandir` paths directly when inspecting Linux
process groups, avoiding repeated `Path` construction for each `/proc` entry.
Every call still reads the current process state and group membership. No PID,
membership or exit result is cached, and only vanished processes are ignored;
unreadable or malformed records still fail supervision. Command deadlines,
termination, final descendant checks and the complete helper inventory remain
unchanged. This reduces scan overhead without reducing lifecycle coverage.

The Dudect timing-file validator retains two exact payload summaries during
each validation. Synthetic helper batches alternate between two payloads, so
a one-entry cache repeatedly recomputed their distributions. Reuse requires
equal current bytes, case and input width. Every file is read and hashed again;
frame context, order and cumulative certificate checks still run on each frame.
Returned summaries are copied so changes to one result cannot affect another.

The cache retains at most two payloads (5,373,952 bytes with the current largest
input width), plus their summaries. A third distinct payload evicts an older
entry. The cache does not retain file acceptance or survive a validation call.
Full-size fixtures, sample counts, test invocations and rejection assertions
remain unchanged. This reduces diagnostic recomputation; it does not establish
new physical timing evidence or change a statistical acceptance condition.

Successful runs [40031175387](https://github.com/codetakt/aegaeon/actions/runs/40031175387),
[39982940198](https://github.com/codetakt/aegaeon/actions/runs/39982940198) and
[39988492614](https://github.com/codetakt/aegaeon/actions/runs/39988492614) spent
26m36s to 35m40s in the former `other` job. Splitting that serial work allows
unrelated helpers to proceed concurrently. Four workers add one runner setup;
this is a latency optimization, not a claim of lower total compute time.

Two Nix checks have explicit source and tool boundaries:

| Check | Complete source inputs | Runtime tools |
| --- | --- | --- |
| Workflow lint | Entire `.github` tree, including new workflows, local actions and configuration; lint script | Bash, coreutils, findutils, actionlint and shellcheck |
| Tamarin | Entire proof and regression-fixture directories, shared selection, evidence registry, admission evaluator, producer and hosted wrapper, admission tests | Bash, coreutils, Python standard library, Tamarin and Maude |

These checks no longer depend on unrelated Rust or documentation contents, or
the F*/extraction/cryptographic tool bundle. Their Nix definitions, tool package
identities and transitive tool dependencies remain part of the derivations.
Relevant input changes invalidate the output; missing required inputs fail.
Empty workflow or admission-test discovery also fails.

The compliance-matrix schema/path check also uses the lightweight Python
environment. It retains the full source tree because its matrix can reference
files anywhere in the repository; only the unnecessary proof tools are removed.

This is computation reuse through Nix, not reuse of a previous CI success.
The current workflow still invokes each check. Tamarin's hosted wrapper still
replays the retained admission records against the current evidence registry,
and every selected theory/lemma must be admitted. No proof selection, warning
exception, timeout or acceptance criterion changes.

RFC compliance reporting uses the output and outcome of the required test
invocation. Report creation does not execute the suite again, including after
cancellation. The original stdout/stderr log is retained with the report;
missing output is identified explicitly, and test/logging failures remain fatal.

The RFC 7520 job uses the same approach: execute its original Cargo command
once, retain both output streams, and generate a JSON report from the recorded
step outcome. `rfc7520-results.json` is a versioned outcome/log receipt, not a
second libtest event stream. Its artifact also contains `rfc7520.log`. The
conformance summary requires a successful producer job, a successful test
outcome and the corresponding nonempty log; file existence alone is insufficient.

## Validation and measurement

Before publication, verify complete discovery and the helper receipt rejection
tests, build both checks in the Nix sandbox, and run Tamarin record replay.
Test the derivation identities under changes to every listed input category,
including new files and missing mandatory inputs. Unrelated Rust/documentation
changes must leave these two check identities unchanged.

Measure the resulting PR and merge-group runs using job and step timestamps.
Record helper inventories, test results, critical-path elapsed time and total
job time separately. Runner allocation, queueing, cache state and unrelated
source changes limit comparisons with historical runs; do not describe a
single before/after run as a guaranteed speedup. A failure remains a failure,
including missing receipts or an incomplete group.

## Remaining selection boundary

Earlier work already added component inventories, protected plan transport,
proof/check ownership and executable verification gates. The active version-2
planner nevertheless selects the full lane set. Its dependency authority has
unresolved discovery/transitive-input conditions and explicitly does not adopt
graph narrowing. These optimizations retain that decision.

Before enabling component-based omission, close the holds in
`ci/ci-input-authority.json`, connect each selected component's actual checks,
and demonstrate that relevant base/head/tested-input changes select every
required consumer. Unknown or incomplete dependency information must select
the full route. Inventory preparation alone is not sufficient authority to skip
checks.

F* source narrowing and cross-event producer reuse likewise require their own
complete input and evidence contracts. They are not enabled by the Tamarin
boundary. External Dudect/performance qualification and release admission remain
governed by the [CI execution boundary](../development/ci-execution-boundary.md).

## Further helper balancing

The four helper workers retain complete modules, fixture lifecycles, discovery
order and exact-once accounting. `test_sanitizers` moves from the sanitizer
worker to the Dudect worker; these names identify execution partitions, not
verification scopes. The worker count and deadlines remain unchanged, and new
modules retain the existing prefix classification.

In [run 40416417430](https://github.com/codetakt/aegaeon/actions/runs/40416417430),
`test_sanitizers` accounted for about 274 seconds of test-body time, compared with
about 701 seconds for `test_sanitizer_dispatch` in the same worker. Moving the
complete module to the less-loaded worker gives an estimated longest test step
of about 854 seconds instead of 1,069 seconds, using the recorded step durations
and transferring that 274-second body cost. This is a placement estimate, not a
measured CI speedup: fixture costs are not transferred by that calculation, and
setup, machine contention and runner allocation can differ. The same run had
430 seconds between creation and start of the Kani Pure job. This change does
not increase runner or merge-queue concurrency or claim to eliminate that wait.

## Follow-up work

The integrated helper, Nix, OpenAPI and reporting improvements do not close the
entire optimization program. The following work remains in dependency order.
Each implementation must retain its original result and evidence requirements;
an unchecked item is not permission to omit a check.

| Priority | Work | Depends on | Completion evidence |
| --- | --- | --- | --- |
| 1 | Inventory remaining Rust, JOSE and KMS producers and consumers | Current workflow and command inventory | For each invocation: source, toolchain, features/profile/backend, test identities, runtime services, events, outputs and failure policy; identify equivalent and complementary executions separately |
| 1 | Reconcile all protected-input authority holds | Direct component checks and actual discovery paths | Current source evidence for every entry in `ci/ci-input-authority.json`; base/head/tested union, additions, removals, renames and unknown-input controls; unexplained inputs retain full selection |
| 2 | Separate additional Rust build/test and lightweight-check inputs | Complete producer and transitive-input inventories | Build scripts, generated/includes, migrations, fixtures and tools retained; relevant mutations invalidate outputs, irrelevant changes preserve outputs, mandatory-input removal fails, actual test inventory agrees |
| 2 | Share equivalent JOSE/KMS build products | Exact compilation and runtime identities | Same target/profile/features and backend, all original tests/results accounted for, independent service tests preserved, missing or mismatched products rebuild |
| 2 | Evaluate input selection in shadow mode | Explicit partial input mappings; full execution remains authoritative | Use `report_input_selection.py` to retain unknown consumers, all holds and old/current test correspondence. Compare with full execution for docs, infrastructure, component, Rust/proof, mixed and unknown changes. Resolve all affected holds before a separate change enables omissions. |
| 3 | Reuse results across events | Complete producer/consumer equivalence and trust rules | Revision/artifact binding, trusted producer, successful complete evidence, expiry/revocation checks and full fallback; dynamic and publication responsibilities retain their owners |
| 3 | Review F* checked-file/pass reuse and Tamarin batching | Separate proof-evidence designs | Preserve solver context, module/interface and assumption-graph inputs, every admitted obligation, exceptions, outputs and freshness; ordinary CI optimization does not establish product assurance |
| Parallel | Measure resource effects | A fixed before/after candidate and unchanged obligations | Matched event/runner/tool/cache scenarios, elapsed and summed job times, waits, setup/build/test times, disk peaks, substitutions, failures and retries; unmatched historical runs stay descriptive |
| Parallel | Audit legacy and manual consumers | Workflow, runbook, scaffold and dynamic-call inventory | A documented replacement or retained owner before removing a helper/job; absence from workflow search is insufficient |

Keep three boundaries explicit:

- Cache capacity/eviction is an investigation, not an established cause of slow
  runs. Obtain service evidence before changing capacity or cleanup thresholds.
- Tested versus shipped release artifacts and external qualification belong to
  the release execution boundary. They remain required for their claims, but
  are not silently added as prerequisites to every local CI optimization.
- Blanket deletion of main triggers, hash-only selection, weaker tests,
  unreviewed proof batching and increased queue concurrency are not adopted.

For each item, record the implementation PR, actual validation, remaining
conditions and integration result separately. Complete direct checks and pinned
extraction routes already integrated in earlier PRs must be reconciled with the
current code rather than implemented a second time.

## Coverage compilation reuse

Coverage caches only instrumented dependency compilation products in a separate
target directory. The exact key includes the runner OS/architecture, Cargo lock
and manifests, toolchain, Cargo configuration, Nix definitions and build scripts.
There is no fallback key. Cargo still checks dependency fingerprints and rebuilds
when necessary; the normal `cargo llvm-cov --workspace` command always cleans
workspace products, runs all tests and generates a new report, even on a hit.

Before a successful miss is saved, `cargo llvm-cov clean --workspace` removes
workspace executables and coverage results. A remaining raw/merged profile or
LCOV file fails cache preparation. The cache never supplies a previous test
outcome or changes the 40% threshold. Failed tests or threshold checks prevent
a new cache save. Cache absence still executes the complete cold build.

A local full-workspace comparison retained all 2,662 passing tests, 455 existing
ignored occurrences and the same coverage file/function/line inventory. The
cold run took 181.6 seconds and dependency reuse with standard cleaning took
145.5 seconds after archive restoration, with another 1.4 seconds to restore;
both reported 46.77% line coverage. Dependency preparation for
saving added 7.9 seconds of cleanup and 1.4 seconds of compression; the archive
was 337 MB. Network transfer and Hosted cache-hit behavior still require direct
observation; these local values are not a claim about overall Hosted latency.
