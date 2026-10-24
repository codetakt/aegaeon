# CI execution efficiency

Last updated: 2026-10-25

Status: current implementation baseline

Owner: CI / Automation

Audience: contributors, reviewers, repository administrators

CI optimization preserves the selected checks, test occurrences, proof
obligations, failure handling and source identity. A shorter successful job is
not an improvement if it stops executing an obligation. Required checks remain
the acceptance gate for PRs and merge groups.

## Current changes

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

The complete helper suite is divided into four whole-module groups:
`sanitizer`, `security-fuzz`, `dudect` and `other`. The new group contains
`test_dudect*` modules, including the actual collector/ACK regressions with
synthetic native inputs. It changes neither the samples in those fixtures nor
the complete discovery inventory. Fixture boundaries, fallback behavior and
occurrence-level receipt reconciliation remain in place.

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
