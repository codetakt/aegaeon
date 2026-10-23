# CI execution efficiency

Last updated: 2026-10-24

Status: current implementation baseline

Owner: CI / Automation

Audience: contributors, reviewers, repository administrators

CI optimization preserves the selected checks, test occurrences, proof
obligations, failure handling and source identity. A shorter successful job is
not an improvement if it stops executing an obligation. Required checks remain
the acceptance gate for PRs and merge groups.

## Current changes

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
