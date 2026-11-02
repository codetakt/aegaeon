# Main validation recovery

Last updated: 2026-11-02

Status: active plan

Owner: Engineering

Audience: maintainers, verification reviewers

The main push at `05cec388039bc7e14c7e609ba0f8f0fd8e65c0fe` failed
[coverage run 41428948073](https://github.com/codetakt/aegaeon/actions/runs/41428948073),
job `125222358285`, in
`jwt_startup_selects_access_active_algorithm_and_legacy_introspection_slot`.
The JWT introspection key manager could not initialize. The run retained
2,339 passing tests, one failure and 728 ignored tests. This failure occurred
after merge; the preceding PR and merge-group results were successful.

Startup fixtures used a module-local environment mutex while KMS fixtures used
`KEY_ENCRYPTION_KEY_ENV_GUARD`. Both replace `AEGAEON_KEY_ENCRYPTION_KEY`.
The startup helper now uses that shared mutex through environment restoration.
This also covers the startup access-verifier fixture and future callers of the
same helper. No production cryptographic or runtime behavior changes.

## Validation

The database test package and Clippy build pass. The selected startup and KMS
suite passes 34 tests with eight test threads. A new contender-thread regression
checks that the startup guard excludes a KMS writer. Restoring the previous
module-local locking mechanism makes that regression fail; a separate normal
control still passes. The negative control keeps the new regression and is not
an execution of the entire historical source tree.

The original hosted interleaving was not recorded. The demonstrated isolation
defect explains a possible wrong-key read; it does not reconstruct that exact
interleaving. Retain the original failure and require the coverage workflow on
the repaired candidate and post-merge main before accepting recovery.

## Task 1b and Task 3 handoff

Task 1b should retain this fixture dependency when evaluating startup signing
and verification tests. Parallel tests must use the same process-wide key
environment guard, including restoration; a successful isolated test cannot
establish that exclusion.

Task 3 should associate these results with the tested source and preserve the
negative control. This repair establishes a test-fixture boundary, not a new
protocol proof or product assurance discharge. The failed main revision remains
an open CI incident until the repaired coverage and post-merge checks succeed.

## Kani runner capacity

The same revision also failed
[formal verification run 41428948042](https://github.com/codetakt/aegaeon/actions/runs/41428948042),
job `125222358509`, when its filesystem filled while fetching Nix inputs for
pure-Kani evidence admission. Its setup step omitted the existing hosted-runner
cleanup used by other verification jobs. Enable that same `free-disk` action
input for this job. The action records capacity before and after preparation;
its deletion paths and behavior remain unchanged.

Full Kani selection, source reconstruction, citation admission, retained evidence
and failure handling remain required. Static workflow checks do not establish
hosted capacity or proof success. Recovery requires the exact candidate's Kani
workflow and post-merge main to succeed, retaining the original disk failure.
Task 3 must distinguish an input-fetch capacity failure from a harness counterexample.
Both this capacity incident and the coverage incident must be resolved before
normal merge admission resumes.
