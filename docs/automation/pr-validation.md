# Pull Request Validation

Last updated: 2026-10-05

Status: current implementation baseline

Owner: CI / Automation

Audience: contributors, reviewers, repository administrators

## Selection policy

`.github/workflows/pr.yml` owns PR validation against `main`, including drafts.
`ci/pr-policy.json` lists the inputs eligible for reduced validation. Classification
uses the complete Git diff from the merge base to the PR head; a rename includes
both its old and new path. No GitHub changed-file API limit applies.

| Scope | Inputs | Required checks |
| --- | --- | --- |
| `docs` | Ordinary Markdown under `docs/` and explicitly listed root documents, including security and conduct contact information | Documentation structure, Markdown lint, new broken local file links, commit messages, PR title, CI policy regression tests |
| `integrity` | Verification/specification/evidence documentation and explicitly listed assurance registers, schemas and compliance matrix | Documentation checks plus `verified-reqs`, FFI contract checks and Python validator lint/type checks |
| `full` | Implementation, tests, extraction inputs, unknown files, executable documents, symlinks, shared scripts, CI policy/workflows, Nix and dependency inputs | Documentation and integrity plus reusable Core, Lint, Security, Formal Verification, Compliance, KMS parity and container workflows |

Documents consumed by Rust regression tests select `full`, including `README.md`
and environment configuration documentation. The policy lists these dependencies
explicitly. Adding a code or test dependency on documentation requires updating
that list; a regression audit catches existing literal Rust document references,
while computed paths still require human review. Unknown specification data and
validation-script changes select `full` until their complete consumers have been
established. File type alone does not establish independence from executable code.

The highest applicable scope wins. Empty or unreadable diffs select `full`.
Draft status does not reduce the selected checks. Validation runs on PR creation,
reopening, commit updates and title/body edits. Marking a draft ready alone does
not rerun it. Title validation therefore covers the title at the last run;
maintainers must check the final PR title and any merge or squash commit message
before merging. Main pushes, schedules and manual runs retain their existing
checks and trigger conditions. Compliance's PR invocation
continues to run its RFC MUST lane; its other lanes retain their original non-PR
conditions. Performance checks retain their main/scheduled/manual triggers.
Container publication remains disabled for PR events, including reusable calls.

## Documentation and CI helper execution

The Documentation lane calls `documentation.yml`. Document and PR metadata
checks run alongside three whole-module CI-helper groups: sanitizer,
security-fuzz and other. Each job has a 30-minute limit. The matrix keeps all
three groups enabled and does not cancel other groups when one fails.

Every worker performs the original complete unittest discovery before selecting
its modules. The final job requires successful metadata and worker jobs, matching
source/run/configuration identities, and coverage of every original occurrence.
Genuine class/module fixture skips retain unittest's skip events and actual test
count; they account only for the cases suppressed by that fixture. Missing,
duplicated, inconsistent or incomplete receipts fail the gate. Unsupported
discovery retains the complete suite or fails before partitioned execution;
the time limit still applies. No test is omitted based on changed paths.

`scripts/ci/run_docs.sh` retains the complete serial entrypoint. Local correction
checks should execute only the affected methods; hosted CI owns the complete
suite. Parallel job limits do not guarantee a particular hosted completion time.

## Classification and aggregate gate

The planning job extracts the classifier and policy from the exact PR base commit.
Editing a classifier or policy in the PR cannot use the new rules to select fewer
checks for that same PR. The `pr-ci-plan` artifact records commit IDs, changed paths,
selection reasons, scope and classifier/policy digests. A missing base policy during
initial adoption selects the full suite and records the bootstrap reason.

The always-running **PR Validation / Required checks** job evaluates direct `needs`
results from this run using the base revision's checker. Each selected job or reusable
workflow must report `success`; failure, cancellation, missing results and selected
skips fail the gate. Unselected jobs can be skipped, but cannot fail silently. A
failed planning job also fails the gate. Bootstrap requires every lane to succeed.

This is a CI selection mechanism, not protection against arbitrary edits to GitHub
workflow definitions. Workflow/policy changes need review. Repository administrators
must configure the aggregate check as required; this source change does not alter
hosted protection settings. See [branch protection](../policies/branch-protection.md).
Do not require an individual conditional lane or the historical passthrough checks.

## Formal check ownership

For full PR validation, Core evaluates every flake output with
`nix flake check --no-build`, then builds all current-system check derivations
except `verifyFstar`, `verifyTamarin` and `verifyKani`. Formal Verification owns
those three derivations and replays their retained evidence. This prevents
separate runners from rebuilding the same formal checks on a cache miss.
Both workflows remain mandatory inputs to **Required checks**.

`scripts/ci/run_core_pr_checks.py` records the complete ownership map in
`core-check-ownership`. A missing formal check, a package alias that resolves to
a different derivation, or a derivation assigned to both owners fails the check.
New check attributes default to Core. This division is enabled only by the full
PR caller; local `nix flake check`, main-push Core and manually invoked Core keep
their full check execution.

## Local reproduction

```bash
# Targeted controls when changing the documentation/helper gate.
nix develop .#docs --command bash -c \
  'PYTHONPATH="scripts/ci:tests/ci${PYTHONPATH:+:$PYTHONPATH}" python3 -m unittest test_ci_helper_shards test_pr_validation.WiringTests.test_workflow_selection_and_dependencies_match_policy test_merge_queue.WorkflowTests.test_group_docs_lints_range_without_fabricating_title'
nix develop .#docs --command python3 scripts/validation/check_docs_structure.py
nix develop .#docs --command bash scripts/lint/lint_markdown.sh

# Use full commit IDs for both revisions.
python3 scripts/ci/pr_plan.py --base "$BASE_SHA" --head "$HEAD_SHA" \
  --policy ci/pr-policy.json --output /tmp/pr-ci-plan.json
python3 scripts/ci/check_doc_links.py --base "$BASE_SHA" --head "$HEAD_SHA"

nix build .#verified-reqs .#ffi-contracts --no-link -L
```

The local-link check compares Git snapshots and rejects newly broken repository
file destinations, including incoming links to deleted files. It checks inline and
reference-style Markdown links, excluding code examples. It does not check remote
URL availability, heading anchors, or every renderer extension. Existing broken
links remain visible debt but do not block an unrelated change. Markdown lint and
document structure checks apply to the current tree.

## Build inputs and cache behavior

`nix/build-source.nix` removes the root Markdown files and `docs/` from production
compilation inputs. Rust sources, manifests, migrations, C/extraction outputs,
verification fixtures and other existing build inputs remain present. Rust test and
verification derivations retain the complete source, including document fixtures.
Consequently, a prose-only edit does not change the production server derivation;
checks which consume that prose can still change and run. Nix/build policy changes
always select the full PR suite.

The `docs` and `integrity` shells contain only the tools needed by their checks and
have no Rust build inputs or development-shell hooks. Formal proof and security
execution remain in the full workflows. Integrity validation establishes consistency
of recorded references and evidence; it does not replace those executions.
