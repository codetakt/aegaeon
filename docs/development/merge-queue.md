# Merge queue operations

Last updated: 2026-11-02

Status: active plan

Owner: Engineering

Audience: maintainers

Queue activation and pilot acceptance remain separate from CI preparation.

## Normal admission and main incidents

Before each normal enqueue, after source, signature, review and dependency checks,
run the read-only check with the exact current PR head and a new evidence file:

```bash
python3 scripts/ci/check_merge_readiness.py \
  --pr NUMBER --head FULL_HEAD_SHA --output NEW_OBSERVATION.json
```

Require exit zero and `normal-ci-clear`. This checks the current main commit's
complete push inventory (including observability), candidate workflows, checks
and external statuses. It also keeps the current main's scheduled, manual and
dynamic workflows separate; a green push does not cancel a failure in those lanes.
Pending, failed, cancelled, missing, malformed or
unavailable observations stop normal admission. A previous green main revision
cannot rescue the current one. Two observations must agree; changed source,
run/attempt or result identities require a fresh decision. Retain old failures.
Workflow selection first rejects every unfinished attempt, including retries of
older run IDs. A completed success supersedes unsuccessful observations only
when its timezone-qualified start is strictly later than every unsuccessful
update. Overlapping runs, tied boundaries and ambiguous retry start times cannot
establish recovery. Completion order alone is insufficient. Check/status IDs are
selected separately. Candidate collection includes every event at the exact SHA:
PR-associated workflows provide the required PR inventory, while push, manual,
scheduled and dynamic runs are checked separately. Another PR's workflows cannot
substitute for the requested PR; shared-SHA check runs and statuses remain checked.
An old successful run does not erase a newer failed or incomplete run. Review
the cause and disposition of earlier failures before relying on successor success;
repeating an unchanged failing test until green is not a repair.
Open incidents from older revisions also need an explicit resolution record;
the current-source API observation does not certify their closure.

The check is an additional operator gate. It does not authorize a merge, replace
signature/review/queue checks, or make API observation and enqueue atomic. Do not
cache its exit status or invoke old enqueue helpers without this check immediately
before their mutation. Retain expected-head protection when enqueueing. Observe
the checked merge-group identity and final main results separately. Admit one
ordinary change at a time and wait for its main workflows to complete before the
next admission. If a failure becomes known after enqueueing, stop further normal
admissions and remove pending ordinary entries where possible. Preserve failures,
fix the incident and verify main recovery before resuming.

A repair PR may need to enter while main is red. It requires a separate, explicit
incident decision identifying the failed main SHA, run/attempt/job, failure cause,
exact repair head/diff, affected workflows, positive and regression evidence,
reviewer/approver, scope, expiry and post-merge recovery condition. Keep all
candidate checks and signatures required. Only the named main-health condition
may be excepted; a label, unrelated dependency update, missing API data, an
author's claim or a general instruction to merge is not an exception. The normal
command deliberately provides no force/skip/repair switch. Do not alter branch
protection, fabricate a successful check or weaken tests to admit the repair.
Use a separately reviewed incident procedure and explicit authorization; if none
exists, keep the repair prepared and the queue stopped.

Distinguish a failed old PR run superseded by a successful reviewed integration
candidate, a failure first observed after merge, and an unresolved failure known
before the next merge. Post-merge metadata edits can start new PR workflows; their
results do not describe the original merge decision. Likewise, post-merge success
does not retroactively justify admitting an unrelated PR during a known incident.

This operator check does not install a GitHub branch-protection rule. Direct UI/API
merges outside the documented procedure are not mechanically blocked by this
script. Preserve the existing required checks and administrator protections.

## Install validation before enabling the queue

Merge the CI preparation PR and confirm its checks and signatures first. Keep
`Required checks` from GitHub Actions as the required status check on `main`.
PR validation also runs on title or target edits and on `merge_group` requests.
It records the event, source range, tested commit and tree, protected-base policy
and signature verification in the `pr-ci-plan` artifact.

A group event parent can itself be speculative. At planning time, CI resolves
`refs/heads/main` once through the GitHub API, fetches that exact commit, and uses
it for policy, signature range, classification and the final aggregate. Evidence
records both the event parent and this protected-main snapshot. The full delta
includes earlier queued PRs. Both bases must be ancestors of the tested group.
If main has advanced outside that ancestry, validation fails conservatively;
requeue against current main. PR validation retains the event base/head range.

After the preparation PR is merged, open **Settings → Branches → main → Edit**
and enable **Require merge queue**. Retain the existing `Required checks` entry
with GitHub Actions as its source, required reviews, and `enforce_admins` (do not
allow administrator bypass). Keep the existing protection until the queue
requirement is saved and confirmed.

Use these initial merge queue settings:

| Setting | Initial value |
| --- | --- |
| Merge method | Merge commit |
| Build concurrency | 1 |
| Minimum PRs to merge | 1 |
| Maximum PRs to merge | 1 |
| Only merge non-failing PRs | Enabled |
| Status check timeout | 60 minutes |

The previously observed 49-job path took roughly 24–35 minutes. Measure actual
runner wait and execution time before changing the timeout. Retain strict branch
freshness until the queue requirement protects `main`; do not leave a gap in
required validation while replacing manual freshness with queue validation.
This document does not itself change repository settings or enqueue a PR.

## Signature gate and review

The required planning lane checks GitHub's commit verification for every commit
introduced by a PR or group. Both `verified: true` and `reason: valid` are required.
Missing objects, API failures, unavailable verification, unsigned commits and
invalid signatures fail. Commits already in the protected base are excluded.
Generated group commits receive the same check. There is no unsigned synthetic
commit exemption.

After installation, the verifier, classifier and lane policy come from the
protected base. The preparation PR alone may bootstrap from the original
installation base on the same-repository `ci/merge-queue-validation` branch;
its artifact explicitly records that the mandatory manual local and GitHub
signature gate is still required. The bootstrap verifier also checks GitHub
signatures, but this does not replace maintainer review of the installation.

Cryptographic signature validity does not establish maintainer authorization of
the signer. Before enqueueing, verify every introduced development commit uses
the configured authorized identity, verify GitHub reports its signature as valid,
and bind review approval to the exact PR head. Review changes after approval
before enqueueing the new head. Review comments and mandatory checks must be
resolved under the repository's normal merge rules.

## Run an explicitly authorized pilot

1. Obtain authorization for the concrete pilot PRs. Enqueue a parent before any
   dependent PR. Do not infer product merge authorization from CI installation.
2. Read the group evidence and compare the recorded test commit/tree with GitHub's
   group. Confirm the entire group delta selects the required validation lanes.
3. Require all selected checks, including signature verification, to succeed.
   If GitHub generates an unsigned group commit, the pilot fails and queue
   acceptance remains pending a separately reviewed policy decision.
4. Confirm group runs only build/load the container; they must not log in, push
   images or publish attestations. PR and group compliance lanes must match.
   Existing CI cache writes remain permitted and are not release publication.
5. After merge, read back the final main commit/tree and signatures; compare them
   with the checked group and record any discrepancy before accepting the pilot.
6. Consider concurrency 2 only after the pilot and runner-capacity evidence show
   that groups finish within the configured timeout without cancelling each other.

Docker publication is limited to main or `v*` tag pushes and manual runs on those
refs. SBOM attestation is limited to public-repository main push, manual or
scheduled runs. SLSA provenance and container-security uploads retain their
main-push requirement. Unknown reusable-workflow origins cannot publish images
or attestations.
