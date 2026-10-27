# Merge queue operations

Last updated: 2026-10-02

Status: active plan

Owner: Engineering

Audience: maintainers

Queue activation and pilot acceptance remain separate from CI preparation.

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
