# Releases Overview

Last updated: 2026-10-13

Status: current implementation baseline

Owner: Release Engineering

Audience: release managers, maintainers

This directory contains operator-facing release runbooks and curated release
evidence summaries. Keep release procedures in `runbooks/` and point-in-time
evidence in `evidence/`.

## Required human dependency review before the next release

Do not tag, dispatch a release workflow or publish the next Aegaeon release
(including a prerelease) until the human review in
[issue #220](https://github.com/codetakt/aegaeon/issues/220) is completed and its
attributable acceptance is linked from the release evidence for the exact candidate.
Security/Verification owns the review; Release Engineering checks its completion.
The [dependency policy](../policies/dependency-policy.md#human-review-required-before-the-next-release)
defines this manual gate. AI audits, successful CI and integration of the dependency
PRs allow development to continue but do not satisfy the human release review.
Existing release workflows do not automatically enforce this issue's state.

## Scope

- release procedures and validation summaries
- pointers to machine-generated release evidence under `artifacts/`
- human-readable indices for conformance, deployment validation, and release readiness

## Canonical Documents

- `[spec]` [Public assurance statement and release record](../verification/claims/assurance-statement.md)
  defines the qualified server/SDK wording and its release-specific evidence requirements.
- `[index]` [Release runbooks](runbooks/README.md)
- `[index]` [Release evidence](evidence/README.md)
- `[index]` [KMS/HSM classification manifests](evidence/kms-hsm-classifications/README.md)

## Evidence Locations

- `artifacts/conformance/` — conformance-suite exports
- `artifacts/sbom/` — SBOM and vulnerability scans
- `artifacts/release/` — release smoke / build transcripts
- `artifacts/releases/<release-id>/` — enterprise-readiness release evidence bundle

## Reading Rule of Thumb

1. Use `runbooks/` when executing release procedures.
2. Use `evidence/` for source-managed summaries and bundle manifests.
3. Treat `artifacts/` as the authoritative home for current machine-generated outputs.
4. Use `docs/program-management/` for planning and `docs/verification/` for formal-claim scope.
