# Release Security Evidence Archive

Last updated: 2026-07-08

Status: snapshot

Owner: Release Engineering

Audience: release managers, maintainers

> **Status note (2026-07-08):** Point-in-time release evidence; rerun the named validator before using it for a new release decision.

## Scope

This document defines the evidence archive required by the
`release-security-evidence` enterprise-readiness gate in
`spec/enterprise-readiness-claim.current.json`.

The machine-readable manifest schema is
`spec/release-security-evidence.schema.json`; validate manifests with
`nix develop .#default --command bash -c 'python3 scripts/validation/validate_release_security_evidence.py <manifest.json>'`.
When the manifest is used inside an enterprise-readiness evidence bundle, validate
it with `--require-enterprise-ready` so publication, managed-provider,
performance, and KMS/HSM evidence are non-empty and required. In that mode, the
`publication` group must include both `publication-org-rollout` and the
enterprise-ready `sdk-release-publication-bundle` produced by the sibling SDK
release flow.

It is a release-evidence procedure, not proof that the enterprise-readiness
claim is active. The claim remains inactive until every activation-required item
in the claim gate is marked `complete` and validated in the same change set.

## Fixed claim posture

- Do not use `enterprise-ready` wording from this document alone.
- Do not reuse evidence from a different release candidate after material code,
  dependency, workflow, key-management, or hosted-evidence changes.
- Treat missing, stale, unsigned, or unlinked evidence as a release blocker for
  enterprise-readiness activation.
- Keep SBOM, vulnerability, dependency, fuzzing, sanitizer, conformance, and
  support-response evidence linkable from a single release archive manifest.
- For enterprise-readiness bundle review, keep the enterprise claim inactive
  while collecting evidence and include required `publication`,
  `managed_provider`, `performance`, and `kms` archive entries in the release
  manifest.
- In enterprise-readiness mode, every required manifest item must include
  `sha256`; local evidence paths must hash to that value.
- Evidence item `id` values must be unique within each evidence group so
  reviewers and validators never have to disambiguate duplicate archive entries.
- Required local evidence paths must stay inside
  `artifacts/releases/<release-id>/`; do not use `../` or absolute paths to
  borrow artifacts from another archive.
- Required external evidence must use `kind: "external"`, include `sha256`,
  and use `https://`, `s3://`, or `gs://`; `http://` is not accepted for
  enterprise-readiness evidence.
- The external URI / `kind: "external"` rule applies to every release manifest
  validation mode; enterprise-readiness mode additionally requires `sha256`.

## Required archive layout

For each release candidate, store evidence under:

```text
artifacts/releases/<release-id>/
```

The archive should contain:

- `manifest.json` with the release identifier, source revision, toolchain
  inputs, generated evidence paths, reviewer, and timestamp.
- `build/` with `nix flake check`, server build, and release build transcripts.
- `verification/` with compliance-matrix validation, runtime-link manifest
  validation, F* / Tamarin / Kani / dudect evidence when run for the release.
- `security/` with `cargo audit`, `cargo deny`, `cargo vet`, `cargo geiger`,
  `cargo udeps`, fuzz smoke, sanitizer, and security-suite logs.
- `sbom/` with CycloneDX SBOM output, grype results, optional Trivy results,
  checksums, and signatures when available.
- `conformance/` with OIDC/OAuth conformance exports when the release makes a
  conformance or certification-related statement.
- `kms/` with KMS/HSM parity artifacts when the release uses a KMS/HSM-backed
  OIDC signing deployment.
- `managed-provider/` with hosted commercial/enterprise provider evidence from
  the sibling SDK repository when enterprise-readiness is being evaluated.
- `performance/` with enterprise SLO baseline manifests and load / observability
  evidence when enterprise-readiness is being evaluated.
- `publication/` with publication-organization rollout evidence and the SDK
  release-publication bundle when enterprise-readiness or released-client
  wording is being evaluated.
- `support/` with the release support contact, response procedure, exception
  register, and known dependency-policy exceptions.

Machine-generated evidence remains authoritative under `artifacts/`; checked-in
Markdown should only define the required structure and stable interpretation
rules.

## Manifest minimum fields

`manifest.json` must include at least:

```json
{
  "$schema": "https://aegaeon.dev/spec/release-security-evidence.schema.json",
  "schema_version": 1,
  "release_id": "v0.0.0-rc.0",
  "source_revision": "<git-sha>",
  "flake_lock_revision": "<git-sha-or-content-hash>",
  "generated_at": "2026-05-19T00:00:00Z",
  "claim_context": {
    "enterprise_readiness_claim_active": false,
    "certification_claim_active": false,
    "admin_ui_assurance_claim_active": false
  },
  "evidence": {
    "build": [
      {
        "id": "nix-flake-check",
        "uri": "build/nix-flake-check.log",
        "kind": "log",
        "required": true,
        "sha256": "<64-hex-sha256>"
      }
    ],
    "verification": [
      {
        "id": "verified-reqs",
        "uri": "verification/verified-reqs.log",
        "kind": "log",
        "required": true,
        "sha256": "<64-hex-sha256>"
      }
    ],
    "security": [
      {
        "id": "security-suite",
        "uri": "security/security-suite.log",
        "kind": "log",
        "required": true,
        "sha256": "<64-hex-sha256>"
      }
    ],
    "sbom": [
      {
        "id": "cyclonedx-sbom",
        "uri": "sbom/aegaeon-sbom.json",
        "kind": "json",
        "required": true,
        "sha256": "<64-hex-sha256>"
      }
    ],
    "conformance": [],
    "kms": [
      {
        "id": "kms-hsm-classification",
        "uri": "kms/production-us-east-1-classification.json",
        "kind": "json",
        "required": true,
        "sha256": "<64-hex-sha256>"
      }
    ],
    "managed_provider": [
      {
        "id": "managed-provider-evidence",
        "uri": "managed-provider/evidence.json",
        "kind": "json",
        "required": true,
        "sha256": "<64-hex-sha256>"
      }
    ],
    "performance": [
      {
        "id": "enterprise-slo-baseline",
        "uri": "performance/enterprise-slo-baseline.json",
        "kind": "json",
        "required": true,
        "sha256": "<64-hex-sha256>"
      }
    ],
    "publication": [
      {
        "id": "publication-org-rollout",
        "uri": "publication/publication-org-rollout-report.json",
        "kind": "json",
        "required": true,
        "sha256": "<64-hex-sha256>"
      },
      {
        "id": "sdk-release-publication-bundle",
        "uri": "publication/sdk-release-publication-bundle.json",
        "kind": "json",
        "required": true,
        "sha256": "<64-hex-sha256>"
      }
    ],
    "support": [
      {
        "id": "support-response",
        "uri": "support/response.md",
        "kind": "markdown",
        "required": true,
        "sha256": "<64-hex-sha256>"
      }
    ]
  },
  "review": {
    "reviewer": null,
    "decision": "pending"
  }
}
```

Paths in `evidence` must be relative to the manifest file's directory or point
to an immutable external evidence store recorded for the release. Absolute local
paths are intentionally rejected so release archives remain portable.

## Freshness and invalidation

Evidence must be regenerated for the same release candidate being approved.

Regenerate the archive after any change to:

- source code or generated FFI artifacts included in the release
- `flake.lock`, Rust dependencies, F* / KaRaMeL / Tamarin tooling, or Nix
  package inputs
- release workflow, artifact signing, publication, or custody settings
- KMS/HSM signing configuration or JWKS rotation state
- hosted conformance, managed-provider, admin-console, or SDK evidence inputs
- documented support response policy or dependency exception register

## Minimum local command set

Use the Nix dev shell as the default execution boundary:

```bash
nix develop .#default --command bash -c 'OUT_DIR="$(mktemp -d)" scripts/flake/verify_reqs.sh'
nix flake check --print-build-logs
nix build .#server -L
nix run .#security-suite
```

Run KMS parity evidence when the release includes an AWS KMS / HSM-backed OIDC
signing posture:

```bash
nix develop .#ci --command bash scripts/validation/run_oidc_kms_parity.sh
```

## Activation checklist

Before marking `release-security-evidence` complete:

1. Confirm the archive manifest exists for the target release candidate.
2. Confirm every required evidence path exists or is linked to immutable
   external storage.
3. Confirm the evidence was generated from the same source revision and release
   candidate.
4. Confirm SBOM and vulnerability reports are present, with exceptions tied to
   `docs/policies/dependency-policy.md`.
5. Confirm the SDK release-publication bundle validates with
   `validate_sdk_release_publication_bundle.py --require-enterprise-ready`.
6. Confirm support-response contacts, response expectations, and escalation
   procedure are present.
7. Confirm the enterprise-readiness claim gate remains inactive unless all other
   activation-required evidence is also complete.

## Related documents

- `docs/releases/README.md`
- `docs/operations/management-platform-regulated-environment.md`
- `docs/operations/hardened-reference-deployment.md`
- `docs/policies/dependency-policy.md`
- `spec/enterprise-readiness-claim.current.json`
