# Enterprise Readiness Evidence Bundle

Last updated: 2026-07-08

Status: snapshot

Owner: Release Engineering

Audience: release managers, maintainers

> **Status note (2026-07-08):** Point-in-time release evidence; rerun the named validator before using it for a new release decision.

## Scope

This document defines the single evidence-bundle entry point for Phase 1
enterprise-readiness activation review.

The bundle does not activate the claim by itself. It validates that the required
evidence artifacts are present and individually acceptable before a human
reviewer changes any public wording or flips `claim_active`.

## Canonical schema and validator

The source-managed bundle schema is:

- `spec/enterprise-readiness-evidence-bundle.schema.json`

Validate bundles with:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_enterprise_readiness_evidence_bundle.py <bundle.json>'
```

For final activation-review evidence, require approval records with:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_enterprise_readiness_evidence_bundle.py --require-approved <bundle.json>'
```

For Phase 1 closure, use the stricter wrapper. It requires the canonical Phase 1
claim-gate evidence IDs to be `complete`, keeps `claim_active=false`, verifies
that the bundle points at the same claim gate being reviewed, and validates the
bundle with approval records:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_enterprise_readiness_phase1.py <bundle.json>'
```

To assemble a standard release archive from real evidence artifacts, use the
collector. It validates the source evidence first, copies local nested evidence
referenced by KMS/HSM and SLO manifests, writes `manifest.json`, writes
`enterprise-readiness-bundle.json`, and then validates the generated archive:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/collect_enterprise_readiness_phase1_evidence.py \
    --release-id <release-id> \
    --publication-org-rollout <publication-org-rollout-report.json> \
    --sdk-release-publication-bundle <release-publication-bundle.json> \
    --managed-provider-evidence <managed-provider-evidence.json> \
    --kms-classification <kms-classification.json> \
    --enterprise-slo-baseline <enterprise-slo-baseline.json> \
    --build-log <nix-flake-check.log> \
    --verification-log <verified-reqs.log> \
    --security-log <security-suite.log> \
    --sbom <aegaeon-sbom.json> \
    --support-response <support-response.md>'
```

## Required evidence

The bundle must link:

- publication organization rollout report validated with `--require-ready`
- release security evidence whose `publication` group also contains a required
  enterprise-ready `sdk-release-publication-bundle`
- managed-provider evidence validated with `--require-enterprise-ready`
- one or more KMS/HSM deployment classification manifests
- release security evidence manifest validated in enterprise-readiness mode
- enterprise SLO baseline manifest
- the current inactive enterprise-readiness claim gate

## Fixed activation rule

The bundle validator intentionally requires the referenced enterprise claim gate
to remain `claim_active=false`. The intended order is:

1. collect and validate all evidence
2. review the bundle
3. update product wording and claim gates in the same reviewed change set

This prevents evidence collection from silently activating stronger wording.

The bundle validator also validates the referenced release security manifest in
enterprise-readiness mode. That means `publication`, `managed_provider`, and
`performance`, and `kms` evidence groups must be non-empty and contain at least
one required item, without imposing that stricter rule on ordinary
non-enterprise release manifests. The stricter enterprise mode also requires the
publication group to contain a required local `sdk-release-publication-bundle`
that validates with
`validate_sdk_release_publication_bundle.py --require-enterprise-ready`.

The publication rollout report, managed-provider evidence, enterprise SLO
baseline, and every KMS/HSM classification listed in the bundle must also appear
as required local evidence items in the referenced release manifest. This
prevents an enterprise-readiness bundle from validating against one set of
artifacts while the release archive points at another.
The SDK release-publication bundle is enforced through the referenced release
manifest rather than as a top-level bundle field, because it is release-custody
evidence for the SDK/package publication flow.
KMS/HSM classification paths must also resolve to unique files; listing the same
classification through different path spellings is rejected.

The referenced release manifest is also checked for archive integrity in
enterprise-readiness mode: every required evidence item must include `sha256`,
local evidence files must hash to the recorded value, and local required
evidence paths must remain inside the release archive root. Required external
evidence must be marked `kind: "external"` and must not use `http://`.
Evidence item `id` values must be unique within each evidence group.
The referenced KMS/HSM and SLO manifests also validate their nested evidence
URIs with the same downgrade-resistant posture: local paths must stay inside the
manifest evidence directory and external evidence must not use `http://`.

The bundle validator also requires server-release evidence generated from the
same source revision. The bundle, release-security manifest, KMS/HSM
classification manifests, and enterprise SLO baseline manifest must share the
same `source_revision`. Managed-provider evidence is intentionally excluded from
this equality check because it is produced by the sibling SDK repository and has
its own GitHub source metadata.

The bundle `release_id` must match the referenced release-security manifest
`release_id`; do not infer release identity from the human-readable `bundle_id`.

The referenced publication rollout report, managed-provider evidence,
release-security manifest, KMS/HSM classification manifests, and enterprise SLO
baseline must not have `generated_at` timestamps after the bundle
`generated_at`. If new evidence is generated, regenerate the bundle instead of
reusing an older bundle wrapper.

Use `--require-approved` only for final activation review. In that mode, the
bundle, release-security manifest, enterprise SLO baseline, and every KMS/HSM
classification manifest must have `review.decision=approved` and a non-empty
reviewer. Normal collection mode intentionally permits pending reviews so
operators can assemble and validate the archive incrementally.

## Minimal bundle shape

```json
{
  "$schema": "https://aegaeon.dev/spec/enterprise-readiness-evidence-bundle.schema.json",
  "schema_version": 1,
  "bundle_id": "v0.0.0-rc.0-enterprise-readiness",
  "release_id": "v0.0.0-rc.0",
  "generated_at": "2026-05-19T00:00:00Z",
  "source_revision": "<git-sha>",
  "claim_target": "enterprise-readiness",
  "claim_gate_path": "../../spec/enterprise-readiness-claim.current.json",
  "evidence": {
    "publication_org_rollout_report": "publication/publication-org-rollout-report.json",
    "managed_provider_evidence": "managed-provider/managed-provider-evidence.json",
    "kms_hsm_classifications": [
      "kms/production-us-east-1-classification.json"
    ],
    "release_security_evidence_manifest": "manifest.json",
    "enterprise_slo_baseline_manifest": "perf/enterprise-slo-baseline.json"
  },
  "review": {
    "reviewer": null,
    "decision": "pending"
  }
}
```

Paths are resolved relative to the bundle file.

## Related documents

- `docs/releases/evidence/publication-org-rollout.md`
- `docs/releases/evidence/managed-provider-evidence.md`
- `docs/releases/runbooks/phase1-evidence-acquisition.md`
- `docs/operations/kms-hsm-deployment-classification.md`
- `docs/releases/evidence/release-security-evidence.md`
- `docs/performance/enterprise-slo-baselines.md`
- `spec/enterprise-readiness-claim.current.json`
