# KMS/HSM Classification Manifests

Last updated: 2026-07-08

Status: snapshot

Owner: Release Engineering

Audience: release managers, maintainers

> **Status note (2026-07-08):** Point-in-time release evidence; rerun the named validator before using it for a new release decision.

This directory indexes source-managed KMS/HSM deployment classification
manifests used by the enterprise-readiness evidence tooling. The manifest and
nested parity-evidence files live under
`artifacts/release/kms-hsm-classifications/` so `docs/` stays focused on
reader-facing guidance.

## Scope

- KMS/HSM deployment classification manifest pointers
- evidence-boundary notes for claim-preserving signer integrations
- validation command references for release reviewers

## Canonical Documents

- `[reference]` `../../../../artifacts/release/kms-hsm-classifications/aws-kms-localstack-rs256-claim-preserving.json`
  — internal LocalStack-backed AWS KMS RS256 parity shape.
- `[reference]` `../../../../artifacts/release/kms-hsm-classifications/aws-kms-ap-northeast-1-rs256-claim-preserving.json`
  — hosted AWS KMS RS256 parity evidence for account `166820905045`,
  region `ap-northeast-1`.
- `[reference]` `../../../../artifacts/release/kms-hsm-classifications/aws-kms-validation-ap-northeast-1-rs256-claim-preserving.json`
  — validation-account AWS KMS RS256 parity evidence for the `8071664`
  release-candidate validation run.
- `[reference]` `../../../../artifacts/release/kms-hsm-classifications/external-finished-jwt-gateway-compat-only.json`
  — fail-closed classification for providers that return finished JWTs instead
  of raw signatures over Aegaeon-owned JWS signing input.

## Reading Rule of Thumb

1. Treat these entries as curated pointers to release artefacts.
2. Validate manifests before citing them in release evidence.
3. Add production deployment classifications only after reviewer confirmation.

## Validation

Validate the manifests with:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_kms_hsm_classification.py \
    artifacts/release/kms-hsm-classifications/*.json'
```

Fresh production or hosted deployments still need their own reviewed
classification manifest and fresh parity evidence before any stronger claim
wording can be activated.

For AWS, the generic evidence path is:

```bash
tofu -chdir=infra/tofu/oidc-aws-kms-parity init
tofu -chdir=infra/tofu/oidc-aws-kms-parity apply

AEG_KMS_CLASSIFICATION_REVIEWER=<reviewer-id> \
nix develop .#ci --command bash \
  scripts/validation/run_oidc_aws_kms_parity_from_tofu.sh
```

That wrapper writes a deployment-specific manifest under
`artifacts/oidc-kms/aws-production/classification.json`; copy or link that
manifest into the release evidence archive only after the reviewer confirms the
deployment boundary.
