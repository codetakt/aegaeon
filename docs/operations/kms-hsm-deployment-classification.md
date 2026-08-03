# KMS/HSM Deployment Classification

Last updated: 2026-06-25

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Scope

This document defines the machine-readable evidence required to classify a
concrete KMS/HSM-backed OIDC signing deployment as either `claim-preserving` or
`compat-only`.

It supports the `kms-hsm-classification` enterprise-readiness gate in
`spec/enterprise-readiness-claim.current.json`. It does not activate the
enterprise-readiness claim by itself.

## Implementation boundary

Classification is per concrete OIDC ID Token `RS256` signing deployment. A
valid `claim-preserving` manifest does not claim broad KMS/HSM coverage across
all runtime-key usages.

Current server support is:

- OIDC ID Token signing: `databaseEncrypted` and feature-gated `awsKms` for the
  deployment shape described by the manifest.
- Hosted bootstrap: may create an `OIDC_ID_TOKEN_SIGNING` `awsKms` runtime key
  when built with `kms-aws`.
- Management runtime-key API: accepts operator-created runtime keys only with
  provider `databaseEncrypted`.
- JWT access-token signing, JWT introspection signing, OpenID Federation
  signing, and OIDC request-object decryption: `databaseEncrypted` runtime-key surfaces.

Do not use this classification to imply a generic KMS/HSM provider framework,
management API support for arbitrary KMS keys, or claim-preserving status for
non-OIDC-signing runtime-key usages.

## Fixed rule

If a deployment does not have a valid classification manifest, treat it as
`compat-only`.

Use:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_kms_hsm_classification.py <manifest.json>'
```

The manifest schema is:

- `spec/kms-hsm-deployment-classification.schema.json`

## Claim-preserving requirements

The validator accepts `claim-preserving` only when all of the following are
true:

- `algorithm.jose_alg` is `RS256`
- `algorithm.provider_algorithm` is exact `RSASSA_PKCS1_V1_5_SHA_256`
- Aegaeon constructs the JWS signing input locally
- the provider returns only a raw signature, not a finished JWT
- the public JWK is derived via a provider API or checked import path
- key-match checking is explicit
- JWKS overlap and rollback match the local-key path
- `kid` reuse is prevented
- parity evidence is `pass` and linkable
- parity evidence uses a local relative path inside the classification
  directory or an immutable `https://`, `s3://`, or `gs://` URI; `http://`,
  absolute paths, and `../` escapes are rejected
- the external signer is recorded as a TCB boundary
- the `RS256 Required Slice` is unchanged
- broad RSA is not promoted
- a reviewer has approved the classification

Anything less is `compat-only`.

If any classification manifest uses `review.decision="approved"`, the validator
requires a non-empty reviewer regardless of whether the classification is
`claim-preserving` or `compat-only`.

## Evidence layout

Store classification manifests beside the relevant deployment or release
evidence, for example:

```text
artifacts/oidc-kms/classification/production-us-east-1.json
```

If the manifest is part of a release evidence archive, link it from
`artifacts/releases/<release-id>/manifest.json` under the `kms` evidence group.

Source-managed baseline examples live under:

- `docs/releases/evidence/kms-hsm-classifications/aws-kms-localstack-rs256-claim-preserving.json`
- `docs/releases/evidence/kms-hsm-classifications/external-finished-jwt-gateway-compat-only.json`

The LocalStack-backed manifest is an internal parity classification for that
bounded integration shape only. It is not hosted production evidence and does
not activate public enterprise-readiness wording.

For hosted / production-style AWS evidence, use the source-managed OpenTofu
stack and wrapper:

- `infra/tofu/oidc-aws-kms-parity/`
- `scripts/validation/run_oidc_aws_kms_parity_from_tofu.sh`

The wrapper reads the selected AWS account / region from OpenTofu outputs,
runs the focused OIDC AWS KMS parity test against the provisioned key, writes
`classification.json` beside the parity summary, and validates the manifest.
It requires `AEG_KMS_CLASSIFICATION_REVIEWER` because approved
claim-preserving classification is a reviewed evidence boundary.

## Minimal claim-preserving manifest shape

```json
{
  "$schema": "https://aegaeon.dev/spec/kms-hsm-deployment-classification.schema.json",
  "schema_version": 1,
  "deployment_id": "production-us-east-1",
  "generated_at": "2026-05-19T00:00:00Z",
  "source_revision": "<git-sha>",
  "signer_backend": "aws-kms",
  "classification": "claim-preserving",
  "algorithm": {
    "jose_alg": "RS256",
    "provider_algorithm": "RSASSA_PKCS1_V1_5_SHA_256"
  },
  "signing_input_ownership": {
    "aegaeon_constructs_jws_signing_input": true,
    "provider_returns_finished_jwt": false
  },
  "public_jwk_derivation": {
    "method": "provider-api",
    "key_match_checked": true
  },
  "jwks_rotation": {
    "overlap_matches_local_path": true,
    "rollback_matches_local_path": true,
    "kid_reuse_prevented": true
  },
  "parity_evidence": {
    "status": "pass",
    "uri": "summary.json",
    "generated_at": "2026-05-19T00:00:00Z"
  },
  "claim_boundary": {
    "rs256_required_slice_unchanged": true,
    "external_signer_recorded_as_tcb": true,
    "broad_rsa_not_promoted": true
  },
  "compat_reason": null,
  "review": {
    "reviewer": "security-reviewer",
    "decision": "approved"
  }
}
```

## Minimal compat-only manifest shape

```json
{
  "$schema": "https://aegaeon.dev/spec/kms-hsm-deployment-classification.schema.json",
  "schema_version": 1,
  "deployment_id": "gateway-jwt-signer",
  "generated_at": "2026-05-19T00:00:00Z",
  "source_revision": "<git-sha>",
  "signer_backend": "other-external",
  "classification": "compat-only",
  "algorithm": {
    "jose_alg": "RS256",
    "provider_algorithm": "gateway-finished-jwt"
  },
  "signing_input_ownership": {
    "aegaeon_constructs_jws_signing_input": false,
    "provider_returns_finished_jwt": true
  },
  "public_jwk_derivation": {
    "method": "operator-supplied",
    "key_match_checked": false
  },
  "jwks_rotation": {
    "overlap_matches_local_path": false,
    "rollback_matches_local_path": false,
    "kid_reuse_prevented": true
  },
  "parity_evidence": {
    "status": "missing",
    "uri": null,
    "generated_at": null
  },
  "claim_boundary": {
    "rs256_required_slice_unchanged": true,
    "external_signer_recorded_as_tcb": true,
    "broad_rsa_not_promoted": true
  },
  "compat_reason": "Provider returns complete JWTs and does not expose raw RS256 signatures.",
  "review": {
    "reviewer": null,
    "decision": "pending"
  }
}
```

## Related documents

- `docs/operations/oidc-kms-signing.md`
- `docs/design/oidc-kms-signing-design.md`
- `docs/verification/oidc/rs256-required-slice.md`
- `docs/verification/workplans/verification-boundary-roadmap.md`
- `spec/enterprise-readiness-claim.current.json`
