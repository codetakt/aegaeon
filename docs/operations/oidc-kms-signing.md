# OIDC KMS/HSM Signing Operations

Last updated: 2026-06-30

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Scope

This runbook covers the operator workflow for OIDC `RS256` signing when a
runtime key uses provider `awsKms` or a future HSM-backed path.

Use this together with:

- `docs/design/oidc-kms-signing-design.md`
- `docs/operations/kms-hsm-deployment-classification.md`
- `docs/verification/claims/crypto-allowlist.md`
- `docs/verification/workplans/verification-boundary-roadmap.md`
- `docs/operations/management-platform-regulated-environment.md`

This runbook does **not** widen the current claim boundary by itself.

## Implementation boundary

The current implemented KMS/HSM surface is intentionally narrow:

- OIDC ID Token `RS256` signing supports the local signer and the feature-gated
  AWS KMS signer.
- Hosted bootstrap and the management runtime-key API may insert an
  `OIDC_ID_TOKEN_SIGNING` runtime key with provider `awsKms` when the server is
  built with `kms-aws`.
- Management-created `awsKms` runtime keys are intentionally narrow: usage must
  be `OIDC_ID_TOKEN_SIGNING`, algorithm must be `RS256`, `privateKeyPem` must be
  omitted, the AWS KMS key must be usable for `RSASSA_PKCS1_V1_5_SHA_256`, the
  public JWK is derived before persistence, the KMS key identifier is stored as
  an encrypted key handle, and provider configuration stores only the public
  `region`.
- Managed JWT access-token signing, JWT introspection signing, OpenID
  Federation signing, and OIDC request-object decryption remain `databaseEncrypted`
  runtime-key surfaces in the current implementation.

Consequently, AWS KMS/HSM parity evidence and claim-preserving classification
apply only to the concrete OIDC ID Token `RS256` signing deployment recorded in
the classification manifest. They do not imply broad KMS/HSM support for every
runtime-key usage or provider-management surface.

## Fixed posture rules

- treat the external KMS/HSM as an operator-controlled dependency / TCB edge
- keep the active signer and published JWKS derived from the same key material
- never reuse a `kid` across different key material
- classify every concrete KMS/HSM-backed deployment as either:
  - claim-preserving, or
  - compat-only
- if that classification is not explicit, treat the deployment as compat-only

## Supported backend inputs

Production `aegaeon-server` runtime selects OIDC signing material from
`aegaeon.runtime_keys` and fails closed if startup `AEGAEON_OIDC_SIGNING_*`
variables are present. The environment variables below are only inputs for the
focused signer/parity harness and explicit bootstrap/evidence workflows; they
are not runtime policy authority for the server process.

The current backend-side OIDC signer harness supports:

- `AEGAEON_OIDC_SIGNING_BACKEND=local|aws-kms`
- `AEGAEON_OIDC_SIGNING_AWS_REGION` or `AWS_REGION`
- `AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID`
- `AEGAEON_OIDC_SIGNING_KID`
- optional overlap publication via `AEGAEON_OIDC_JWKS_ADDITIONAL(_FILE)`

The AWS KMS-backed path is intended only for asymmetric RSA signing keys that
support `RSASSA_PKCS1_V1_5_SHA_256`.

## AWS parity infrastructure

The repository provides a generic OpenTofu stack for creating an AWS KMS key
that can be used by any AWS account / region selected through the standard AWS
environment:

- `infra/tofu/oidc-aws-kms-parity/`

The stack provisions:

- an asymmetric AWS KMS `RSA_2048` signing key with `SIGN_VERIFY` usage
- a KMS alias
- an optional minimal IAM policy for a parity runner

Credentials and account selection are intentionally outside the stack and come
from the AWS provider / SDK chain (`AWS_PROFILE`, `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, SSO, etc.). Region comes from
`AWS_REGION` / `AWS_DEFAULT_REGION` unless otherwise configured by the operator.

Quick start:

```bash
export AWS_PROFILE=<profile>
export AWS_REGION=us-east-1

tofu -chdir=infra/tofu/oidc-aws-kms-parity init
tofu -chdir=infra/tofu/oidc-aws-kms-parity apply
```

Then collect hosted / production-style parity evidence and validate the
classification manifest:

```bash
export AEG_KMS_CLASSIFICATION_REVIEWER=<reviewer-id>
nix develop .#ci --command bash \
  scripts/validation/run_oidc_aws_kms_parity_from_tofu.sh
```

The wrapper reads Tofu outputs, exports `AEGAEON_OIDC_SIGNING_BACKEND=aws-kms`,
`AEGAEON_OIDC_SIGNING_AWS_REGION`,
`AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID`, and
`AEGAEON_OIDC_SIGNING_KID`, runs the focused OIDC AWS KMS parity test, writes a
classification manifest, and validates it with
`scripts/validation/validate_kms_hsm_classification.py`.

`AEG_KMS_CLASSIFICATION_REVIEWER` is required because claim-preserving
classification is a reviewed evidence boundary. Do not use a placeholder value
for release archives.

## Claim-preserving vs compat-only classification

Classify a deployment as claim-preserving only when all of the following hold:

1. the provider signs the locally-constructed JWS input with exact `RS256`
2. the public JWK is derived from the active signer through an authoritative
   provider API or an equivalently checked import path
3. JWKS overlap / rollback procedures match the local-key path
4. the focused KMS parity lane is green for the same integration shape

Treat the deployment as compat-only when any of the following is true:

- the provider exposes only `PS*` or another non-`RS256` algorithm
- the provider or gateway returns finished JWTs instead of raw signatures over
  the local signing input
- the public JWK is injected without a key-match check
- the parity lane is stale, missing, or failing

## Preflight checks

Before enabling a hosted-bootstrap `awsKms` OIDC signing runtime key in a real environment:

1. confirm the target KMS key is an asymmetric RSA sign/verify key
2. confirm the allowed signing algorithm includes `RSASSA_PKCS1_V1_5_SHA_256`
3. confirm the configured `kid` is unique for the target key material
4. confirm JWKS overlap keys are loaded if a rotation window is active
5. confirm the most recent KMS parity artifact is present and green
6. confirm the deployment has an explicit claim-preserving or compat-only label

## CI and release evidence

The backend repository carries two AWS KMS parity lanes for the OIDC signer.

### LocalStack parity lane

- script: `scripts/validation/run_oidc_kms_parity.sh`
- hosted lane: `.github/workflows/oidc-kms-parity.yml`

The LocalStack lane:

- requires LocalStack-backed KMS on `localhost:4566`
- forces `AEG_KMS_REQUIRE_LOCALSTACK=1`
- runs `cargo test -p aegaeon-server --features kms-aws --lib test_oidc_aws_kms_runtime_key_material_issues_verifiable_rs256_jwt -- --nocapture`
- emits artifacts under `artifacts/oidc-kms/`
- runs on pull requests to `main`, pushes to `main`, and release-tag pushes (`v*`)

### Real AWS parity lane

- wrapper: `scripts/validation/run_oidc_aws_kms_parity_from_tofu.sh`
- infrastructure: `infra/tofu/oidc-aws-kms-parity/`
- mode: `AEG_OIDC_KMS_MODE=aws`
- focused test:

  ```bash
  cargo test -p aegaeon-server --features kms-aws \
    --lib \
    test_oidc_aws_kms_runtime_key_material_issues_verifiable_rs256_jwt \
    -- --nocapture
  ```

- default artifacts:
  `artifacts/oidc-kms/aws-production/`

The real AWS lane refuses `AWS_ENDPOINT_URL` unless
`AEG_OIDC_KMS_ALLOW_ENDPOINT_URL=1` is set, so hosted / production evidence does
not accidentally point back to LocalStack.

Expected artifacts:

- `artifacts/oidc-kms/metadata.txt`
- `artifacts/oidc-kms/localstack-health.json`
- `artifacts/oidc-kms/test.log`
- `artifacts/oidc-kms/summary.json`
- `artifacts/oidc-kms/aws-production/classification.json` for the Tofu-backed
  real AWS lane

If the lane is absent or stale for the integration being released, do not use
claim-preserving wording.

Every concrete deployment must also have a classification manifest validated by
`scripts/validation/validate_kms_hsm_classification.py`; without that manifest,
the deployment remains compat-only for claim wording.

## Local reproduction

Run the parity lane locally from the repo root:

```bash
nix develop .#ci --command bash scripts/validation/run_oidc_kms_parity.sh
```

If you need to point at a different LocalStack health endpoint or artifact
directory:

```bash
AEG_OIDC_KMS_LOCALSTACK_HEALTH_URL=http://127.0.0.1:4566/_localstack/health \
AEG_OIDC_KMS_ARTIFACT_DIR=artifacts/oidc-kms-manual \
nix develop .#ci --command bash scripts/validation/run_oidc_kms_parity.sh
```

## Rotation and rollback

For KMS/HSM-backed OIDC signing, keep the same external behaviour as the local
RSA path.

### Rotation

1. provision the new signer in the provider
2. assign a fresh `kid`
3. derive and publish the new active JWK from the same provider-backed key
4. keep the previous public JWK in the overlap set until the maximum ID Token
   lifetime has elapsed
5. run the KMS parity lane against the new configuration shape before promoting
   claim-preserving wording

### Rollback

1. revert the active backend signer configuration to the previous key
2. keep JWKS overlap coherent so already-issued tokens remain verifiable
3. preserve the failed parity artifact and incident notes
4. downgrade release wording to compat-only if claim-preserving parity is no
   longer established

## Incident handling

Treat the following as fail-closed conditions:

- KMS signer initialization failure
- inability to derive the active public JWK
- mismatch between active signer and published JWKS
- ambiguous algorithm classification
- missing or failing KMS parity evidence

Operator response:

1. stop claiming claim-preserving posture for the affected deployment
2. restore the local signer or a previously validated KMS-backed signer
3. regenerate parity evidence before re-enabling claim-preserving wording
4. retain the failing artifacts with the release / incident record

## Related documents

- `docs/design/oidc-kms-signing-design.md`
- `docs/operations/kms-hsm-deployment-classification.md`
- `docs/operations/jwks-operations.md`
- `docs/operations/management-platform-regulated-environment.md`
- `docs/development/current-delivery-context.md`
