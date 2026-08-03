# OIDC AWS KMS Parity Environment

This OpenTofu stack provisions the minimal AWS resources required to collect
hosted / production-style OIDC `RS256` AWS KMS parity evidence for Aegaeon.

The stack is intentionally account- and region-neutral:

- AWS credentials come from the standard AWS provider / SDK environment
  (`AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_SESSION_TOKEN`, SSO, etc.).
- Region comes from `AWS_REGION` / `AWS_DEFAULT_REGION` or provider config.
- No secret is written into OpenTofu variables.

## Resources

- one asymmetric AWS KMS signing key:
  - `key_usage = SIGN_VERIFY`
  - `customer_master_key_spec = RSA_2048`
- one KMS alias
- optionally, one IAM policy granting the parity runner:
  - `kms:DescribeKey`
  - `kms:GetPublicKey`
  - `kms:Sign`

## Quick Start

```bash
export AWS_PROFILE=<profile>
export AWS_REGION=us-east-1

tofu -chdir=infra/tofu/oidc-aws-kms-parity init
tofu -chdir=infra/tofu/oidc-aws-kms-parity apply
```

Then collect parity evidence and validate the generated classification manifest:

```bash
export AEG_KMS_CLASSIFICATION_REVIEWER=<reviewer-id>
nix develop .#ci --command bash \
  scripts/validation/run_oidc_aws_kms_parity_from_tofu.sh
```

The wrapper reads the OpenTofu outputs, exports the required
`AEGAEON_OIDC_SIGNING_*` variables, runs the focused AWS KMS OIDC parity test,
generates `classification.json`, and validates it with
`scripts/validation/validate_kms_hsm_classification.py`.

Artifacts default to:

```text
artifacts/oidc-kms/aws-production/
```

Override with:

```bash
AEG_OIDC_KMS_ARTIFACT_DIR=artifacts/oidc-kms/aws-us-east-1 \
nix develop .#ci --command bash \
  scripts/validation/run_oidc_aws_kms_parity_from_tofu.sh
```

## Existing IAM Principals

The key policy enables account-level IAM permissions through the account root
principal. The caller still needs IAM permission to create and use the resources.

If the parity runner uses a separate IAM principal, either attach the emitted
`runner_policy_arn` to that principal outside this module or pass direct key
policy principals:

```bash
tofu -chdir=infra/tofu/oidc-aws-kms-parity apply \
  -var 'key_usage_principal_arns=["arn:aws:iam::<account-id>:role/<runner-role>"]'
```

## Outputs

Useful outputs:

```bash
tofu -chdir=infra/tofu/oidc-aws-kms-parity output -raw aws_region
tofu -chdir=infra/tofu/oidc-aws-kms-parity output -raw kms_key_id
tofu -chdir=infra/tofu/oidc-aws-kms-parity output -raw oidc_signing_kid
tofu -chdir=infra/tofu/oidc-aws-kms-parity output -json oidc_signing_env
```

Manual parity environment:

```bash
TOFU_DIR=infra/tofu/oidc-aws-kms-parity

export AEGAEON_OIDC_SIGNING_BACKEND=aws-kms
export AEGAEON_OIDC_SIGNING_AWS_REGION="$(
  tofu -chdir="${TOFU_DIR}" output -raw aws_region
)"
export AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID="$(
  tofu -chdir="${TOFU_DIR}" output -raw kms_key_id
)"
export AEGAEON_OIDC_SIGNING_KID="$(
  tofu -chdir="${TOFU_DIR}" output -raw oidc_signing_kid
)"
```

## Classification Boundary

The wrapper emits a `claim-preserving` classification only after the focused
parity test passes and `AEG_KMS_CLASSIFICATION_REVIEWER` is set. The reviewer
value is an evidence-control field; use a real review identity for release
archives.

This stack proves only the AWS KMS OIDC `RS256` path for the selected
account/region/key. It does not imply a provider-neutral KMS/HSM claim.

## Destroy

```bash
tofu -chdir=infra/tofu/oidc-aws-kms-parity destroy
```

AWS KMS keys enter scheduled deletion according to `deletion_window_in_days`
(default: 7).
