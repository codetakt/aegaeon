output "aws_account_id" {
  description = "AWS account ID where the parity KMS key was provisioned."
  value       = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  description = "AWS region selected by the provider environment."
  value       = data.aws_region.current.name
}

output "kms_key_arn" {
  description = "ARN of the OIDC signing KMS key."
  value       = aws_kms_key.oidc_signing.arn
}

output "kms_key_id" {
  description = "KMS key ID to pass as AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID."
  value       = aws_kms_key.oidc_signing.key_id
}

output "kms_alias_name" {
  description = "KMS alias name."
  value       = aws_kms_alias.oidc_signing.name
}

output "oidc_signing_kid" {
  description = "OIDC signing kid to pass as AEGAEON_OIDC_SIGNING_KID."
  value       = local.oidc_signing_kid
}

output "runner_policy_arn" {
  description = "Optional IAM policy ARN granting minimal parity-runner permissions."
  value       = var.create_runner_policy ? aws_iam_policy.runner[0].arn : null
}

output "oidc_signing_env" {
  description = "Non-secret environment values for the parity runner."
  value = {
    AEGAEON_OIDC_SIGNING_BACKEND        = "aws-kms"
    AEGAEON_OIDC_SIGNING_AWS_REGION     = data.aws_region.current.name
    AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID = aws_kms_key.oidc_signing.key_id
    AEGAEON_OIDC_SIGNING_KID            = local.oidc_signing_kid
    AWS_REGION                          = data.aws_region.current.name
  }
}
