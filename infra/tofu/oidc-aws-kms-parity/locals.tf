data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  kms_alias_name     = coalesce(var.kms_alias_name, var.name_prefix)
  runner_policy_name = coalesce(var.runner_policy_name, var.name_prefix)
  oidc_signing_kid   = coalesce(var.oidc_signing_kid, "aws-kms-${substr(aws_kms_key.oidc_signing.key_id, 0, 12)}")

  tags = merge(
    {
      Project     = "aegaeon"
      Component   = "oidc-kms-parity"
      ManagedBy   = "opentofu"
      EvidenceUse = "oidc-rs256-parity"
    },
    var.tags,
  )
}
