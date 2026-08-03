data "aws_iam_policy_document" "kms_key_policy" {
  statement {
    sid = "EnableAccountIamPermissions"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = length(var.key_usage_principal_arns) == 0 ? [] : [1]

    content {
      sid = "AllowConfiguredParityRunnerUse"

      principals {
        type        = "AWS"
        identifiers = var.key_usage_principal_arns
      }

      actions = [
        "kms:DescribeKey",
        "kms:GetPublicKey",
        "kms:Sign",
      ]
      resources = ["*"]
    }
  }
}

resource "aws_kms_key" "oidc_signing" {
  description              = "Aegaeon OIDC RS256 AWS KMS parity signing key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_2048"
  deletion_window_in_days  = var.deletion_window_in_days
  multi_region             = var.multi_region
  policy                   = data.aws_iam_policy_document.kms_key_policy.json
}

resource "aws_kms_alias" "oidc_signing" {
  name          = "alias/${local.kms_alias_name}"
  target_key_id = aws_kms_key.oidc_signing.key_id
}
