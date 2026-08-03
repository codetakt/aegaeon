data "aws_iam_policy_document" "runner" {
  statement {
    sid = "AegaeonOidcAwsKmsParityUse"

    actions = [
      "kms:DescribeKey",
      "kms:GetPublicKey",
      "kms:Sign",
    ]

    resources = [aws_kms_key.oidc_signing.arn]
  }
}

resource "aws_iam_policy" "runner" {
  count = var.create_runner_policy ? 1 : 0

  name        = local.runner_policy_name
  description = "Minimal permissions for Aegaeon OIDC AWS KMS RS256 parity evidence collection"
  policy      = data.aws_iam_policy_document.runner.json
}
