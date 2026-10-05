data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect = "Allow"
    actions = [
      "sts:AssumeRole",
    ]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "perf_instance" {
  for_each           = toset(["server", "loadgen"])
  name               = "${var.name_prefix}-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  for_each   = aws_iam_role.perf_instance
  role       = each.value.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

locals {
  enable_ghcr_auth = (
    var.ghcr_auth_enabled
    && var.ghcr_username != null
    && length(trimspace(var.ghcr_username)) > 0
    && (var.ghcr_token_ssm_parameter_name != null || var.ghcr_token_secretsmanager_secret_id != null)
  )

  ghcr_token_ssm_parameter_arn = (
    var.ghcr_token_ssm_parameter_name != null
    ? "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:parameter/${trim(var.ghcr_token_ssm_parameter_name, "/")}"
    : null
  )

  ghcr_token_secretsmanager_arn = (
    var.ghcr_token_secretsmanager_secret_id != null
    ? (
      startswith(var.ghcr_token_secretsmanager_secret_id, "arn:")
      ? var.ghcr_token_secretsmanager_secret_id
      : "arn:aws:secretsmanager:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:secret:${var.ghcr_token_secretsmanager_secret_id}*"
    )
    : null
  )

  kms_ssm_alias_arn = "arn:aws:kms:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:alias/aws/ssm"

  kms_secretsmanager_alias_arn = "arn:aws:kms:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:alias/aws/secretsmanager"
}

data "aws_iam_policy_document" "ghcr_token_read" {
  count = local.enable_ghcr_auth ? 1 : 0

  dynamic "statement" {
    for_each = var.ghcr_token_ssm_parameter_name != null ? [local.ghcr_token_ssm_parameter_arn] : []
    iterator = ssm
    content {
      effect = "Allow"
      actions = [
        "ssm:GetParameter",
      ]
      resources = [ssm.value]
    }
  }

  dynamic "statement" {
    for_each = var.ghcr_token_ssm_parameter_name != null ? [local.kms_ssm_alias_arn] : []
    iterator = kms
    content {
      effect = "Allow"
      actions = [
        "kms:Decrypt",
      ]
      resources = [kms.value]
    }
  }

  dynamic "statement" {
    for_each = var.ghcr_token_secretsmanager_secret_id != null ? [local.ghcr_token_secretsmanager_arn] : []
    iterator = sm
    content {
      effect = "Allow"
      actions = [
        "secretsmanager:GetSecretValue",
      ]
      resources = [sm.value]
    }
  }

  dynamic "statement" {
    for_each = var.ghcr_token_secretsmanager_secret_id != null ? [local.kms_secretsmanager_alias_arn] : []
    iterator = kms
    content {
      effect = "Allow"
      actions = [
        "kms:Decrypt",
      ]
      resources = [kms.value]
    }
  }
}

resource "aws_iam_policy" "ghcr_token_read" {
  count = local.enable_ghcr_auth ? 1 : 0

  name   = "${var.name_prefix}-ghcr-token-read"
  policy = data.aws_iam_policy_document.ghcr_token_read[0].json
}

resource "aws_iam_role_policy_attachment" "ghcr_token_read" {
  for_each   = local.enable_ghcr_auth ? aws_iam_role.perf_instance : {}
  role       = each.value.name
  policy_arn = aws_iam_policy.ghcr_token_read[0].arn
}

data "aws_iam_policy_document" "artifact_write" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetBucketLocation",
    ]
    resources = [
      "arn:aws:s3:::${local.artifact_bucket_name}",
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::${local.artifact_bucket_name}/${var.artifact_prefix}*",
    ]
  }
}

resource "aws_iam_policy" "artifact_write" {
  name   = "${var.name_prefix}-artifact-write"
  policy = data.aws_iam_policy_document.artifact_write.json
}

resource "aws_iam_role_policy_attachment" "artifact_write" {
  role       = aws_iam_role.perf_instance["loadgen"].name
  policy_arn = aws_iam_policy.artifact_write.arn
}

resource "aws_iam_instance_profile" "perf_instance" {
  for_each = aws_iam_role.perf_instance
  name     = "${var.name_prefix}-${each.key}"
  role     = each.value.name
}

data "aws_iam_policy_document" "runtime_supply" {
  for_each = local.node_secret_arns
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = each.value
  }
  dynamic "statement" {
    for_each = length(local.node_secret_kms_key_arns[each.key]) > 0 ? [local.node_secret_kms_key_arns[each.key]] : []
    content {
      actions   = ["kms:Decrypt"]
      resources = statement.value
    }
  }
}

resource "aws_iam_role_policy" "runtime_supply" {
  for_each = aws_iam_role.perf_instance
  name     = "${var.name_prefix}-${each.key}-supplies"
  role     = each.value.id
  policy   = data.aws_iam_policy_document.runtime_supply[each.key].json
}

data "aws_iam_policy_document" "runtime_signing" {
  statement {
    actions   = ["kms:Sign", "kms:GetPublicKey"]
    resources = var.runtime_kms_key_arns
  }
}

resource "aws_iam_role_policy" "runtime_signing" {
  name   = "${var.name_prefix}-runtime-signing"
  role   = aws_iam_role.perf_instance["server"].id
  policy = data.aws_iam_policy_document.runtime_signing.json
}
