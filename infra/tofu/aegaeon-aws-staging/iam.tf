resource "aws_iam_role" "ecs_execution" {
  name               = "${var.name_prefix}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ecs_execution_managed" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "ecs_execution_secrets" {
  statement {
    actions = [
      "secretsmanager:GetSecretValue",
    ]

    resources = [
      aws_secretsmanager_secret.bootstrap_token.arn,
      aws_secretsmanager_secret.bootstrap_owner_password.arn,
      aws_secretsmanager_secret.database_url.arn,
      aws_secretsmanager_secret.key_encryption_key.arn,
      aws_secretsmanager_secret.redis_url.arn,
    ]
  }
}

resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name   = "${var.name_prefix}-secrets"
  role   = aws_iam_role.ecs_execution.id
  policy = data.aws_iam_policy_document.ecs_execution_secrets.json
}

resource "aws_iam_role" "ecs_task" {
  name               = "${var.name_prefix}-ecs-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume_role.json
}

data "aws_iam_policy_document" "ecs_task_oidc_kms" {
  statement {
    actions = [
      "kms:GetPublicKey",
      "kms:Sign",
    ]

    resources = [
      local.oidc_kms_key_policy_arn,
    ]
  }
}

resource "aws_iam_role_policy" "ecs_task_oidc_kms" {
  name   = "${var.name_prefix}-oidc-kms"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.ecs_task_oidc_kms.json

  lifecycle {
    precondition {
      condition     = length(trimspace(local.oidc_kms_key_policy_arn)) > 0
      error_message = "oidc_kms_key_policy_arn is required when create_oidc_kms_key=false."
    }
  }
}
