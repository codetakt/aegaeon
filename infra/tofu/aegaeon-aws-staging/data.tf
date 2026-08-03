data "aws_iam_policy_document" "ecs_task_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

data "aws_route53_zone" "selected_public" {
  count = var.hosted_zone_id == null && var.hosted_zone_name != null ? 1 : 0

  name         = trimspace(var.hosted_zone_name)
  private_zone = false
}
