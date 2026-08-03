resource "aws_ecs_cluster" "main" {
  name = var.name_prefix

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "server" {
  family                   = "${var.name_prefix}-server"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name      = "aegaeon-server"
      image     = local.server_image
      essential = true

      command = [
        "--host",
        "0.0.0.0",
        "--port",
        tostring(var.container_port),
      ]

      portMappings = [
        {
          containerPort = var.container_port
          hostPort      = var.container_port
          protocol      = "tcp"
        }
      ]

      environment = local.container_environment
      secrets     = local.secret_environment

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.server.name
          awslogs-region        = data.aws_region.current.region
          awslogs-stream-prefix = "server"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = length(trimspace(local.server_image)) > 0
      error_message = "server_image is required when create_ecr_repositories=false."
    }
  }
}

resource "aws_ecs_task_definition" "migrate" {
  family                   = "${var.name_prefix}-migrate"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name      = "aegaeon-migrate"
      image     = local.migration_image
      essential = true

      environment = []
      secrets = [
        { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.database_url.arn },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.migrate.name
          awslogs-region        = data.aws_region.current.region
          awslogs-stream-prefix = "migrate"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = length(trimspace(local.migration_image)) > 0
      error_message = "migration_image is required when create_ecr_repositories=false."
    }
  }
}

resource "aws_ecs_task_definition" "hosted_bootstrap" {
  family                   = "${var.name_prefix}-hosted-bootstrap"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name       = "aegaeon-hosted-bootstrap"
      image      = local.server_image
      essential  = true
      entryPoint = ["/usr/local/bin/aegaeon-hosted-bootstrap"]

      environment = [
        { name = "AWS_REGION", value = data.aws_region.current.region },
        { name = "AEGAEON_HOSTED_BOOTSTRAP_ISSUER_URL", value = local.base_url },
        { name = "AEGAEON_HOSTED_BOOTSTRAP_OWNER_EMAIL", value = var.bootstrap_owner_email },
        { name = "AEGAEON_HOSTED_BOOTSTRAP_TEAM_SLUG", value = var.bootstrap_team_slug },
        { name = "AEGAEON_HOSTED_BOOTSTRAP_TENANT_SLUG", value = var.bootstrap_tenant_slug },
        { name = "AEGAEON_HOSTED_BOOTSTRAP_TENANT_REGION", value = var.bootstrap_tenant_region },
        { name = "AEGAEON_HOSTED_BOOTSTRAP_ENVIRONMENT_SLUG", value = var.bootstrap_environment_slug },
        { name = "AEGAEON_HOSTED_BOOTSTRAP_KMS_REGION", value = data.aws_region.current.region },
        { name = "AEGAEON_HOSTED_BOOTSTRAP_KMS_KEY_ID", value = local.oidc_kms_key_id },
        { name = "AEGAEON_HOSTED_BOOTSTRAP_KMS_KID", value = local.oidc_kms_kid },
        { name = "RUST_LOG", value = "info,aegaeon_server=info" },
      ]

      secrets = [
        { name = "AEGAEON_DATABASE_URL", valueFrom = aws_secretsmanager_secret.database_url.arn },
        { name = "AEGAEON_KEY_ENCRYPTION_KEY", valueFrom = aws_secretsmanager_secret.key_encryption_key.arn },
        { name = "AEGAEON_HOSTED_BOOTSTRAP_OWNER_PASSWORD", valueFrom = aws_secretsmanager_secret.bootstrap_owner_password.arn },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.bootstrap.name
          awslogs-region        = data.aws_region.current.region
          awslogs-stream-prefix = "bootstrap"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = length(trimspace(local.server_image)) > 0
      error_message = "server_image is required when create_ecr_repositories=false."
    }

    precondition {
      condition     = length(trimspace(local.oidc_kms_key_id)) > 0
      error_message = "oidc_kms_key_id is required when create_oidc_kms_key=false."
    }
  }

  depends_on = [
    aws_db_instance.main,
    aws_iam_role_policy.ecs_task_oidc_kms,
    aws_secretsmanager_secret_version.bootstrap_owner_password,
    aws_secretsmanager_secret_version.database_url,
    aws_secretsmanager_secret_version.key_encryption_key,
  ]
}

resource "aws_ecs_service" "server" {
  name                   = "${var.name_prefix}-server"
  cluster                = aws_ecs_cluster.main.id
  task_definition        = aws_ecs_task_definition.server.arn
  desired_count          = local.service_desired_count
  launch_type            = "FARGATE"
  enable_execute_command = var.enable_execute_command

  network_configuration {
    subnets          = local.private_subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = var.assign_public_ip
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.server.arn
    container_name   = "aegaeon-server"
    container_port   = var.container_port
  }

  lifecycle {
    precondition {
      condition     = !var.create_vpc || var.enable_nat_gateway || var.assign_public_ip
      error_message = "ECS tasks in a created VPC need egress; enable NAT gateway or assign public IPs."
    }

    precondition {
      condition = (
        !local.enterprise_readiness
        || (
          local.https_enabled
          && local.route53_alias_enabled
          && var.create_vpc
          && var.enable_nat_gateway
          && var.nat_gateway_mode == "per_az"
          && !var.assign_public_ip
          && (var.deployment_phase == "bootstrap" || var.desired_count >= 2)
          && var.db_multi_az
          && var.enable_waf
          && var.log_retention_days >= 90
        )
      )
      error_message = "deployment_profile=enterprise requires HTTPS with Route53, a dedicated VPC, private ECS tasks, per-AZ NAT, desired_count>=2 in serve phase, Multi-AZ DB, WAF, and log_retention_days>=90."
    }
  }

  depends_on = [
    aws_db_instance.main,
    aws_elasticache_replication_group.main,
    aws_lb_listener.http,
    aws_lb_listener.https,
    aws_secretsmanager_secret_version.bootstrap_token,
    aws_secretsmanager_secret_version.database_url,
    aws_secretsmanager_secret_version.key_encryption_key,
    aws_secretsmanager_secret_version.redis_url,
  ]
}
