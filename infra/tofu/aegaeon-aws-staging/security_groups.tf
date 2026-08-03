resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb"
  description = "Aegaeon staging ALB ingress"
  vpc_id      = local.vpc_id

  dynamic "ingress" {
    for_each = local.https_enabled ? [443] : []

    content {
      description = "HTTPS"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = var.alb_ingress_cidr_blocks
    }
  }

  ingress {
    description = local.https_enabled ? "HTTP redirect" : "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.alb_ingress_cidr_blocks
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    precondition {
      condition = (
        var.create_vpc
        || (
          var.vpc_id != null
          && length(var.public_subnet_ids) >= 2
          && length(var.private_subnet_ids) >= 2
        )
      )
      error_message = "create_vpc=false requires vpc_id and at least two public and private subnet IDs."
    }
  }
}

resource "aws_security_group" "ecs" {
  name        = "${var.name_prefix}-ecs"
  description = "Aegaeon staging ECS tasks"
  vpc_id      = local.vpc_id

  ingress {
    description     = "ALB to server"
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name        = "${var.name_prefix}-db"
  description = "Aegaeon staging PostgreSQL"
  vpc_id      = local.vpc_id

  ingress {
    description     = "ECS to PostgreSQL"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

}

resource "aws_security_group" "redis" {
  name        = "${var.name_prefix}-redis"
  description = "Aegaeon staging Redis"
  vpc_id      = local.vpc_id

  ingress {
    description     = "ECS to Redis"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

}
