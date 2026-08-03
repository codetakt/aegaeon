resource "aws_db_subnet_group" "main" {
  name       = var.name_prefix
  subnet_ids = local.private_subnet_ids
}

resource "aws_db_instance" "main" {
  identifier = var.name_prefix

  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = max(var.db_allocated_storage, 100)
  storage_encrypted     = true
  multi_az              = var.db_multi_az
  enabled_cloudwatch_logs_exports = [
    "postgresql",
    "upgrade",
  ]

  db_name  = "aegaeon"
  username = "aegaeon"
  password = random_password.db_password.result

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false

  backup_retention_period = 7
  deletion_protection     = var.db_deletion_protection
  skip_final_snapshot     = var.db_skip_final_snapshot
  final_snapshot_identifier = (
    var.db_skip_final_snapshot ? null : var.db_final_snapshot_identifier
  )

  apply_immediately = true

  lifecycle {
    precondition {
      condition     = var.db_skip_final_snapshot || var.db_final_snapshot_identifier != null
      error_message = "db_final_snapshot_identifier is required when db_skip_final_snapshot=false."
    }
  }
}
