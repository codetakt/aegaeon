resource "aws_elasticache_subnet_group" "main" {
  name       = var.name_prefix
  subnet_ids = local.private_subnet_ids
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id = var.name_prefix
  description          = "Aegaeon staging shared runtime state"

  engine         = "redis"
  engine_version = var.redis_engine_version
  node_type      = var.redis_node_type
  port           = 6379

  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_auth_token.result

  apply_immediately = true
}
