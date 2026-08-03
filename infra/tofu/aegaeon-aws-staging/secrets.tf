resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "random_password" "redis_auth_token" {
  length  = 32
  special = false
}

resource "random_password" "bootstrap_token" {
  length  = 48
  special = false
}

resource "random_password" "bootstrap_owner_password" {
  length  = 32
  special = false
}

resource "random_id" "key_encryption_key" {
  byte_length = 32
}

resource "aws_secretsmanager_secret" "database_url" {
  name                    = "${var.name_prefix}/database-url"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id     = aws_secretsmanager_secret.database_url.id
  secret_string = local.database_url
}

resource "aws_secretsmanager_secret" "redis_url" {
  name                    = "${var.name_prefix}/redis-url"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "redis_url" {
  secret_id     = aws_secretsmanager_secret.redis_url.id
  secret_string = local.redis_url
}

resource "aws_secretsmanager_secret" "key_encryption_key" {
  name                    = "${var.name_prefix}/key-encryption-key"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "key_encryption_key" {
  secret_id     = aws_secretsmanager_secret.key_encryption_key.id
  secret_string = random_id.key_encryption_key.b64_url
}

resource "aws_secretsmanager_secret" "bootstrap_token" {
  name                    = "${var.name_prefix}/management-bootstrap-token"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "bootstrap_token" {
  secret_id     = aws_secretsmanager_secret.bootstrap_token.id
  secret_string = random_password.bootstrap_token.result
}

resource "aws_secretsmanager_secret" "bootstrap_owner_password" {
  name                    = "${var.name_prefix}/hosted-bootstrap-owner-password"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "bootstrap_owner_password" {
  secret_id     = aws_secretsmanager_secret.bootstrap_owner_password.id
  secret_string = random_password.bootstrap_owner_password.result
}
