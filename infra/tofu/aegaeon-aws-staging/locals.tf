data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_region" "current" {}

data "aws_vpc" "selected" {
  count = var.vpc_id == null ? 0 : 1

  id = var.vpc_id
}

locals {
  enterprise_readiness = var.deployment_profile == "enterprise"
  service_desired_count = (
    var.deployment_phase == "serve" ? var.desired_count : 0
  )
  certificate_arn_input = var.certificate_arn == null ? "" : trimspace(var.certificate_arn)
  domain_name           = var.domain_name == null ? "" : trimspace(var.domain_name)
  hosted_zone_id_input  = var.hosted_zone_id == null ? "" : trimspace(var.hosted_zone_id)
  hosted_zone_name      = var.hosted_zone_name == null ? "" : trimspace(var.hosted_zone_name)
  hosted_zone_id = (
    local.hosted_zone_id_input != ""
    ? local.hosted_zone_id_input
    : try(data.aws_route53_zone.selected_public[0].zone_id, "")
  )
  managed_certificate_enabled = (
    var.manage_certificate
    && local.certificate_arn_input == ""
    && local.domain_name != ""
    && local.hosted_zone_id != ""
  )
  certificate_arn = (
    local.certificate_arn_input != ""
    ? local.certificate_arn_input
    : (
      local.managed_certificate_enabled
      ? aws_acm_certificate_validation.public[0].certificate_arn
      : ""
    )
  )
  https_enabled         = local.certificate_arn_input != "" || local.managed_certificate_enabled
  route53_alias_enabled = local.domain_name != "" && local.hosted_zone_id != ""
  azs = slice(
    data.aws_availability_zones.available.names,
    0,
    var.availability_zone_count,
  )
  vpc_id             = coalesce(var.vpc_id, try(aws_vpc.main[0].id, ""))
  selected_vpc_cidr  = coalesce(var.trusted_proxy_cidr, try(data.aws_vpc.selected[0].cidr_block, var.vpc_cidr))
  public_subnet_ids  = length(var.public_subnet_ids) > 0 ? var.public_subnet_ids : [for subnet in values(aws_subnet.public) : subnet.id]
  private_subnet_ids = length(var.private_subnet_ids) > 0 ? var.private_subnet_ids : [for subnet in values(aws_subnet.private) : subnet.id]
  managed_server_image = (
    var.create_ecr_repositories
    ? "${aws_ecr_repository.image["server"].repository_url}:${var.image_tag}"
    : ""
  )
  managed_migration_image = (
    var.create_ecr_repositories
    ? "${aws_ecr_repository.image["migrate"].repository_url}:${var.image_tag}"
    : ""
  )
  server_image    = coalesce(var.server_image, local.managed_server_image)
  migration_image = coalesce(var.migration_image, local.managed_migration_image)
  base_url = coalesce(
    var.base_url,
    local.domain_name != "" ? "https://${local.domain_name}" : null,
    "https://${aws_lb.main.dns_name}",
  )
  runtime_issuer_host = regex("^https://([^/?#]+)$", local.base_url)[0]

  redis_host = aws_elasticache_replication_group.main.primary_endpoint_address
  redis_url  = "rediss://:${random_password.redis_auth_token.result}@${local.redis_host}:6379"
  database_url = join("", [
    "postgres://aegaeon:",
    random_password.db_password.result,
    "@",
    aws_db_instance.main.address,
    ":5432/aegaeon?sslmode=require",
  ])

  redis_secret_env_names = toset([
    "AEGAEON_AUTH_CODE_REDIS_URL",
    "AEGAEON_AUTH_SESSION_REDIS_URL",
    "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
    "AEGAEON_CSRF_REDIS_URL",
    "AEGAEON_DEVICE_CODE_REDIS_URL",
    "AEGAEON_DEVICE_CSRF_REDIS_URL",
    "AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL",
    "AEGAEON_DPOP_NONCE_REDIS_URL",
    "AEGAEON_DPOP_REDIS_URL",
    "AEGAEON_FEDERATION_LIST_RATE_LIMIT_REDIS_URL",
    "AEGAEON_JWKS_REDIS_URL",
    "AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL",
    "AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL",
    "AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL",
    "AEGAEON_MANAGEMENT_SESSION_REDIS_URL",
    "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
    "AEGAEON_PAR_REDIS_URL",
    "AEGAEON_RATE_LIMIT_REDIS_URL",
    "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
    "AEGAEON_STEPUP_REDIS_URL",
    "AEGAEON_TOKEN_STORE_REDIS_URL",
    "AEGAEON_UPSTREAM_AUTH_REDIS_URL",
    "AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL",
  ])

  container_environment = [
    { name = "AWS_REGION", value = data.aws_region.current.region },
    { name = "AEGAEON_RUNTIME_ISSUER_HOST", value = local.runtime_issuer_host },
    { name = "AEGAEON_EXPOSE_METRICS_ON_MAIN", value = "1" },
    { name = "AEGAEON_POLICY_REQUIRE_TRUSTED_PROXY", value = "1" },
    { name = "AEGAEON_REQUIRE_TLS_PROXY", value = local.https_enabled ? "1" : "0" },
    { name = "AEGAEON_TRUSTED_PROXIES", value = local.selected_vpc_cidr },
    { name = "RUST_LOG", value = "info,aegaeon_server=info" },
  ]

  secret_environment = concat(
    [
      { name = "AEGAEON_DATABASE_URL", valueFrom = aws_secretsmanager_secret.database_url.arn },
      {
        name      = "AEGAEON_KEY_ENCRYPTION_KEY"
        valueFrom = aws_secretsmanager_secret.key_encryption_key.arn
      },
      {
        name      = "AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN"
        valueFrom = aws_secretsmanager_secret.bootstrap_token.arn
      },
    ],
    [for name in local.redis_secret_env_names : {
      name      = name
      valueFrom = aws_secretsmanager_secret.redis_url.arn
    }],
  )

  oidc_kms_key_id = (
    var.create_oidc_kms_key
    ? aws_kms_key.oidc_signing[0].arn
    : coalesce(var.oidc_kms_key_id, "")
  )
  oidc_kms_key_policy_arn = (
    var.create_oidc_kms_key
    ? aws_kms_key.oidc_signing[0].arn
    : coalesce(var.oidc_kms_key_policy_arn, var.oidc_kms_key_id, "")
  )
  oidc_kms_kid = "${var.name_prefix}-oidc-rs256"

  tags = merge(
    {
      Project   = "aegaeon"
      Component = "hosted-staging"
      ManagedBy = "opentofu"
    },
    var.tags,
  )
}
