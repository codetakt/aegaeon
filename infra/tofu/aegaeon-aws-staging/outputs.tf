output "base_url" {
  description = "Configured public issuer base URL."
  value       = local.base_url
}

output "server_image" {
  description = "Runtime image reference configured for the ECS server task."
  value       = local.server_image
}

output "migration_image" {
  description = "Migration image reference configured for the ECS migration task."
  value       = local.migration_image
}

output "server_ecr_repository_url" {
  description = "Managed ECR repository URL for aegaeon-server, when created."
  value       = try(aws_ecr_repository.image["server"].repository_url, null)
}

output "migration_ecr_repository_url" {
  description = "Managed ECR repository URL for the Atlas migration image, when created."
  value       = try(aws_ecr_repository.image["migrate"].repository_url, null)
}

output "alb_dns_name" {
  description = "ALB DNS name."
  value       = aws_lb.main.dns_name
}

output "route53_hosted_zone_id" {
  description = "Route53 hosted zone ID used for alias and ACM validation records."
  value       = local.hosted_zone_id != "" ? local.hosted_zone_id : null
}

output "certificate_arn" {
  description = "ACM certificate ARN used for the HTTPS listener."
  value       = local.certificate_arn != "" ? local.certificate_arn : null
}

output "managed_certificate_validation_record_fqdns" {
  description = "DNS validation record FQDNs created for the managed ACM certificate."
  value       = [for record in aws_route53_record.certificate_validation : record.fqdn]
}

output "ecs_cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "ECS service name."
  value       = aws_ecs_service.server.name
}

output "migration_task_definition_arn" {
  description = "Task definition ARN for the one-off Atlas migration task."
  value       = aws_ecs_task_definition.migrate.arn
}

output "hosted_bootstrap_task_definition_arn" {
  description = "Task definition ARN for the one-off hosted management bootstrap task."
  value       = aws_ecs_task_definition.hosted_bootstrap.arn
}

output "private_subnet_ids" {
  description = "Private subnet IDs for ECS one-off tasks."
  value       = local.private_subnet_ids
}

output "ecs_security_group_id" {
  description = "Security group ID for ECS tasks."
  value       = aws_security_group.ecs.id
}

output "database_url_secret_arn" {
  description = "Secrets Manager ARN containing AEGAEON_DATABASE_URL."
  value       = aws_secretsmanager_secret.database_url.arn
}

output "redis_url_secret_arn" {
  description = "Secrets Manager ARN containing the shared Redis URL."
  value       = aws_secretsmanager_secret.redis_url.arn
}

output "bootstrap_token_secret_arn" {
  description = "Secrets Manager ARN containing the management bootstrap token."
  value       = aws_secretsmanager_secret.bootstrap_token.arn
}

output "bootstrap_owner_password_secret_arn" {
  description = "Secrets Manager ARN containing the initial hosted management owner password."
  value       = aws_secretsmanager_secret.bootstrap_owner_password.arn
}

output "oidc_kms_key_id" {
  description = "AWS KMS key ID/ARN used for hosted OIDC RS256 signing."
  value       = local.oidc_kms_key_id
}

output "oidc_kms_kid" {
  description = "KID registered for the hosted OIDC RS256 signing key."
  value       = local.oidc_kms_kid
}

output "https_enabled" {
  description = "Whether the ALB HTTPS listener is enabled."
  value       = local.https_enabled
}

output "enterprise_readiness_profile" {
  description = "Whether deployment_profile=enterprise fail-closed checks are enabled."
  value       = local.enterprise_readiness
}

output "deployment_phase" {
  description = "Hosted deployment phase applied by this stack."
  value       = var.deployment_phase
}

output "ecs_applied_desired_count" {
  description = "Actual desired count applied to the ECS service after deployment_phase handling."
  value       = local.service_desired_count
}
