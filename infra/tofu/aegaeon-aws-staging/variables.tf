variable "name_prefix" {
  type        = string
  description = "Prefix for AWS resource names and tags."
  default     = "aegaeon-staging"

  validation {
    condition     = can(regex("^[A-Za-z0-9-]+$", var.name_prefix))
    error_message = "name_prefix must contain only ASCII letters, digits, or hyphen."
  }
}

variable "create_vpc" {
  type        = bool
  description = "Create a dedicated VPC and subnets. Set false to use existing VPC/subnet IDs."
  default     = true
}

variable "deployment_profile" {
  type        = string
  description = "Deployment posture profile. Use enterprise for claim-quality hosted readiness evidence; smoke is for temporary wiring tests only."
  default     = "smoke"

  validation {
    condition     = contains(["enterprise", "smoke"], var.deployment_profile)
    error_message = "deployment_profile must be enterprise or smoke."
  }
}

variable "deployment_phase" {
  type        = string
  description = "Hosted deployment phase. bootstrap keeps ECS service desired count at zero until migrations and hosted bootstrap have run; serve applies desired_count."
  default     = "bootstrap"

  validation {
    condition     = contains(["bootstrap", "serve"], var.deployment_phase)
    error_message = "deployment_phase must be bootstrap or serve."
  }
}

variable "server_image" {
  type        = string
  description = "Container image reference for aegaeon-server. When unset and create_ecr_repositories=true, the stack derives this from the managed server ECR repository and image_tag."
  default     = null

  validation {
    condition     = var.server_image == null || length(trimspace(var.server_image)) > 0
    error_message = "server_image must be null or a non-empty image reference."
  }
}

variable "migration_image" {
  type        = string
  description = "Atlas migration image reference. When unset and create_ecr_repositories=true, the stack derives this from the managed migration ECR repository and image_tag."
  default     = null

  validation {
    condition     = var.migration_image == null || length(trimspace(var.migration_image)) > 0
    error_message = "migration_image must be null or a non-empty image reference."
  }
}

variable "create_ecr_repositories" {
  type        = bool
  description = "Create ECR repositories for the runtime and migration images."
  default     = true
}

variable "image_tag" {
  type        = string
  description = "Image tag used when deriving image references from the managed ECR repositories."
  default     = "staging"

  validation {
    condition     = length(trimspace(var.image_tag)) > 0
    error_message = "image_tag must not be empty."
  }
}

variable "ecr_image_tag_mutability" {
  type        = string
  description = "ECR tag mutability for managed repositories."
  default     = "IMMUTABLE"

  validation {
    condition     = contains(["IMMUTABLE", "MUTABLE"], var.ecr_image_tag_mutability)
    error_message = "ecr_image_tag_mutability must be IMMUTABLE or MUTABLE."
  }
}

variable "ecr_retain_image_count" {
  type        = number
  description = "Number of recent tagged ECR images to retain in each managed repository."
  default     = 10

  validation {
    condition     = var.ecr_retain_image_count >= 1
    error_message = "ecr_retain_image_count must be at least 1."
  }
}

variable "ecr_force_delete" {
  type        = bool
  description = "Delete managed ECR repositories even if images remain. Keep true for ephemeral evidence stacks."
  default     = true
}

variable "base_url" {
  type        = string
  description = "Public issuer base URL. Use https:// for enterprise/hosted evidence."
  default     = null

  validation {
    condition     = var.base_url == null || can(regex("^https://[^\\s/?#]+$", trimspace(var.base_url)))
    error_message = "base_url must be null or an https URL with only host or host:port."
  }
}

variable "domain_name" {
  type        = string
  description = "Optional DNS name for the ALB alias record."
  default     = null

  validation {
    condition     = var.domain_name == null || length(trimspace(var.domain_name)) > 0
    error_message = "domain_name must be null or non-empty."
  }
}

variable "hosted_zone_id" {
  type        = string
  description = "Optional Route53 hosted zone id for domain_name. Overrides hosted_zone_name when set."
  default     = null

  validation {
    condition     = var.hosted_zone_id == null || length(trimspace(var.hosted_zone_id)) > 0
    error_message = "hosted_zone_id must be null or non-empty."
  }
}

variable "hosted_zone_name" {
  type        = string
  description = "Optional public Route53 hosted zone name used as a data source when hosted_zone_id is unset."
  default     = null

  validation {
    condition = (
      var.hosted_zone_name == null
      || can(regex("^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\\.?$", trimspace(var.hosted_zone_name)))
    )
    error_message = "hosted_zone_name must be null or a public DNS zone name."
  }
}

variable "certificate_arn" {
  type        = string
  description = "Optional existing ACM certificate ARN for the HTTPS listener. When unset, the stack can manage an ACM DNS-validated certificate."
  default     = null

  validation {
    condition     = var.certificate_arn == null || can(regex("^arn:aws[a-zA-Z-]*:acm:[a-z0-9-]+:[0-9]{12}:certificate/.+$", trimspace(var.certificate_arn)))
    error_message = "certificate_arn must be null or an ACM certificate ARN."
  }
}

variable "manage_certificate" {
  type        = bool
  description = "Create and DNS-validate an ACM public certificate for domain_name when certificate_arn is unset."
  default     = true
}

variable "alb_ingress_cidr_blocks" {
  type        = list(string)
  description = "CIDR blocks allowed to reach the public ALB."
  default     = ["0.0.0.0/0"]
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the created staging VPC."
  default     = "10.82.0.0/16"
}

variable "vpc_id" {
  type        = string
  description = "Existing VPC ID used when create_vpc=false."
  default     = null

  validation {
    condition     = var.vpc_id == null || length(trimspace(var.vpc_id)) > 0
    error_message = "vpc_id must be null or a non-empty VPC ID."
  }
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Existing public subnet IDs for the ALB when create_vpc=false."
  default     = []
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Existing private subnet IDs for ECS, RDS, Redis, and migration tasks when create_vpc=false."
  default     = []
}

variable "trusted_proxy_cidr" {
  type        = string
  description = "CIDR trusted for reverse-proxy headers. Defaults to the selected VPC CIDR."
  default     = null

  validation {
    condition     = var.trusted_proxy_cidr == null || length(trimspace(var.trusted_proxy_cidr)) > 0
    error_message = "trusted_proxy_cidr must be null or a non-empty CIDR string."
  }
}

variable "availability_zone_count" {
  type        = number
  description = "Number of AZs to use."
  default     = 2

  validation {
    condition     = var.availability_zone_count >= 2 && var.availability_zone_count <= 3
    error_message = "availability_zone_count must be 2 or 3."
  }
}

variable "enable_nat_gateway" {
  type        = bool
  description = "Create one NAT gateway for private ECS task egress."
  default     = true
}

variable "nat_gateway_mode" {
  type        = string
  description = "NAT gateway topology when create_vpc=true and enable_nat_gateway=true. Use per_az for enterprise evidence."
  default     = "single"

  validation {
    condition     = contains(["single", "per_az"], var.nat_gateway_mode)
    error_message = "nat_gateway_mode must be single or per_az."
  }
}

variable "assign_public_ip" {
  type        = bool
  description = "Assign public IPs to ECS tasks. Keep false with NAT or VPC endpoints."
  default     = false
}

variable "desired_count" {
  type        = number
  description = "ECS service desired task count."
  default     = 2
}

variable "container_port" {
  type        = number
  description = "Aegaeon server container port."
  default     = 8080
}

variable "task_cpu" {
  type        = number
  description = "Fargate task CPU units."
  default     = 1024
}

variable "task_memory" {
  type        = number
  description = "Fargate task memory MiB."
  default     = 2048
}

variable "db_instance_class" {
  type        = string
  description = "RDS PostgreSQL instance class."
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  type        = number
  description = "RDS allocated storage in GiB."
  default     = 20
}

variable "db_engine_version" {
  type        = string
  description = "RDS PostgreSQL engine version."
  default     = "16"
}

variable "db_multi_az" {
  type        = bool
  description = "Enable RDS Multi-AZ for hosted readiness evidence."
  default     = true
}

variable "db_deletion_protection" {
  type        = bool
  description = "Enable RDS deletion protection."
  default     = false
}

variable "db_skip_final_snapshot" {
  type        = bool
  description = "Skip the final RDS snapshot on destroy. Keep true for short-lived staging; set false with db_final_snapshot_identifier when evidence retention requires a snapshot."
  default     = true
}

variable "db_final_snapshot_identifier" {
  type        = string
  description = "Stable final snapshot identifier used when db_skip_final_snapshot=false."
  default     = null

  validation {
    condition     = var.db_final_snapshot_identifier == null || length(trimspace(var.db_final_snapshot_identifier)) > 0
    error_message = "db_final_snapshot_identifier must be null or a non-empty identifier."
  }
}

variable "redis_node_type" {
  type        = string
  description = "ElastiCache Redis node type."
  default     = "cache.t4g.micro"
}

variable "redis_engine_version" {
  type        = string
  description = "ElastiCache Redis engine version."
  default     = "7.1"
}

variable "bootstrap_owner_email" {
  type        = string
  description = "Initial management owner email used by the hosted bootstrap task."
  default     = "owner@example.com"

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.bootstrap_owner_email))
    error_message = "bootstrap_owner_email must be an email address."
  }
}

variable "bootstrap_team_slug" {
  type        = string
  description = "Initial hosted management team slug."
  default     = "aegaeon-hosted"

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.bootstrap_team_slug))
    error_message = "bootstrap_team_slug must be a lowercase DNS label."
  }
}

variable "bootstrap_tenant_slug" {
  type        = string
  description = "Initial hosted tenant slug."
  default     = "primary"

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.bootstrap_tenant_slug))
    error_message = "bootstrap_tenant_slug must be a lowercase DNS label."
  }
}

variable "bootstrap_tenant_region" {
  type        = string
  description = "Initial hosted tenant region label."
  default     = "aws"

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.bootstrap_tenant_region))
    error_message = "bootstrap_tenant_region must be a lowercase DNS label."
  }
}

variable "bootstrap_environment_slug" {
  type        = string
  description = "Initial hosted environment slug."
  default     = "issuer"

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.bootstrap_environment_slug))
    error_message = "bootstrap_environment_slug must be a lowercase DNS label."
  }
}

variable "create_oidc_kms_key" {
  type        = bool
  description = "Create an AWS KMS asymmetric RSA signing key for hosted OIDC ID Token signing."
  default     = true
}

variable "oidc_kms_key_id" {
  type        = string
  description = "Existing AWS KMS key ID or ARN for hosted OIDC signing when create_oidc_kms_key=false."
  default     = null
}

variable "oidc_kms_key_policy_arn" {
  type        = string
  description = "IAM policy resource ARN for the OIDC KMS key when create_oidc_kms_key=false."
  default     = null
}

variable "oidc_kms_deletion_window_days" {
  type        = number
  description = "KMS deletion window for managed hosted OIDC signing keys."
  default     = 7

  validation {
    condition     = var.oidc_kms_deletion_window_days >= 7 && var.oidc_kms_deletion_window_days <= 30
    error_message = "oidc_kms_deletion_window_days must be in 7..=30."
  }
}

variable "enable_waf" {
  type        = bool
  description = "Attach an AWS WAFv2 web ACL with AWS managed baseline rules to the public ALB."
  default     = true
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention in days."
  default     = 30
}

variable "enable_execute_command" {
  type        = bool
  description = "Enable ECS execute-command for break-glass diagnostics."
  default     = false
}

variable "tags" {
  type        = map(string)
  description = "Additional resource tags."
  default     = {}
}
