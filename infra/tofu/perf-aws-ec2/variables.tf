variable "name_prefix" {
  type        = string
  description = "Prefix for resource names/tags."
  default     = "aegaeon-perf"
}

variable "create_vpc" {
  type        = bool
  description = "If true, create a dedicated VPC + subnet for this environment (standalone apply)."
  default     = false
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the dedicated VPC (only used when create_vpc=true)."
  default     = "10.10.0.0/16"
}

variable "public_subnet_cidr" {
  type        = string
  description = "CIDR block for the public subnet (only used when create_vpc=true)."
  default     = "10.10.10.0/24"
}

variable "availability_zone" {
  type        = string
  description = "Optional AZ for the managed subnet (only used when create_vpc=true). When unset, the first available AZ is used."
  default     = null
}

variable "subnet_id" {
  type        = string
  description = "Subnet ID for both instances. If unset and create_vpc=false, the first subnet in the default VPC is used."
  default     = null

  validation {
    condition     = !(var.create_vpc && var.subnet_id != null)
    error_message = "subnet_id must be null when create_vpc=true."
  }
}

variable "associate_public_ip" {
  type        = bool
  description = "Whether to assign public IPs (required if your subnet has no NAT/VPC endpoints)."
  default     = true
}

variable "server_instance_type" {
  type        = string
  description = "EC2 instance type for the server node (x86_64 recommended; container image is amd64)."
  default     = "c6i.large"
}

variable "loadgen_instance_type" {
  type        = string
  description = "EC2 instance type for the load generator node (x86_64 recommended; container image is amd64)."
  default     = "c6i.large"
}

variable "root_volume_gb" {
  type        = number
  description = "Root volume size (GB) for each instance."
  default     = 40
}

variable "server_port" {
  type        = number
  description = "Server listen port."
  default     = 8080
}

variable "server_trusted_proxies" {
  type        = string
  description = "Optional comma-separated CIDRs/IPs for AEGAEON_TRUSTED_PROXIES. When unset, defaults to the selected subnet CIDR + loopback so loadgen traffic is accepted when trusted-proxy enforcement is enabled."
  default     = null

  validation {
    condition     = var.server_trusted_proxies == null ? true : length(trimspace(var.server_trusted_proxies)) > 0
    error_message = "server_trusted_proxies must be null or a non-empty comma-separated list."
  }
}

variable "server_image" {
  type        = string
  description = "Container image reference used for both server and load test binaries."
  default     = "ghcr.io/cariandrum22/aegaeon/aegaeon-server:latest"
}

variable "ghcr_username" {
  type        = string
  description = "GitHub username used for `docker login ghcr.io` when the image registry is GHCR."
  default     = null

  validation {
    condition     = var.ghcr_username == null ? true : length(trimspace(var.ghcr_username)) > 0
    error_message = "ghcr_username must be null or a non-empty string."
  }
}

variable "ghcr_token_ssm_parameter_name" {
  type        = string
  description = "Optional SSM Parameter Store name (SecureString recommended) that contains a GHCR access token. The token value is not managed by OpenTofu."
  default     = null

  validation {
    condition = (
      var.ghcr_token_ssm_parameter_name == null
      ? true
      : (
        length(trimspace(var.ghcr_token_ssm_parameter_name)) > 0
        && (
          !var.ghcr_auth_enabled
          || (var.ghcr_username == null ? false : length(trimspace(var.ghcr_username)) > 0)
        )
      )
    )
    error_message = "ghcr_token_ssm_parameter_name must be null or a non-empty string; when ghcr_auth_enabled=true it also requires ghcr_username."
  }
}

variable "ghcr_token_secretsmanager_secret_id" {
  type        = string
  description = "Optional Secrets Manager secret id/ARN that contains a GHCR access token (SecretString). The token value is not managed by OpenTofu."
  default     = null

  validation {
    condition = (
      var.ghcr_token_secretsmanager_secret_id == null
      ? true
      : (
        length(trimspace(var.ghcr_token_secretsmanager_secret_id)) > 0
        && (
          !var.ghcr_auth_enabled
          || (var.ghcr_username == null ? false : length(trimspace(var.ghcr_username)) > 0)
        )
      )
    )
    error_message = "ghcr_token_secretsmanager_secret_id must be null or a non-empty string; when ghcr_auth_enabled=true it also requires ghcr_username."
  }
}

variable "ghcr_auth_enabled" {
  type        = bool
  description = "If true, attempt to authenticate to GHCR before pulling images when the registry is ghcr.io."
  default     = true
}

variable "expose_metrics_on_main" {
  type        = bool
  description = "Expose /metrics on the main server port (sets AEGAEON_EXPOSE_METRICS_ON_MAIN=1)."
  default     = true
}

variable "artifact_bucket_name" {
  type        = string
  description = "Existing S3 bucket name for load test reports. If unset, a dedicated bucket is created."
  default     = null

  validation {
    condition     = var.artifact_bucket_name == null ? true : length(trimspace(var.artifact_bucket_name)) > 0
    error_message = "artifact_bucket_name must be null or a non-empty bucket name."
  }
}

variable "artifact_bucket_force_destroy" {
  type        = bool
  description = "If true and this module creates the bucket, objects will be deleted on destroy."
  default     = false
}

variable "artifact_prefix" {
  type        = string
  description = "S3 key prefix for uploaded reports (e.g. perf/)."
  default     = "perf/"

  validation {
    condition     = length(var.artifact_prefix) > 0
    error_message = "artifact_prefix must be a non-empty string."
  }
}

variable "auto_run_loadtest" {
  type        = bool
  description = "If true, run the load test automatically on the load generator instance at boot."
  default     = false
}

variable "loadtest_workers" {
  type        = number
  description = "Load test workers (concurrency)."
  default     = 50
}

variable "loadtest_rps" {
  type        = number
  description = "Target requests per second."
  default     = 200
}

variable "loadtest_run_time" {
  type        = string
  description = "Run time duration string (e.g. 60s, 5m)."
  default     = "60s"
}

variable "loadtest_warmup" {
  type        = number
  description = "Warmup duration (seconds)."
  default     = 10
}

variable "loadtest_scenario" {
  type        = string
  description = "Scenario name for aegaeon-loadtest (mixed, auth-code, par, dpop, introspection, revocation, key-rotation)."
  default     = "mixed"
}
