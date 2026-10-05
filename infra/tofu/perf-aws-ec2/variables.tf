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
  nullable    = false
  description = "Canonical IPv4 CIDRs of TLS proxy sources reaching the backend; shared by ingress and header trust."
  validation {
    condition = length(trimspace(var.server_trusted_proxies)) > 0 && alltrue([
      for cidr in split(",", var.server_trusted_proxies) : (
        !strcontains(trimspace(cidr), ":")
        && try(cidrsubnet(trimspace(cidr), 0, 0) == trimspace(cidr), false)
        && try(tonumber(split("/", trimspace(cidr))[1]) > 0, false)
      )
    ])
    error_message = "Supply comma-separated canonical IPv4 proxy CIDRs with prefixes 1 through 32; IPv6, host bits and unrestricted /0 are not supported by these IPv4 backend nodes."
  }
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

variable "artifact_bucket_name" {
  type        = string
  description = "Existing S3 bucket name for load test reports. If unset, a dedicated bucket is created."
  default     = null

  validation {
    condition = alltrue([for name in [var.artifact_bucket_name == null ? "${var.name_prefix}-00000000" : var.artifact_bucket_name] : (
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", name))
      && !strcontains(name, "..")
      && !can(regex("^[0-9]+([.][0-9]+){3}$", name))
      && !anytrue([for prefix in ["xn--", "sthree-", "amzn-s3-demo-"] : startswith(name, prefix)])
      && !anytrue([for suffix in ["-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"] : endswith(name, suffix)])
      && (!endswith(name, "-an") || can(regex("^[a-z0-9][a-z0-9.-]*-[0-9]{12}-[a-z]+(-[a-z]+)+-[0-9]+-an$", name)))
    )])
    error_message = "The supplied or generated artifact bucket must satisfy general-purpose S3 naming and reserved namespace rules."
  }
}

variable "artifact_bucket_force_destroy" {
  type        = bool
  description = "If true and this module creates the bucket, objects will be deleted on destroy."
  default     = false
}

variable "artifact_prefix" {
  type        = string
  nullable    = false
  description = "S3 key prefix for uploaded reports (e.g. perf/)."
  default     = "perf/"

  validation {
    condition = (
      can(regex("^[A-Za-z0-9_./-]+/$", var.artifact_prefix))
      && !startswith(var.artifact_prefix, "/")
      && alltrue([for part in split("/", trim(var.artifact_prefix, "/")) : !contains(["", ".", ".."], part)])
    )
    error_message = "artifact_prefix must end in /, contain only letters, digits, _, ., / or -, and have no empty, . or .. path segments."
  }
}

variable "auto_run_loadtest" {
  type        = bool
  description = "If true, run the load test automatically on the load generator instance at boot."
  default     = false
}

variable "loadtest_workers" {
  type        = number
  nullable    = false
  description = "Load test workers (concurrency)."
  default     = 50
  validation {
    condition     = var.loadtest_workers == floor(var.loadtest_workers) && var.loadtest_workers >= 1 && var.loadtest_workers <= 4294967295
    error_message = "loadtest_workers must be an integer from 1 through 4294967295."
  }
}

variable "loadtest_rps" {
  type        = number
  nullable    = false
  description = "Target scenario invocations per second; HTTP attempts are accounted separately."
  default     = 200
  validation {
    # pow(x, 1) converts to binary64, matching the guest and load-test CLI.
    # Check the converted rate and delay, preserving accepted rounding at the bounds.
    condition = try(
      pow(var.loadtest_rps, 1) > 0
      && pow(var.loadtest_rps, 1) <= pow(1.7976931348623157e308, 1)
      && pow(var.loadtest_workers / pow(var.loadtest_rps, 1), 1) <= 86400,
      false,
    )
    error_message = "loadtest_rps must convert to a finite positive binary64 rate with a per-worker delay of at most 86400 seconds."
  }
}

variable "loadtest_run_time" {
  type        = string
  nullable    = false
  description = "Canonical positive integer duration, optionally followed by s, m or h; at most one day."
  default     = "60s"
  validation {
    condition = try(
      tonumber(regex("^([1-9][0-9]*)([smh]?)$", var.loadtest_run_time)[0])
      * lookup({ "" = 1, s = 1, m = 60, h = 3600 }, regex("^([1-9][0-9]*)([smh]?)$", var.loadtest_run_time)[1]) <= 86400,
      false,
    )
    error_message = "loadtest_run_time must be a canonical positive integer number of seconds, minutes or hours, no greater than 86400 seconds."
  }
}

variable "loadtest_warmup" {
  type        = number
  nullable    = false
  description = "Warmup duration (seconds)."
  default     = 10
  validation {
    condition     = var.loadtest_warmup == floor(var.loadtest_warmup) && var.loadtest_warmup >= 0 && var.loadtest_warmup <= 86400
    error_message = "loadtest_warmup must be an integer number of seconds from 0 through 86400."
  }
}

variable "loadtest_scenario" {
  type        = string
  nullable    = false
  description = "Selection: smoke, auth-code, introspection, revocation, dpop, userinfo, discovery, jwks, par, mixed, policy-mixed or key-rotation (explicitly unsupported)."
  default     = "mixed"
  validation {
    condition     = contains(["smoke", "auth-code", "introspection", "revocation", "dpop", "userinfo", "discovery", "jwks", "par", "mixed", "policy-mixed", "key-rotation"], var.loadtest_scenario)
    error_message = "Select a documented load-test scenario; key-rotation remains explicitly unsupported by the consumer."
  }
}

variable "server_image" {
  type        = string
  description = "Exact externally tested OCI artifact digest."
  validation {
    condition = (
      can(regex("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:[.][a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::[0-9]+)?/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*@sha256:[0-9a-f]{64}$", var.server_image)) &&
      can(regex("^[^/]+/[^@]{1,255}@sha256:[0-9a-f]{64}$", var.server_image))
    )
    error_message = "A lowercase Docker repository reference with a path of at most 255 characters and a pinned SHA256 digest is required."
  }
}

variable "loadgen_image" {
  type        = string
  description = "Exact externally tested OCI artifact digest."
  validation {
    condition = (
      can(regex("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:[.][a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::[0-9]+)?/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*@sha256:[0-9a-f]{64}$", var.loadgen_image)) &&
      can(regex("^[^/]+/[^@]{1,255}@sha256:[0-9a-f]{64}$", var.loadgen_image))
    )
    error_message = "A lowercase Docker repository reference with a path of at most 255 characters and a pinned SHA256 digest is required."
  }
}

variable "server_entrypoint" {
  type        = string
  description = "Explicit externally verified container executable path."
  validation {
    condition     = can(regex("^/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$", var.server_entrypoint)) && !contains(split("/", var.server_entrypoint), "..") && !contains(split("/", var.server_entrypoint), ".")
    error_message = "An absolute executable path with nonempty components and no traversal is required."
  }
}

variable "loadgen_entrypoint" {
  type        = string
  description = "Explicit externally verified container executable path."
  validation {
    condition     = can(regex("^/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$", var.loadgen_entrypoint)) && !contains(split("/", var.loadgen_entrypoint), "..") && !contains(split("/", var.loadgen_entrypoint), ".")
    error_message = "An absolute executable path with nonempty components and no traversal is required."
  }
}

variable "issuer_host" {
  type        = string
  description = "Canonical active management environment selector."
  validation {
    condition     = length(var.issuer_host) <= 253 && alltrue([for label in split(".", var.issuer_host) : can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", label))])
    error_message = "A canonical DNS issuer host is required."
  }
}

variable "issuer_url" {
  type        = string
  description = "Actual HTTPS issuer target through supplied TLS routing."
  validation {
    condition     = var.issuer_url == "https://${var.issuer_host}"
    error_message = "The target must match the canonical HTTPS issuer origin."
  }
}

variable "server_secret_arn" {
  type        = string
  description = "External Secrets Manager bundle ARN; values never managed by OpenTofu."
  validation {
    condition     = can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", var.server_secret_arn))
    error_message = "A full Secrets Manager ARN is required."
  }
}

variable "server_secret_version" {
  type        = string
  description = "Exact supplier version ID for the bundle."
  validation {
    condition     = can(regex("^[A-Za-z0-9-]{32,64}$", var.server_secret_version))
    error_message = "server_secret_version must be a pinned version ID of 32 to 64 letters, digits, or hyphens."
  }
}

variable "server_secret_kms_key_arns" {
  type        = list(string)
  description = "Actual customer-managed encryption key ARNs, if used."
  default     = []
  validation {
    condition     = alltrue([for arn in var.server_secret_kms_key_arns : can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-f0-9-]+$", arn))])
    error_message = "Supply actual KMS key ARNs."
  }
}

variable "client_secret_arn" {
  type        = string
  description = "External Secrets Manager bundle ARN; values never managed by OpenTofu."
  validation {
    condition     = can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", var.client_secret_arn))
    error_message = "A full Secrets Manager ARN is required."
  }
}

variable "client_secret_version" {
  type        = string
  description = "Exact supplier version ID for the bundle."
  validation {
    condition     = can(regex("^[A-Za-z0-9-]{32,64}$", var.client_secret_version))
    error_message = "client_secret_version must be a pinned version ID of 32 to 64 letters, digits, or hyphens."
  }
}

variable "client_secret_kms_key_arns" {
  type        = list(string)
  description = "Actual customer-managed encryption key ARNs, if used."
  default     = []
  validation {
    condition     = alltrue([for arn in var.client_secret_kms_key_arns : can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-f0-9-]+$", arn))])
    error_message = "Supply actual KMS key ARNs."
  }
}

variable "metrics_secret_arn" {
  type        = string
  description = "External Secrets Manager bundle ARN; values never managed by OpenTofu."
  default     = ""
  validation {
    condition     = can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", var.metrics_secret_arn)) || var.metrics_secret_arn == ""
    error_message = "A full Secrets Manager ARN is required."
  }
}

variable "metrics_secret_version" {
  type        = string
  description = "Exact supplier version ID for the bundle."
  default     = ""
  validation {
    condition     = (var.metrics_secret_arn != "" && can(regex("^[A-Za-z0-9-]{32,64}$", var.metrics_secret_version))) || (var.metrics_secret_version == "" && var.metrics_secret_arn == "")
    error_message = "A pinned version ID is required; absent metrics must have no version."
  }
}

variable "metrics_secret_kms_key_arns" {
  type        = list(string)
  description = "Actual customer-managed encryption key ARNs, if used."
  default     = []
  validation {
    condition     = alltrue([for arn in var.metrics_secret_kms_key_arns : can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-f0-9-]+$", arn))])
    error_message = "Supply actual KMS key ARNs."
  }
}

variable "runtime_kms_key_arns" {
  type        = list(string)
  description = "Actual active runtime signing key ARNs; bootstrap identity stays external."
  validation {
    condition     = length(var.runtime_kms_key_arns) > 0 && alltrue([for arn in var.runtime_kms_key_arns : can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-f0-9-]+$", arn))])
    error_message = "Supply active runtime KMS key ARNs."
  }
}

variable "loadgen_artifact_receipt_path" {
  description = "Externally supplied trusted build artifact protected absolute host path; no Terraform retrieval or artifact creation."
  type        = string
  nullable    = false
  validation {
    condition = (
      can(regex("^/(?:[^\\p{C}\\p{Z}]| )+$", var.loadgen_artifact_receipt_path))
      && alltrue([for part in slice(split("/", var.loadgen_artifact_receipt_path), 1, length(split("/", var.loadgen_artifact_receipt_path))) : !contains(["", ".", ".."], part)])
      && var.loadgen_artifact_receipt_path != var.loadgen_source_manifest_path
    )
    error_message = "Use a printable canonical absolute receipt file path, without empty, . or .. components, distinct from the source manifest path."
  }
}

variable "loadgen_source_manifest_path" {
  description = "Externally supplied trusted build artifact protected absolute host path; no Terraform retrieval or artifact creation."
  type        = string
  nullable    = false
  validation {
    condition = (
      can(regex("^/(?:[^\\p{C}\\p{Z}]| )+$", var.loadgen_source_manifest_path))
      && alltrue([for part in slice(split("/", var.loadgen_source_manifest_path), 1, length(split("/", var.loadgen_source_manifest_path))) : !contains(["", ".", ".."], part)])
    )
    error_message = "Use a printable canonical absolute manifest file path, without empty, . or .. components."
  }
}

variable "loadgen_artifact_receipt_sha256" {
  description = "Externally supplied trusted build artifact independently adopted raw SHA256 pin; no Terraform retrieval or artifact creation."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.loadgen_artifact_receipt_sha256))
    error_message = "loadgen_artifact_receipt_sha256 must be 64 lowercase hexadecimal characters."
  }
}

variable "loadgen_source_manifest_sha256" {
  description = "Externally supplied trusted build artifact independently adopted raw SHA256 pin; no Terraform retrieval or artifact creation."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.loadgen_source_manifest_sha256))
    error_message = "loadgen_source_manifest_sha256 must be 64 lowercase hexadecimal characters."
  }
}

variable "loadgen_executable_sha256" {
  description = "Externally supplied trusted build artifact independently adopted raw SHA256 pin; no Terraform retrieval or artifact creation."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.loadgen_executable_sha256))
    error_message = "loadgen_executable_sha256 must be 64 lowercase hexadecimal characters."
  }
}
