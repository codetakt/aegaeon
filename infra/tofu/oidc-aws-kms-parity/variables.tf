variable "name_prefix" {
  type        = string
  description = "Prefix for AWS resource names and tags."
  default     = "aegaeon-oidc-kms-parity"

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.name_prefix))
    error_message = "name_prefix must contain only ASCII letters, digits, underscore, or hyphen."
  }
}

variable "kms_alias_name" {
  type        = string
  description = "KMS alias name without the alias/ prefix. Defaults to name_prefix."
  default     = null

  validation {
    condition = (
      var.kms_alias_name == null
      ? true
      : (
        can(regex("^[A-Za-z0-9/_-]+$", var.kms_alias_name))
        && !startswith(var.kms_alias_name, "alias/")
        && !startswith(var.kms_alias_name, "aws/")
      )
    )
    error_message = "kms_alias_name must be a non-reserved KMS alias suffix."
  }
}

variable "deletion_window_in_days" {
  type        = number
  description = "KMS key deletion window used by destroy. AWS allows 7..30 days."
  default     = 7

  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "deletion_window_in_days must be in 7..=30."
  }
}

variable "multi_region" {
  type        = bool
  description = "Whether to create a multi-Region KMS key."
  default     = false
}

variable "key_usage_principal_arns" {
  type        = list(string)
  description = "IAM principal ARNs to grant direct key-policy use."
  default     = []
}

variable "create_runner_policy" {
  type        = bool
  description = "Create a standalone minimal IAM policy for the parity runner."
  default     = true
}

variable "runner_policy_name" {
  type        = string
  description = "Name for the optional parity runner IAM policy. Defaults to name_prefix."
  default     = null

  validation {
    condition = (
      var.runner_policy_name == null
      ? true
      : can(regex("^[\\w+=,.@-]+$", var.runner_policy_name))
    )
    error_message = "runner_policy_name must be null or a valid IAM policy name."
  }
}

variable "oidc_signing_kid" {
  type        = string
  description = "Optional explicit OIDC signing kid; defaults from key id."
  default     = null

  validation {
    condition = (
      var.oidc_signing_kid == null
      ? true
      : (
        length(var.oidc_signing_kid) > 0
        && length(var.oidc_signing_kid) <= 128
        && can(regex("^[\\x21-\\x7e]+$", var.oidc_signing_kid))
        && !can(regex("\\s", var.oidc_signing_kid))
      )
    )
    error_message = "oidc_signing_kid must be visible ASCII without spaces."
  }
}

variable "tags" {
  type        = map(string)
  description = "Additional resource tags."
  default     = {}
}
