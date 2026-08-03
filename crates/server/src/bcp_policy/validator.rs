use serde::{Deserialize, Serialize};

use super::BcpBaselinePolicy;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcpBaselineViolation {
    pub policy_item: String,
    pub description: String,
    pub severity: ViolationSeverity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Critical, // MUST/MUST NOT violations
    High,     // SHOULD violations
    Medium,   // Recommendations
}

/// Audit helper that compares a source-managed posture against RFC 9700 BCP requirements.
///
/// This type does not participate in request admission. The data plane enforces
/// OAuth/OIDC policy through the management database policy projection and
/// endpoint-local validators.
pub struct BcpBaselineValidator {
    policy: BcpBaselinePolicy,
}

impl BcpBaselineValidator {
    #[must_use]
    pub fn new(policy: BcpBaselinePolicy) -> Self {
        Self { policy }
    }

    /// Validate that the policy meets RFC 9700 BCP requirements
    ///
    /// # Errors
    ///
    /// Returns a list of policy violations when the current configuration falls below the RFC 9700
    /// baseline or local hardening requirements.
    pub fn validate_policy(&self) -> Result<(), Vec<BcpBaselineViolation>> {
        let mut violations = Vec::new();
        self.validate_must_requirements(&mut violations);
        self.validate_should_requirements(&mut violations);
        self.validate_client_jwt_algorithms(&mut violations);
        self.validate_entropy_requirements(&mut violations);
        self.validate_forbidden_flows(&mut violations);
        self.validate_timing_requirements(&mut violations);

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }

    fn push_violation(
        violations: &mut Vec<BcpBaselineViolation>,
        policy_item: &str,
        description: impl Into<String>,
        severity: ViolationSeverity,
    ) {
        violations.push(BcpBaselineViolation {
            policy_item: policy_item.to_string(),
            description: description.into(),
            severity,
        });
    }

    fn validate_must_requirements(&self, violations: &mut Vec<BcpBaselineViolation>) {
        if !self.policy.require_pkce {
            Self::push_violation(
                violations,
                "require_pkce",
                "RFC 9700: PKCE MUST be used for all OAuth clients",
                ViolationSeverity::Critical,
            );
        }

        if !self.policy.require_exact_redirect_uri {
            Self::push_violation(
                violations,
                "require_exact_redirect_uri",
                "RFC 9700: Exact redirect_uri matching MUST be enforced",
                ViolationSeverity::Critical,
            );
        }

        if !self.policy.forbid_implicit_flow {
            Self::push_violation(
                violations,
                "forbid_implicit_flow",
                "RFC 9700: Implicit flow MUST NOT be used",
                ViolationSeverity::Critical,
            );
        }

        if !self.policy.forbid_ropc {
            Self::push_violation(
                violations,
                "forbid_ropc",
                "RFC 9700: Resource Owner Password Credentials MUST NOT be used",
                ViolationSeverity::Critical,
            );
        }

        if !self.policy.require_state_parameter {
            Self::push_violation(
                violations,
                "require_state_parameter",
                "RFC 9700: State parameter MUST be used in authorization requests",
                ViolationSeverity::Critical,
            );
        }

        if !self.policy.require_iss_parameter {
            Self::push_violation(
                violations,
                "require_iss_parameter",
                "RFC 9700: Issuer identifier MUST be included to prevent Mix-Up attacks",
                ViolationSeverity::Critical,
            );
        }

        if !self.policy.require_client_jwt_kid {
            Self::push_violation(
                violations,
                "require_client_jwt_kid",
                "Client private_key_jwt assertions should include 'kid' for reliable key selection",
                ViolationSeverity::High,
            );
        }
    }

    fn validate_should_requirements(&self, violations: &mut Vec<BcpBaselineViolation>) {
        if !self.policy.require_sender_constrained_tokens {
            Self::push_violation(
                violations,
                "require_sender_constrained_tokens",
                "RFC 9700: Sender-constrained tokens (DPoP/mTLS) SHOULD be used",
                ViolationSeverity::High,
            );
        }

        if !self.policy.require_refresh_token_rotation {
            Self::push_violation(
                violations,
                "require_refresh_token_rotation",
                "RFC 9700: Refresh token rotation SHOULD be implemented",
                ViolationSeverity::High,
            );
        }
    }

    fn validate_client_jwt_algorithms(&self, violations: &mut Vec<BcpBaselineViolation>) {
        if self.policy.allowed_client_jwt_algs.is_empty() {
            Self::push_violation(
                violations,
                "allowed_client_jwt_algs",
                "Client JWT algorithm policy must enable at least one supported algorithm",
                ViolationSeverity::Critical,
            );
            return;
        }

        for alg in &self.policy.allowed_client_jwt_algs {
            let normalized = alg.trim().to_ascii_uppercase();
            if normalized != *alg || normalized != "RS256" {
                Self::push_violation(
                    violations,
                    "allowed_client_jwt_algs",
                    format!(
                        "Client JWT algorithm policy contains unsupported algorithm {alg:?}; expected RS256"
                    ),
                    ViolationSeverity::Critical,
                );
            }
        }
    }

    fn validate_entropy_requirements(&self, violations: &mut Vec<BcpBaselineViolation>) {
        if self.policy.min_state_entropy_bits < 128 {
            Self::push_violation(
                violations,
                "min_state_entropy_bits",
                format!(
                    "RFC 9700: State parameter should have at least 128 bits of entropy, got {}",
                    self.policy.min_state_entropy_bits
                ),
                ViolationSeverity::High,
            );
        }
    }

    fn validate_forbidden_flows(&self, violations: &mut Vec<BcpBaselineViolation>) {
        if self.policy.allowed_flows.contains("implicit") {
            Self::push_violation(
                violations,
                "allowed_flows",
                "RFC 9700: Implicit flow found in allowed flows but is forbidden",
                ViolationSeverity::Critical,
            );
        }

        if self.policy.allowed_flows.contains("password") {
            Self::push_violation(
                violations,
                "allowed_flows",
                "RFC 9700: Password flow (ROPC) found in allowed flows but is forbidden",
                ViolationSeverity::Critical,
            );
        }
    }

    fn validate_timing_requirements(&self, violations: &mut Vec<BcpBaselineViolation>) {
        if self.policy.max_auth_code_lifetime_seconds > 600 {
            Self::push_violation(
                violations,
                "max_auth_code_lifetime_seconds",
                format!(
                    "RFC 9700: Authorization codes should expire within 10 minutes, configured for {} seconds",
                    self.policy.max_auth_code_lifetime_seconds
                ),
                ViolationSeverity::High,
            );
        }
    }

    /// Check if a specific flow is allowed
    #[must_use]
    pub fn is_flow_allowed(&self, flow: &str) -> bool {
        // First check explicit forbidding
        match flow {
            "implicit" if self.policy.forbid_implicit_flow => false,
            "password" if self.policy.forbid_ropc => false,
            _ => self.policy.allowed_flows.contains(flow),
        }
    }

    /// Check if an authentication method is allowed
    #[must_use]
    pub fn is_auth_method_allowed(&self, method: &str) -> bool {
        self.policy
            .allowed_token_endpoint_auth_methods
            .contains(method)
    }

    /// Generate a baseline audit report.
    #[must_use]
    pub fn generate_compliance_report(&self) -> BcpBaselineReport {
        let validation_result = self.validate_policy();
        let is_compliant = validation_result.is_ok();
        let violations = match validation_result {
            Ok(()) => Vec::new(),
            Err(v) => v,
        };

        let critical_count = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Critical)
            .count();
        let high_count = violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::High)
            .count();

        BcpBaselineReport {
            is_bcp_compliant: is_compliant,
            total_violations: violations.len(),
            critical_violations: critical_count,
            high_violations: high_count,
            violations,
            policy_hash: self.calculate_policy_hash(),
        }
    }

    fn calculate_policy_hash(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        format!("{:?}", self.policy).hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcpBaselineReport {
    pub is_bcp_compliant: bool,
    pub total_violations: usize,
    pub critical_violations: usize,
    pub high_violations: usize,
    pub violations: Vec<BcpBaselineViolation>,
    pub policy_hash: String,
}
