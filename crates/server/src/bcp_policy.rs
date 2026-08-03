use serde::{Deserialize, Serialize};
use std::collections::HashSet;

mod validator;
pub use validator::{
    BcpBaselineReport, BcpBaselineValidator, BcpBaselineViolation, ViolationSeverity,
};

/// RFC 9700 OAuth 2.0 Security Best Current Practice baseline posture.
///
/// This type is an audit/reporting model, not the runtime authority. Runtime
/// enforcement is driven by the PostgreSQL-backed management policy snapshot
/// projected into `ServerConfig`, client registry admission, and endpoint-local
/// validators.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // Policy toggles are intentionally explicit for operator reviewability.
pub struct BcpBaselinePolicy {
    /// PKCE is REQUIRED for all OAuth clients (RFC 9700 Section 2.1.1)
    pub require_pkce: bool,

    /// Exact `redirect_uri` matching REQUIRED (RFC 9700 Section 2.1.2)
    pub require_exact_redirect_uri: bool,

    /// Sender-constrained tokens SHOULD be used (RFC 9700 Section 2.2)
    pub require_sender_constrained_tokens: bool,

    /// Implicit flow MUST NOT be used (RFC 9700 Section 2.1.3)
    pub forbid_implicit_flow: bool,

    /// Resource Owner Password Credentials MUST NOT be used (RFC 9700 Section 2.4)
    pub forbid_ropc: bool,

    /// State parameter REQUIRED for authorization code flow (RFC 9700 Section 2.1)
    pub require_state_parameter: bool,

    /// Minimum entropy for state parameter in bits (RFC 9700 recommends 128)
    pub min_state_entropy_bits: u32,

    /// Nonce REQUIRED for ID token requests
    pub require_nonce_for_id_token: bool,

    /// Minimum entropy for nonce in bits
    pub min_nonce_entropy_bits: u32,

    /// Authorization code lifetime in seconds (RFC 9700 recommends max 10 minutes)
    pub max_auth_code_lifetime_seconds: u32,

    /// Access token lifetime in seconds
    pub max_access_token_lifetime_seconds: u32,

    /// Refresh token rotation REQUIRED
    pub require_refresh_token_rotation: bool,

    /// `DPoP` nonce required for enhanced replay protection
    pub require_dpop_nonce: bool,

    /// Issuer identifier REQUIRED in responses (Mix-Up mitigation)
    pub require_iss_parameter: bool,

    /// Client `private_key_jwt` assertions MUST include kid (operational policy)
    pub require_client_jwt_kid: bool,

    /// Allowed client `private_key_jwt` algorithms (operational)
    pub allowed_client_jwt_algs: HashSet<String>,

    /// Allowed OAuth 2.0 flows
    pub allowed_flows: HashSet<String>,

    /// Allowed token endpoint authentication methods
    pub allowed_token_endpoint_auth_methods: HashSet<String>,
}

impl Default for BcpBaselinePolicy {
    /// Returns RFC 9700 compliant default policy
    fn default() -> Self {
        let mut allowed_flows = HashSet::new();
        allowed_flows.insert("authorization_code".to_string());
        allowed_flows.insert("refresh_token".to_string());
        allowed_flows.insert("client_credentials".to_string());
        // Explicitly NOT including "implicit" or "password"

        let mut allowed_auth_methods = HashSet::new();
        allowed_auth_methods.insert("client_secret_basic".to_string());
        allowed_auth_methods.insert("client_secret_post".to_string());
        allowed_auth_methods.insert("private_key_jwt".to_string());

        Self {
            require_pkce: true,
            require_exact_redirect_uri: true,
            require_sender_constrained_tokens: true,
            forbid_implicit_flow: true,
            forbid_ropc: true,
            require_state_parameter: true,
            min_state_entropy_bits: 128,
            require_nonce_for_id_token: true,
            min_nonce_entropy_bits: 128,
            max_auth_code_lifetime_seconds: 600,     // 10 minutes
            max_access_token_lifetime_seconds: 3600, // 1 hour
            require_refresh_token_rotation: true,
            require_dpop_nonce: true,
            require_iss_parameter: true,
            require_client_jwt_kid: true,
            allowed_client_jwt_algs: {
                let mut s = HashSet::new();
                s.insert("RS256".to_string());
                s
            },
            allowed_flows,
            allowed_token_endpoint_auth_methods: allowed_auth_methods,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_is_compliant() {
        let policy = BcpBaselinePolicy::default();
        let validator = BcpBaselineValidator::new(policy);
        let result = validator.validate_policy();
        assert!(result.is_ok(), "Default policy should be BCP compliant");
    }

    #[test]
    fn test_pkce_requirement() -> Result<(), String> {
        let policy = BcpBaselinePolicy {
            require_pkce: false,
            ..Default::default()
        };
        let validator = BcpBaselineValidator::new(policy);
        let violations = validator
            .validate_policy()
            .err()
            .ok_or_else(|| "PKCE-disabled policy must be rejected".to_string())?;
        assert!(violations
            .iter()
            .any(|v| v.policy_item == "require_pkce" && v.severity == ViolationSeverity::Critical));
        Ok(())
    }

    #[test]
    fn test_forbidden_flows() -> Result<(), String> {
        let mut policy = BcpBaselinePolicy::default();
        policy.allowed_flows.insert("implicit".to_string());
        let validator = BcpBaselineValidator::new(policy);
        let violations = validator
            .validate_policy()
            .err()
            .ok_or_else(|| "implicit flow must be rejected".to_string())?;
        assert!(violations
            .iter()
            .any(|v| v.description.contains("Implicit flow")));
        Ok(())
    }

    #[test]
    fn test_flow_checking() {
        let policy = BcpBaselinePolicy::default();
        let validator = BcpBaselineValidator::new(policy);

        assert!(validator.is_flow_allowed("authorization_code"));
        assert!(validator.is_flow_allowed("refresh_token"));
        assert!(!validator.is_flow_allowed("implicit"));
        assert!(!validator.is_flow_allowed("password"));
    }

    #[test]
    fn test_default_auth_methods_match_runtime_support() {
        let policy = BcpBaselinePolicy::default();
        let validator = BcpBaselineValidator::new(policy);

        assert!(validator.is_auth_method_allowed("client_secret_basic"));
        assert!(validator.is_auth_method_allowed("client_secret_post"));
        assert!(validator.is_auth_method_allowed("private_key_jwt"));
        assert!(!validator.is_auth_method_allowed("client_secret_jwt"));
        assert!(!validator.is_auth_method_allowed("tls_client_auth"));
        assert!(!validator.is_auth_method_allowed("self_signed_tls_client_auth"));
    }

    #[test]
    fn test_compliance_report() {
        let policy = BcpBaselinePolicy::default();
        let validator = BcpBaselineValidator::new(policy);
        let report = validator.generate_compliance_report();

        assert!(report.is_bcp_compliant);
        assert_eq!(report.total_violations, 0);
        assert_eq!(report.critical_violations, 0);
    }

    #[test]
    fn invalid_client_jwt_alg_policy_is_reported_without_panic() {
        let policy = BcpBaselinePolicy {
            allowed_client_jwt_algs: ["HS256".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let validator = BcpBaselineValidator::new(policy);
        let result = std::panic::catch_unwind(|| validator.validate_policy());

        assert!(matches!(
            result,
            Ok(Err(violations))
                if violations.iter().any(|violation|
                    violation.policy_item == "allowed_client_jwt_algs"
                        && violation.severity == ViolationSeverity::Critical
                )
        ));
    }
}
