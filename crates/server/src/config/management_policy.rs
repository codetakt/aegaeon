use crate::management::types::{PolicyDocument, PolicySenderConstraint};
use crate::policy::{
    canonical_supported_grant_types, validate_supported_grant_types, SenderConstraint,
    DEVICE_CODE_GRANT_TYPE, JWT_BEARER_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE,
};
use crate::runtime_keys::canonical_runtime_signing_algorithm_name;
use aegaeon_jose::algorithms::CryptoProfile;

use super::federation::normalize_federation_outbound_allowed_domains;
use super::{
    valid_client_assertion_replay_window_secs, validate_public_base_url_value, ConfigError,
    ServerConfig,
};

mod numeric;
use numeric::{validate_auth_max_sessions_policy, validate_numeric_policy_fields};

impl ServerConfig {
    pub fn with_management_policy(mut self, policy: &PolicyDocument) -> Result<Self, ConfigError> {
        self.apply_management_policy(policy)?;
        Ok(self)
    }

    pub fn apply_management_policy(&mut self, policy: &PolicyDocument) -> Result<(), ConfigError> {
        validate_management_policy_for_runtime(policy)?;

        self.strict_authorize_redirect = policy.strict_authorize_redirect;
        self.require_state = policy.require_state_parameter;
        self.require_client_auth_token = policy.require_client_auth_token;
        self.require_client_auth_par = policy.require_client_auth_par;
        self.require_client_auth_introspection = policy.require_client_auth_introspection;
        self.require_client_auth_revocation = policy.require_client_auth_revocation;
        self.require_pushed_authorization_requests = policy.require_pushed_authorization_requests;
        self.dpop_strict = policy.dpop_strict;
        self.dpop_iat_window_secs = u64::from(policy.dpop_iat_window_seconds);
        self.require_dpop_nonce = policy.dpop_require_nonce;
        self.dpop_nonce_ttl_secs = u64::from(policy.dpop_nonce_ttl_seconds);
        self.enable_private_key_jwt = policy.private_key_jwt_enabled;
        self.enable_jwt_bearer_grant = policy_allows_grant(policy, JWT_BEARER_GRANT_TYPE);
        self.allow_jwt_bearer_client_subject = policy.jwt_bearer_allow_client_subject;
        self.enable_token_exchange = policy_allows_grant(policy, TOKEN_EXCHANGE_GRANT_TYPE);
        self.enable_device_authz = policy_allows_grant(policy, DEVICE_CODE_GRANT_TYPE);
        self.allowed_grant_types = canonical_supported_grant_types(&policy.allowed_grant_types)
            .map_err(|error| ConfigError::InvalidValue {
                key: "allowed_grant_types".to_string(),
                value: policy.allowed_grant_types.join(","),
                reason: error.to_string(),
            })?;
        self.dcr_everparse_runtime_enabled = policy.dcr_everparse_runtime_enabled;
        self.request_object_everparse_runtime_enabled =
            policy.request_object_everparse_runtime_enabled;
        self.enable_jwt_access_tokens = policy.jwt_access_tokens_enabled;
        self.enable_jwt_introspection = policy.jwt_introspection_enabled;
        self.jwt_introspection_exp_secs = u64::from(policy.jwt_introspection_exp_seconds);
        self.jwt_leeway_secs = u64::from(policy.jwt_leeway_seconds);
        self.jose_header_max_len = usize::try_from(policy.jose_header_max_len).map_err(|_| {
            ConfigError::InvalidNumberRange {
                key: "jose_header_max_len".to_string(),
                value: policy.jose_header_max_len.to_string(),
                expectation: "a value in 1..=65536 characters".to_string(),
            }
        })?;
        self.authorization_details_types_supported =
            normalize_runtime_policy_list(&policy.authorization_details_types_supported);
        self.acr_values_supported = normalize_runtime_policy_list(&policy.acr_values_supported);
        self.default_acr = normalize_runtime_policy_text(policy.default_acr.as_deref());
        self.local_password_acr =
            normalize_runtime_policy_text(policy.local_password_acr.as_deref());
        self.access_token_ttl_secs = u64::from(policy.access_token_time_to_live_seconds);
        self.refresh_token_ttl_secs = u64::from(policy.refresh_token_time_to_live_seconds);
        self.authorization_code_ttl_secs =
            u64::from(policy.authorization_code_time_to_live_seconds);
        self.par_expires_in_secs = u64::from(policy.par_expires_in_seconds);
        self.device_code_ttl_secs = u64::from(policy.device_code_ttl_seconds);
        self.device_code_poll_interval_secs = u64::from(policy.device_code_poll_interval_seconds);
        self.pkjwt_jti_window_secs = i64::from(policy.pkjwt_jti_window_seconds);
        self.jwt_bearer_jti_window_secs = i64::from(policy.jwt_bearer_jti_window_seconds);
        self.request_object_jti_ttl_secs = u64::from(policy.request_object_jti_ttl_seconds);
        self.stepup_challenge_ttl_secs = u64::from(policy.stepup_challenge_ttl_seconds);
        self.upstream_auth_ttl_secs = u64::from(policy.upstream_auth_ttl_seconds);
        self.upstream_logout_relay_ttl_secs = u64::from(policy.upstream_logout_relay_ttl_seconds);
        self.upstream_outbound_allowed_domains =
            crate::upstream::normalize_upstream_outbound_allowed_domains(
                &policy.upstream_outbound_allowed_domains,
            )
            .map_err(|reason| ConfigError::InvalidValue {
                key: "upstream_outbound_allowed_domains".to_string(),
                value: policy.upstream_outbound_allowed_domains.join(","),
                reason,
            })?;
        self.mtls_enabled = policy.mtls_enabled;
        self.mtls_alias_par = policy.mtls_alias_par_enabled;
        self.mtls_base_url =
            normalize_runtime_policy_url("mtls_base_url", policy.mtls_base_url.as_deref())?;
        self.crypto_profile = crypto_profile_from_management_policy(&policy.crypto_profile)?;

        self.security_policy.require_pkce = policy.pkce_required;
        self.security_policy.sender_constrained = SenderConstraint::from(policy.sender_constraint);
        self.security_policy.token_validation.require_scope_subset = policy.require_scope_subset;
        self.security_policy.token_validation.require_audience_match =
            policy.require_audience_match;
        self.security_policy.refresh.retain_refresh_chain = policy.retain_refresh_chain;
        self.security_policy.refresh.enforce_sender_binding = policy.enforce_refresh_sender_binding;
        self.transport.apply_security_policy(&self.security_policy);

        Ok(())
    }
}

pub(crate) fn validate_management_policy_for_runtime(
    policy: &PolicyDocument,
) -> Result<(), ConfigError> {
    validate_numeric_policy_fields(policy)?;
    validate_auth_max_sessions_policy(policy)?;
    crate::client_registry::JwksRuntimePolicy::validate_management_policy(policy)?;
    validate_client_assertion_replay_windows(policy)?;
    validate_required_policy_allowlists(policy)?;
    validate_dcr_allowed_sender_methods(policy)?;
    crypto_profile_from_management_policy(&policy.crypto_profile)?;
    validate_runtime_signing_algorithm_policy(policy)?;
    validate_private_key_jwt_algorithm_policy(policy)?;
    validate_policy_urls(policy)?;
    validate_sender_constraint_policy(policy)?;
    validate_software_statement_key_policy(policy)?;
    validate_policy_acr(policy)?;

    Ok(())
}

fn validate_client_assertion_replay_windows(policy: &PolicyDocument) -> Result<(), ConfigError> {
    if !valid_client_assertion_replay_window_secs(i64::from(policy.pkjwt_jti_window_seconds)) {
        return Err(ConfigError::InvalidNumberRange {
            key: "pkjwt_jti_window_seconds".to_string(),
            value: policy.pkjwt_jti_window_seconds.to_string(),
            expectation: "a value in 1..=3600 seconds".to_string(),
        });
    }
    if !valid_client_assertion_replay_window_secs(i64::from(policy.jwt_bearer_jti_window_seconds)) {
        return Err(ConfigError::InvalidNumberRange {
            key: "jwt_bearer_jti_window_seconds".to_string(),
            value: policy.jwt_bearer_jti_window_seconds.to_string(),
            expectation: "a value in 1..=3600 seconds".to_string(),
        });
    }
    Ok(())
}

fn validate_required_policy_allowlists(policy: &PolicyDocument) -> Result<(), ConfigError> {
    if policy.allowed_signing_algorithms.is_empty() || policy.allowed_grant_types.is_empty() {
        return Err(ConfigError::InvalidValue {
            key: "configurationDocument.policy".to_string(),
            value: "[]".to_string(),
            reason: "algorithm and grant allowlists must not be empty".to_string(),
        });
    }
    validate_supported_grant_types(&policy.allowed_grant_types).map_err(|error| {
        ConfigError::InvalidValue {
            key: "allowed_grant_types".to_string(),
            value: policy.allowed_grant_types.join(","),
            reason: error.to_string(),
        }
    })?;
    Ok(())
}

fn validate_dcr_allowed_sender_methods(policy: &PolicyDocument) -> Result<(), ConfigError> {
    let methods = normalized_dcr_allowed_sender_methods(policy);
    if methods.is_empty() {
        return Err(ConfigError::InvalidValue {
            key: "dcr_allowed_sender_methods".to_string(),
            value: policy.dcr_allowed_sender_methods.join(","),
            reason: "must contain at least one sender-constrained DCR method".to_string(),
        });
    }
    if let Some(unimplemented) = methods
        .iter()
        .find(|method| !crate::dcr::runtime_supported_sender_constrained_method(method))
    {
        return Err(ConfigError::InvalidValue {
            key: "dcr_allowed_sender_methods".to_string(),
            value: unimplemented.clone(),
            reason: format!(
                "sender-constrained DCR currently supports only {}",
                crate::dcr::RUNTIME_SUPPORTED_DCR_SENDER_METHODS.join(",")
            ),
        });
    }
    Ok(())
}

fn normalized_dcr_allowed_sender_methods(policy: &PolicyDocument) -> Vec<String> {
    policy
        .dcr_allowed_sender_methods
        .iter()
        .flat_map(|method| method.split(','))
        .map(str::trim)
        .filter(|method| !method.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn crypto_profile_from_management_policy(value: &str) -> Result<CryptoProfile, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "verified" => Ok(CryptoProfile::Verified),
        _ => Err(ConfigError::InvalidCryptoProfile {
            value: value.to_string(),
        }),
    }
}

fn validate_runtime_signing_algorithm_policy(policy: &PolicyDocument) -> Result<(), ConfigError> {
    let mut seen = std::collections::BTreeSet::new();
    for algorithm in &policy.allowed_signing_algorithms {
        let Some(canonical) = canonical_runtime_signing_algorithm_name(algorithm) else {
            return Err(ConfigError::InvalidValue {
                key: "allowed_signing_algorithms".to_string(),
                value: algorithm.clone(),
                reason: "expected one of RS256, EdDSA".to_string(),
            });
        };
        if !matches!(canonical, "RS256" | "EdDSA") {
            return Err(ConfigError::InvalidValue {
                key: "allowed_signing_algorithms".to_string(),
                value: algorithm.clone(),
                reason: "verified server runtime signing policy allows only RS256 and EdDSA"
                    .to_string(),
            });
        }
        if !seen.insert(canonical) {
            return Err(ConfigError::InvalidValue {
                key: "allowed_signing_algorithms".to_string(),
                value: algorithm.clone(),
                reason: "entries must be unique".to_string(),
            });
        }
    }
    Ok(())
}

fn validate_private_key_jwt_algorithm_policy(policy: &PolicyDocument) -> Result<(), ConfigError> {
    let mut seen = std::collections::BTreeSet::new();
    for algorithm in &policy.client_jwt_allowed_algs {
        let normalized = algorithm.trim().to_ascii_uppercase();
        if !matches!(normalized.as_str(), "RS256" | "PS256") {
            return Err(ConfigError::InvalidValue {
                key: "client_jwt_allowed_algs".to_string(),
                value: algorithm.clone(),
                reason: "verified server client assertion policy allows only promoted RS256 or PS256 verification"
                    .to_string(),
            });
        }
        if !seen.insert(normalized) {
            return Err(ConfigError::InvalidValue {
                key: "client_jwt_allowed_algs".to_string(),
                value: algorithm.clone(),
                reason: "entries must be unique".to_string(),
            });
        }
    }
    if policy.private_key_jwt_enabled && policy.client_jwt_allowed_algs.is_empty() {
        return Err(ConfigError::InvalidValue {
            key: "client_jwt_allowed_algs".to_string(),
            value: "[]".to_string(),
            reason: "private_key_jwt requires at least one allowed client assertion algorithm"
                .to_string(),
        });
    }
    Ok(())
}

fn validate_policy_urls(policy: &PolicyDocument) -> Result<(), ConfigError> {
    if let Some(mtls_base_url) = policy.mtls_base_url.as_deref() {
        validate_public_base_url_value("mtls_base_url", mtls_base_url)?;
    }
    normalize_federation_outbound_allowed_domains(&policy.federation_outbound_allowed_domains)
        .map(|_| ())?;
    crate::upstream::normalize_upstream_outbound_allowed_domains(
        &policy.upstream_outbound_allowed_domains,
    )
    .map_err(|reason| ConfigError::InvalidValue {
        key: "upstream_outbound_allowed_domains".to_string(),
        value: policy.upstream_outbound_allowed_domains.join(","),
        reason,
    })?;
    Ok(())
}

fn validate_sender_constraint_policy(policy: &PolicyDocument) -> Result<(), ConfigError> {
    if policy.sender_constraint == PolicySenderConstraint::Mtls && !policy.mtls_enabled {
        return Err(ConfigError::InvalidValue {
            key: "sender_constraint".to_string(),
            value: policy.sender_constraint.as_db_str().to_string(),
            reason: "mTLS sender constraint requires mtls_enabled=true".to_string(),
        });
    }
    Ok(())
}

fn validate_software_statement_key_policy(policy: &PolicyDocument) -> Result<(), ConfigError> {
    let Some(pem) = policy.ssa_jwt_pem.as_deref() else {
        return Ok(());
    };
    let trimmed = pem.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::InvalidValue {
            key: "ssa_jwt_pem".to_string(),
            value: pem.to_string(),
            reason: "must be non-empty when set".to_string(),
        });
    }
    jsonwebtoken::DecodingKey::from_rsa_pem(trimmed.as_bytes()).map_err(|_| {
        ConfigError::InvalidValue {
            key: "ssa_jwt_pem".to_string(),
            value: "<redacted>".to_string(),
            reason:
                "must be an RSA public key PEM usable for RS256 software statement verification"
                    .to_string(),
        }
    })?;
    Ok(())
}

fn validate_policy_acr(policy: &PolicyDocument) -> Result<(), ConfigError> {
    let acr_values_supported = normalize_runtime_policy_list(&policy.acr_values_supported);
    let default_acr = normalize_runtime_policy_text(policy.default_acr.as_deref());
    let local_password_acr = normalize_runtime_policy_text(policy.local_password_acr.as_deref());
    super::try_validate_acr_config(&acr_values_supported, default_acr.as_deref())?;
    super::try_validate_acr_config(&acr_values_supported, local_password_acr.as_deref())
}

fn normalize_runtime_policy_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn normalize_runtime_policy_text(value: Option<&str>) -> Option<String> {
    value
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
}

fn normalize_runtime_policy_url(
    key: &str,
    value: Option<&str>,
) -> Result<Option<String>, ConfigError> {
    value
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(|raw| validate_public_base_url_value(key, &raw).map(|()| raw))
        .transpose()
}

fn policy_allows_grant(policy: &PolicyDocument, grant_type: &str) -> bool {
    policy
        .allowed_grant_types
        .iter()
        .map(|grant| grant.trim())
        .any(|grant| grant.eq_ignore_ascii_case(grant_type))
}
