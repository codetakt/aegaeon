use std::collections::HashSet;

use crate::config::{valid_jose_header_max_len, valid_ssa_leeway_secs, ConfigError};
use crate::management::types::PolicyDocument;

use super::sender_methods::{
    build_sender_methods_mask, runtime_supported_sender_constrained_method,
    RUNTIME_SUPPORTED_DCR_SENDER_METHODS,
};

#[derive(Clone, Debug)]
pub struct DcrValidationConfig {
    pub(super) require_pkce_for_public: bool,
    pub(super) require_pkce_for_confidential: bool,
    pub(super) require_sender_constrained: bool,
    pub(super) allowed_sender_methods: Vec<String>,
    pub(super) jwt_bearer_enabled: bool,
    pub(super) token_exchange_enabled: bool,
    pub(super) device_code_enabled: bool,
    everparse_runtime_enabled: bool,
    software_statement: SoftwareStatementValidationConfig,
}

#[derive(Clone, Debug)]
pub struct SoftwareStatementValidationConfig {
    pub(in crate::dcr) public_key_pem: Option<String>,
    pub(in crate::dcr) expected_issuer: Option<String>,
    pub(in crate::dcr) expected_audience: Option<String>,
    pub(in crate::dcr) leeway_secs: u64,
    pub(in crate::dcr) jose_header_max_len: usize,
}

impl Default for SoftwareStatementValidationConfig {
    fn default() -> Self {
        Self {
            public_key_pem: None,
            expected_issuer: None,
            expected_audience: None,
            leeway_secs: 120,
            jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
        }
    }
}

impl Default for DcrValidationConfig {
    fn default() -> Self {
        Self {
            require_pkce_for_public: false,
            require_pkce_for_confidential: false,
            require_sender_constrained: false,
            allowed_sender_methods: vec!["dpop".to_string()],
            jwt_bearer_enabled: false,
            token_exchange_enabled: false,
            device_code_enabled: false,
            everparse_runtime_enabled: false,
            software_statement: SoftwareStatementValidationConfig::default(),
        }
    }
}

impl DcrValidationConfig {
    pub fn try_from_policy(
        policy: &PolicyDocument,
        jwt_bearer_enabled: bool,
        token_exchange_enabled: bool,
        device_code_enabled: bool,
        everparse_runtime_enabled: bool,
        jose_header_max_len: usize,
    ) -> Result<Self, ConfigError> {
        let allowed_sender_methods = normalize_allowed_sender_methods(
            "dcr_allowed_sender_methods",
            &policy.dcr_allowed_sender_methods,
        )?;
        let jose_header_max_len_for_validation =
            u64::try_from(jose_header_max_len).map_err(|_| ConfigError::InvalidNumberRange {
                key: "jose_header_max_len".to_string(),
                value: jose_header_max_len.to_string(),
                expectation: "a value in 1..=65536 characters".to_string(),
            })?;
        if !valid_jose_header_max_len(jose_header_max_len_for_validation) {
            return Err(ConfigError::InvalidNumberRange {
                key: "jose_header_max_len".to_string(),
                value: jose_header_max_len.to_string(),
                expectation: "a value in 1..=65536 characters".to_string(),
            });
        }
        if !valid_ssa_leeway_secs(u64::from(policy.ssa_leeway_seconds)) {
            return Err(ConfigError::InvalidNumberRange {
                key: "ssa_leeway_seconds".to_string(),
                value: policy.ssa_leeway_seconds.to_string(),
                expectation: "a value in 0..=300 seconds".to_string(),
            });
        }
        let software_statement = SoftwareStatementValidationConfig {
            public_key_pem: normalize_policy_optional_rsa_public_key_pem(
                "ssa_jwt_pem",
                policy.ssa_jwt_pem.as_deref(),
            )?,
            expected_issuer: normalize_policy_optional_non_empty(
                "ssa_expected_iss",
                policy.ssa_expected_iss.as_deref(),
            )?,
            expected_audience: normalize_policy_optional_non_empty(
                "ssa_expected_aud",
                policy.ssa_expected_aud.as_deref(),
            )?,
            leeway_secs: u64::from(policy.ssa_leeway_seconds),
            jose_header_max_len,
        };

        Ok(Self {
            require_pkce_for_public: policy.dcr_require_pkce_for_public,
            require_pkce_for_confidential: policy.dcr_require_pkce_for_confidential,
            require_sender_constrained: policy.dcr_require_sender_constrained,
            allowed_sender_methods,
            jwt_bearer_enabled,
            token_exchange_enabled,
            device_code_enabled,
            everparse_runtime_enabled,
            software_statement,
        })
    }

    #[must_use]
    pub const fn everparse_runtime_enabled(&self) -> bool {
        self.everparse_runtime_enabled
    }

    #[must_use]
    pub const fn software_statement(&self) -> &SoftwareStatementValidationConfig {
        &self.software_statement
    }
}

fn normalize_policy_optional_non_empty(
    key: &str,
    value: Option<&str>,
) -> Result<Option<String>, ConfigError> {
    value
        .map(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                Err(ConfigError::InvalidValue {
                    key: key.to_string(),
                    value: raw.to_string(),
                    reason: "must be non-empty when set".to_string(),
                })
            } else {
                Ok(trimmed.to_string())
            }
        })
        .transpose()
}

fn normalize_policy_optional_rsa_public_key_pem(
    key: &str,
    value: Option<&str>,
) -> Result<Option<String>, ConfigError> {
    let normalized = normalize_policy_optional_non_empty(key, value)?;
    if let Some(pem) = normalized.as_deref() {
        jsonwebtoken::DecodingKey::from_rsa_pem(pem.as_bytes()).map_err(|_| {
            ConfigError::InvalidValue {
                key: key.to_string(),
                value: "<redacted>".to_string(),
                reason:
                    "must be an RSA public key PEM usable for RS256 software statement verification"
                        .to_string(),
            }
        })?;
    }
    Ok(normalized)
}

fn normalize_allowed_sender_methods(
    key: &str,
    values: &[String],
) -> Result<Vec<String>, ConfigError> {
    let mut methods = values
        .iter()
        .flat_map(|raw| raw.split(','))
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter(|method| !method.is_empty())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    methods.sort();
    if methods.is_empty() {
        return Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: values.join(","),
            reason: "must contain at least one sender-constrained method".to_string(),
        });
    }
    let _ = build_sender_methods_mask(&methods).map_err(|err| ConfigError::InvalidValue {
        key: key.to_string(),
        value: values.join(","),
        reason: err,
    })?;
    if let Some(unimplemented) = methods
        .iter()
        .find(|method| !runtime_supported_sender_constrained_method(method))
    {
        return Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: unimplemented.clone(),
            reason: format!(
                "sender-constrained DCR currently supports only {}",
                RUNTIME_SUPPORTED_DCR_SENDER_METHODS.join(",")
            ),
        });
    }
    Ok(methods)
}
