use aegaeon_jose::{
    algorithms::{Algorithm, CryptoProfile},
    jwt::JwtClaims,
    RequestObjectError,
};
use std::collections::HashSet;
use tracing::warn;

use crate::config::ConfigError;
use crate::util::{JsonObjectParseError, SignedAssertionClaimsError};

use super::metrics;

mod replay;

pub(super) const PRIVATE_KEY_JWT_REPLAY_NAMESPACE: &str = "private-key-jwt:v1";
pub(super) const JWT_BEARER_REPLAY_NAMESPACE: &str = "jwt-bearer:v1";

#[cfg(test)]
pub(super) use replay::jwt_replay_material;
pub(super) use replay::{assertion_replay_ttl_secs, jwt_replay_store_from_env, record_jwt_replay};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAssertionValidationError {
    InvalidAssertion,
    Internal(String),
}

pub type ClientAssertionValidationResult = Result<Option<String>, ClientAssertionValidationError>;

pub(super) fn client_assertion_error_from_jose_header(
    err: JsonObjectParseError,
) -> ClientAssertionValidationError {
    match err {
        JsonObjectParseError::BackendPolicy => ClientAssertionValidationError::Internal(
            "unsupported raw JSON backend for jose-header".to_string(),
        ),
        JsonObjectParseError::DuplicateKey
        | JsonObjectParseError::InvalidJson
        | JsonObjectParseError::TrailingBytes
        | JsonObjectParseError::InvalidShape => ClientAssertionValidationError::InvalidAssertion,
    }
}

fn client_assertion_backend_policy_error(surface: &'static str) -> ClientAssertionValidationError {
    ClientAssertionValidationError::Internal(format!("unsupported raw JSON backend for {surface}"))
}

pub(super) fn signed_assertion_error_result(
    err: SignedAssertionClaimsError,
    surface: &'static str,
) -> ClientAssertionValidationResult {
    match err {
        SignedAssertionClaimsError::BackendPolicy => {
            Err(client_assertion_backend_policy_error(surface))
        }
        SignedAssertionClaimsError::VerificationFailed
        | SignedAssertionClaimsError::ClaimsInvalid => Ok(None),
    }
}

pub(super) fn client_assertion_clock_error(
    context: &'static str,
) -> ClientAssertionValidationError {
    ClientAssertionValidationError::Internal(format!(
        "system clock is outside supported Unix epoch range for {context}"
    ))
}

pub(super) fn jwt_algorithm_name(alg: jsonwebtoken::Algorithm) -> Option<&'static str> {
    match alg {
        jsonwebtoken::Algorithm::RS256 => Some("RS256"),
        jsonwebtoken::Algorithm::RS384 => Some("RS384"),
        jsonwebtoken::Algorithm::RS512 => Some("RS512"),
        jsonwebtoken::Algorithm::PS256 => Some("PS256"),
        jsonwebtoken::Algorithm::PS384 => Some("PS384"),
        jsonwebtoken::Algorithm::PS512 => Some("PS512"),
        jsonwebtoken::Algorithm::ES256 => Some("ES256"),
        jsonwebtoken::Algorithm::ES384 => Some("ES384"),
        _ => None,
    }
}

pub(super) fn client_jwt_algorithm_name(alg: jsonwebtoken::Algorithm) -> Option<&'static str> {
    match alg {
        jsonwebtoken::Algorithm::RS256 => Some("RS256"),
        jsonwebtoken::Algorithm::PS256 => Some("PS256"),
        jsonwebtoken::Algorithm::ES256 => Some("ES256"),
        _ => None,
    }
}

pub(super) fn request_object_error_from_jose_header(
    err: JsonObjectParseError,
) -> RequestObjectError {
    match err {
        JsonObjectParseError::BackendPolicy => {
            RequestObjectError::Internal("jose-header-backend-policy".to_string())
        }
        JsonObjectParseError::DuplicateKey => {
            RequestObjectError::PolicyViolation("duplicate-jose-header-key".to_string())
        }
        JsonObjectParseError::InvalidJson
        | JsonObjectParseError::TrailingBytes
        | JsonObjectParseError::InvalidShape => RequestObjectError::InvalidFormat,
    }
}

fn normalize_client_jwt_allowed_algorithm_names(
    key: &str,
    names: impl IntoIterator<Item = String>,
) -> Result<HashSet<String>, ConfigError> {
    let mut allowed = HashSet::new();
    for raw in names {
        let normalized = raw.trim().to_ascii_uppercase();
        if normalized.is_empty() {
            continue;
        }
        match normalized.as_str() {
            "RS256" | "PS256" => {
                allowed.insert(normalized);
            }
            other => {
                return Err(ConfigError::InvalidValue {
                    key: key.to_string(),
                    value: other.to_string(),
                    reason: "expected RS256 or PS256".to_string(),
                });
            }
        }
    }
    if allowed.is_empty() {
        return Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: "[]".to_string(),
            reason: "must enable at least one supported algorithm".to_string(),
        });
    }
    Ok(allowed)
}

pub(super) fn jwt_algorithm_allowed_by_profile(
    alg: jsonwebtoken::Algorithm,
    crypto_profile: CryptoProfile,
    promoted_rsa: bool,
) -> bool {
    if promoted_rsa
        && matches!(
            alg,
            jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256
        )
    {
        return true;
    }

    // Non-promoted request-object verification dispatches to the compat backend.
    jwt_algorithm_name(alg)
        .and_then(|name| Algorithm::from_string(name).ok())
        .is_some_and(|alg| crypto_profile.allows_on_compat_dispatch(&alg))
}

pub(super) fn require_non_empty_jti<'a>(
    claims: &'a JwtClaims,
    metric_label: &'static str,
    client_id: &str,
) -> Option<&'a str> {
    let jti = claims
        .jti
        .as_deref()
        .map(str::trim)
        .filter(|j| !j.is_empty());
    if jti.is_none() {
        metrics::record_runtime_bcp_noncompliant(metric_label);
        warn!(
            target: "jwks",
            client_id = %client_id,
            "jwt assertion jti missing"
        );
    }
    jti
}

#[derive(Clone, Debug)]
pub struct ClientAssertionRuntimePolicy {
    pub(super) allowed_algorithms: HashSet<String>,
    pub(super) require_kid: bool,
    pub(super) jwt_leeway_secs: u64,
    pub(super) jose_header_max_len: usize,
    pub(super) private_key_jwt_replay_window_secs: i64,
    pub(super) jwt_bearer_replay_window_secs: i64,
}

impl Default for ClientAssertionRuntimePolicy {
    fn default() -> Self {
        Self {
            allowed_algorithms: ["RS256".to_string()].into_iter().collect(),
            require_kid: false,
            jwt_leeway_secs: 60,
            jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
            private_key_jwt_replay_window_secs: 300,
            jwt_bearer_replay_window_secs: 300,
        }
    }
}

impl ClientAssertionRuntimePolicy {
    pub fn try_new(
        allowed_algorithms: impl IntoIterator<Item = String>,
        require_kid: bool,
        jwt_leeway_secs: u64,
        jose_header_max_len: usize,
        private_key_jwt_replay_window_secs: i64,
        jwt_bearer_replay_window_secs: i64,
    ) -> Result<Self, ConfigError> {
        if !crate::config::valid_jwt_leeway_secs(jwt_leeway_secs) {
            return Err(ConfigError::InvalidNumberRange {
                key: "jwt_leeway_seconds".to_string(),
                value: jwt_leeway_secs.to_string(),
                expectation: "a value in 0..=300 seconds".to_string(),
            });
        }
        let allowed_algorithms = normalize_client_jwt_allowed_algorithm_names(
            "client_jwt_allowed_algs",
            allowed_algorithms,
        )?;
        let jose_header_max_len_for_validation =
            u64::try_from(jose_header_max_len).map_err(|_| ConfigError::InvalidNumberRange {
                key: "jose_header_max_len".to_string(),
                value: jose_header_max_len.to_string(),
                expectation: "a value in 1..=65536 characters".to_string(),
            })?;
        if !crate::config::valid_jose_header_max_len(jose_header_max_len_for_validation) {
            return Err(ConfigError::InvalidNumberRange {
                key: "jose_header_max_len".to_string(),
                value: jose_header_max_len.to_string(),
                expectation: "a value in 1..=65536 characters".to_string(),
            });
        }
        let private_key_jwt_replay_window_secs = replay::validate_client_assertion_replay_window(
            "pkjwt_jti_window_seconds",
            private_key_jwt_replay_window_secs,
        )?;
        let jwt_bearer_replay_window_secs = replay::validate_client_assertion_replay_window(
            "jwt_bearer_jti_window_seconds",
            jwt_bearer_replay_window_secs,
        )?;
        Ok(Self {
            allowed_algorithms,
            require_kid,
            jwt_leeway_secs,
            jose_header_max_len,
            private_key_jwt_replay_window_secs,
            jwt_bearer_replay_window_secs,
        })
    }
}
