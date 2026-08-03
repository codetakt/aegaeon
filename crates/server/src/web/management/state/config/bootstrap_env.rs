use crate::config::{try_env_optional_string, ConfigError};

use super::super::super::hash_support::sha256_array;
use super::super::control_plane_policy::{DEFAULT_MAX_SESSIONS, DEFAULT_SESSION_TTL_SECS};
use super::ManagementConfig;

pub(super) fn try_from_system_bootstrap_env() -> Result<ManagementConfig, ConfigError> {
    if let Some(value) = try_env_optional_string("AEGAEON_MANAGEMENT_COOKIE_SECURE")? {
        return Err(ConfigError::InvalidValue {
            key: "AEGAEON_MANAGEMENT_COOKIE_SECURE".to_string(),
            value,
            reason: "management session cookies are always Secure; remove this legacy bootstrap environment variable".to_string(),
        });
    }

    let bootstrap_token_sha256 = try_env_optional_string("AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN")?
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(|token| sha256_array(token.as_bytes()));

    Ok(ManagementConfig {
        allowed_origins: Vec::new(),
        issuer_base_domain: "aegaeon.cloud".to_string(),
        cookie_secure: true,
        session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
        max_sessions: DEFAULT_MAX_SESSIONS,
        bootstrap_token_sha256,
    })
}
