use sqlx::PgPool;

use crate::config::ConfigError;

use super::super::control_plane_policy::{
    load_control_plane_policy, normalize_control_plane_allowed_origins,
    normalize_control_plane_issuer_base_domain, valid_management_api_key_expiration_days,
    valid_management_max_sessions, valid_management_session_ttl_secs, ControlPlanePolicy,
};
#[cfg(test)]
use super::super::control_plane_policy::{DEFAULT_MAX_SESSIONS, DEFAULT_SESSION_TTL_SECS};
use super::bootstrap_env::try_from_system_bootstrap_env;
use super::ManagementConfig;

impl ManagementConfig {
    /// Build management configuration for tests without consulting startup environment.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        Self {
            allowed_origins: Vec::new(),
            issuer_base_domain: "aegaeon.cloud".to_string(),
            cookie_secure: true,
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            max_sessions: DEFAULT_MAX_SESSIONS,
            bootstrap_token_sha256: None,
        }
    }

    pub(in crate::web::management) fn try_from_system_bootstrap_env() -> Result<Self, ConfigError> {
        try_from_system_bootstrap_env()
    }

    pub(in crate::web::management) async fn try_from_env_with_database(
        pool: &PgPool,
    ) -> Result<Self, ConfigError> {
        let cfg = Self::try_from_system_bootstrap_env()?;
        cfg.with_control_plane_policy(load_control_plane_policy(pool).await?)
    }

    pub(in crate::web::management) fn with_control_plane_policy(
        mut self,
        policy: ControlPlanePolicy,
    ) -> Result<Self, ConfigError> {
        if !valid_management_session_ttl_secs(policy.session_ttl_secs) {
            return Err(ConfigError::InvalidNumberRange {
                key: "management_session_ttl_seconds".to_string(),
                value: policy.session_ttl_secs.to_string(),
                expectation: "a value in 1..=86400 seconds".to_string(),
            });
        }
        if !valid_management_max_sessions(policy.max_sessions) {
            return Err(ConfigError::InvalidNumberRange {
                key: "management_max_sessions".to_string(),
                value: policy.max_sessions.to_string(),
                expectation: "a value in 1..=1000000 sessions".to_string(),
            });
        }
        if !valid_management_api_key_expiration_days(policy.api_key_default_expiration_days)
            || !valid_management_api_key_expiration_days(policy.api_key_max_expiration_days)
            || policy.api_key_default_expiration_days > policy.api_key_max_expiration_days
        {
            return Err(ConfigError::InvalidNumberRange {
                key: "management_api_key_expiration_days".to_string(),
                value: policy.api_key_default_expiration_days.to_string(),
                expectation: "a default/max pair in 1..=365 days with default <= max".to_string(),
            });
        }
        self.allowed_origins = normalize_control_plane_allowed_origins(policy.allowed_origins)?;
        self.issuer_base_domain =
            normalize_control_plane_issuer_base_domain(policy.issuer_base_domain)?;
        self.session_ttl_secs = policy.session_ttl_secs;
        self.max_sessions = policy.max_sessions;
        Ok(self)
    }
}
