use sqlx::PgPool;
use std::sync::Arc;

use crate::config::{ConfigError, RuntimeStateNamespace};
use crate::device_authz::VerificationRateLimiter;

use super::config::ManagementConfig;
use super::session_store::ManagementSessionStore;

#[derive(Clone)]
pub struct ManagementState {
    pub cfg: Arc<ManagementConfig>,
    pub(in crate::web::management) sessions: Arc<ManagementSessionStore>,
    pub(in crate::web::management) login_rate_limiter: Arc<VerificationRateLimiter>,
}

impl ManagementState {
    /// Build process-local management state for tests.
    ///
    /// Production code should use [`Self::try_from_env_with_database`] so DB-backed management
    /// policy and shared runtime-state policy are applied.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        let cfg = ManagementConfig::new_process_local_for_tests();
        let sessions = ManagementSessionStore::new_process_local_with_limits(
            cfg.session_ttl_secs,
            cfg.max_sessions,
        );
        Self {
            cfg: Arc::new(cfg),
            sessions: Arc::new(sessions),
            login_rate_limiter: Arc::new(VerificationRateLimiter::new_process_local_for_tests()),
        }
    }

    pub async fn try_from_env_with_database(
        pool: &PgPool,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        let cfg = ManagementConfig::try_from_env_with_database(pool).await?;
        Self::try_from_config(cfg, runtime_state_namespace)
    }

    fn try_from_config(
        cfg: ManagementConfig,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        let sessions = ManagementSessionStore::try_from_config(&cfg, runtime_state_namespace)?;
        Ok(Self {
            cfg: Arc::new(cfg),
            sessions: Arc::new(sessions),
            login_rate_limiter: Arc::new(VerificationRateLimiter::try_from_shared_store_env(
                "AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL",
                "management-login",
                runtime_state_namespace,
            )?),
        })
    }

    #[cfg(test)]
    pub fn cleanup_login_rate_limiter(&self) {
        self.try_cleanup_login_rate_limiter()
            .expect("test management login rate limiter cleanup should succeed");
    }

    pub fn try_cleanup_login_rate_limiter(&self) -> Result<(), String> {
        self.login_rate_limiter.try_cleanup_expired()
    }
}
