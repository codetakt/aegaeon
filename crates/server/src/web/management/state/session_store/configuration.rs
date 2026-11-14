#[cfg(test)]
use crate::config::require_shared_runtime_store_url;
use crate::config::{ConfigError, RuntimeStateNamespace};

use super::super::config::ManagementConfig;
#[cfg(test)]
use super::super::control_plane_policy::MAX_SESSION_TTL_SECS;
#[cfg(test)]
use super::super::redis_sessions::RedisManagementSessionBackend;
#[cfg(test)]
use super::in_memory::new_in_memory_backend;
#[cfg(test)]
use super::MANAGEMENT_SESSION_REDIS_URL_ENV;
use super::{ManagementSessionBackend, ManagementSessionStore};

impl ManagementSessionStore {
    pub(in crate::web::management) fn from_postgres(
        cfg: &ManagementConfig,
        pool: sqlx::PgPool,
        namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        use super::super::control_plane_policy::{
            valid_management_max_sessions, valid_management_session_ttl_secs,
        };
        if !valid_management_session_ttl_secs(cfg.session_ttl_secs)
            || !valid_management_max_sessions(cfg.max_sessions)
        {
            return Err(ConfigError::InvalidValue {
                key: "management session policy".into(),
                value: "[database]".into(),
                reason: "invalid session lifetime or capacity".into(),
            });
        }
        Ok(Self {
            diagnostics: Default::default(),
            backend: ManagementSessionBackend::Postgres(
                super::postgres::PostgresManagementSessions::new(
                    pool,
                    namespace.flow_namespace("management", "session"),
                ),
            ),
            session_ttl_secs: cfg.session_ttl_secs,
            max_sessions: cfg.max_sessions,
        })
    }

    #[cfg(test)]
    pub(in crate::web::management) fn new_process_local_with_limits(
        ttl_secs: u64,
        max_sessions: usize,
    ) -> Self {
        Self {
            diagnostics: Default::default(),
            backend: new_in_memory_backend(),
            session_ttl_secs: ttl_secs.clamp(1, MAX_SESSION_TTL_SECS),
            max_sessions: max_sessions.max(1),
        }
    }

    #[cfg(test)]
    pub(in crate::web::management) fn try_from_config(
        cfg: &ManagementConfig,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        let url = require_shared_runtime_store_url(
            "management session store",
            MANAGEMENT_SESSION_REDIS_URL_ENV,
        )?;
        let backend = RedisManagementSessionBackend::new(url.as_str(), runtime_state_namespace)
            .map_err(|err| ConfigError::InvalidValue {
                key: url.env_key().to_string(),
                value: "[redacted]".to_string(),
                reason: err.to_string(),
            })?;
        tracing::info!("management session store backend: redis");
        Ok(Self {
            diagnostics: Default::default(),
            backend: ManagementSessionBackend::Redis(backend),
            session_ttl_secs: cfg.session_ttl_secs,
            max_sessions: cfg.max_sessions.max(1),
        })
    }
}
