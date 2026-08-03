use crate::config::{require_shared_runtime_store_url, ConfigError, RuntimeStateNamespace};

use super::super::config::ManagementConfig;
#[cfg(test)]
use super::super::control_plane_policy::MAX_SESSION_TTL_SECS;
use super::super::redis_sessions::RedisManagementSessionBackend;
#[cfg(test)]
use super::in_memory::new_in_memory_backend;
use super::{ManagementSessionBackend, ManagementSessionStore, MANAGEMENT_SESSION_REDIS_URL_ENV};

impl ManagementSessionStore {
    #[cfg(test)]
    pub(in crate::web::management) fn new_process_local_with_limits(
        ttl_secs: u64,
        max_sessions: usize,
    ) -> Self {
        Self {
            backend: new_in_memory_backend(),
            session_ttl_secs: ttl_secs.clamp(1, MAX_SESSION_TTL_SECS),
            max_sessions: max_sessions.max(1),
        }
    }

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
            backend: ManagementSessionBackend::Redis(backend),
            session_ttl_secs: cfg.session_ttl_secs,
            max_sessions: cfg.max_sessions.max(1),
        })
    }
}
