use std::sync::Arc;

use crate::config::{RuntimeStateNamespace, ServerConfig};
use crate::device_authz::{CsrfTokenStore, DeviceCodeStore, VerificationRateLimiter};
use anyhow::Result;

pub(super) struct DeviceRuntimeStores {
    pub(super) device_code_store: Arc<DeviceCodeStore>,
    pub(super) device_csrf_store: Arc<CsrfTokenStore>,
    pub(super) local_auth_csrf_store: Arc<CsrfTokenStore>,
    pub(super) local_login_rate_limiter: Arc<VerificationRateLimiter>,
    pub(super) device_rate_limiter: Arc<VerificationRateLimiter>,
}

pub(super) fn device_runtime_stores_from_postgres(
    cfg: &ServerConfig,
    database: &crate::authcode::store::PostgresGrantDatabase,
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<DeviceRuntimeStores> {
    Ok(DeviceRuntimeStores {
        device_code_store: Arc::new(DeviceCodeStore::from_postgres(
            database.clone(),
            cfg.device_code_ttl_secs,
            cfg.device_code_poll_interval_secs,
        )?),
        device_csrf_store: Arc::new(CsrfTokenStore::from_postgres(
            database.pool.clone(),
            runtime_state_namespace,
            "device",
        )),
        local_auth_csrf_store: Arc::new(CsrfTokenStore::from_postgres(
            database.pool.clone(),
            runtime_state_namespace,
            "local-auth",
        )),
        local_login_rate_limiter: Arc::new(VerificationRateLimiter::from_postgres(
            database.pool.clone(),
            runtime_state_namespace,
            "local-login",
        )),
        device_rate_limiter: Arc::new(VerificationRateLimiter::from_postgres(
            database.pool.clone(),
            runtime_state_namespace,
            "device",
        )),
    })
}
