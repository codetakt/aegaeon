use std::sync::Arc;

use aegaeon_server::config::{RuntimeStateNamespace, ServerConfig};
use aegaeon_server::device_authz::{CsrfTokenStore, DeviceCodeStore, VerificationRateLimiter};
use anyhow::Result;

pub(super) struct DeviceRuntimeStores {
    pub(super) device_code_store: Arc<DeviceCodeStore>,
    pub(super) device_csrf_store: Arc<CsrfTokenStore>,
    pub(super) local_auth_csrf_store: Arc<CsrfTokenStore>,
    pub(super) local_login_rate_limiter: Arc<VerificationRateLimiter>,
    pub(super) device_rate_limiter: Arc<VerificationRateLimiter>,
}

pub(super) fn device_runtime_stores_from_shared_env(
    cfg: &ServerConfig,
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<DeviceRuntimeStores> {
    Ok(DeviceRuntimeStores {
        device_code_store: Arc::new(DeviceCodeStore::try_from_shared_store_env_with_policy(
            cfg.device_code_ttl_secs,
            cfg.device_code_poll_interval_secs,
            runtime_state_namespace,
        )?),
        device_csrf_store: Arc::new(CsrfTokenStore::try_from_shared_store_env(
            "AEGAEON_DEVICE_CSRF_REDIS_URL",
            "device",
            runtime_state_namespace,
        )?),
        local_auth_csrf_store: Arc::new(CsrfTokenStore::try_from_shared_store_env(
            "AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL",
            "local-auth",
            runtime_state_namespace,
        )?),
        local_login_rate_limiter: Arc::new(VerificationRateLimiter::try_from_shared_store_env(
            "AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL",
            "local-login",
            runtime_state_namespace,
        )?),
        device_rate_limiter: Arc::new(VerificationRateLimiter::try_from_shared_store_env(
            "AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL",
            "device",
            runtime_state_namespace,
        )?),
    })
}
