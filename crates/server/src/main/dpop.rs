use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

use aegaeon_server::config::{
    require_shared_runtime_store_url, RuntimeStateNamespace, ServerConfig,
};
use aegaeon_server::middleware::{dpop::DpopMiddleware, DpopNonceStore};

fn dpop_replay_ttl(iat_window_secs: u64) -> Result<Duration> {
    DpopMiddleware::minimum_replay_ttl(iat_window_secs)
        .map_err(|err| anyhow::anyhow!("DPoP replay TTL is outside representable time: {err:?}"))
}

fn dpop_nonce_store_from_shared_store_env(
    namespace: &RuntimeStateNamespace,
    nonce_ttl: Duration,
) -> Result<Arc<DpopNonceStore>> {
    let url = require_shared_runtime_store_url("DPoP nonce store", "AEGAEON_DPOP_NONCE_REDIS_URL")?;
    info!("DPoP nonce store backend: redis ({})", url.env_key());
    DpopNonceStore::redis(
        url.as_str(),
        namespace.replay_namespace("dpop-nonce"),
        nonce_ttl,
    )
    .map(Arc::new)
    .map_err(|err| anyhow::anyhow!(err.to_string()))
}

pub(super) fn dpop_middleware_from_shared_store_env(
    cfg: &ServerConfig,
    issuer: &str,
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<DpopMiddleware> {
    let namespace = runtime_state_namespace.replay_namespace("dpop");
    let replay_ttl = dpop_replay_ttl(cfg.dpop_iat_window_secs)?;
    let middleware = DpopMiddleware::try_from_shared_store_env(
        namespace,
        issuer.to_string(),
        replay_ttl,
        runtime_state_namespace,
    )?
    .with_iat_window_secs(cfg.dpop_iat_window_secs);
    let middleware = middleware.with_jose_header_max_len(cfg.jose_header_max_len);
    if cfg.require_dpop_nonce {
        let nonce_ttl_secs = cfg.dpop_nonce_ttl_secs;
        let nonce_store = dpop_nonce_store_from_shared_store_env(
            runtime_state_namespace,
            Duration::from_secs(nonce_ttl_secs),
        )?;
        info!("DPoP nonce enforcement enabled (TTL={nonce_ttl_secs}s)");
        Ok(middleware.with_nonce_store(nonce_store))
    } else {
        Ok(middleware)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpop_replay_ttl_covers_the_supported_acceptance_horizon() {
        for window in [1, 30, aegaeon_server::config::MAX_DPOP_IAT_WINDOW_SECS] {
            assert_eq!(
                dpop_replay_ttl(window).ok(),
                Some(Duration::from_secs(
                    2 * aegaeon_server::config::MAX_DPOP_IAT_WINDOW_SECS + 1
                ))
            );
        }
        assert!(dpop_replay_ttl(u64::MAX).is_err());
    }
}
