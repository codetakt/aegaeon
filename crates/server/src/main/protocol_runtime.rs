use std::sync::Arc;

use aegaeon_server::config::{RuntimeStateNamespace, ServerConfig};
use aegaeon_server::metrics_integration::MetricsIntegration;
use aegaeon_server::par::{ParEndpoint, ParStore};
use aegaeon_server::request_object_store::RequestObjectJtiStore;
use aegaeon_server::stepup::StepUpStore;
use anyhow::Result;

pub(super) struct ProtocolRuntimeStores {
    pub(super) par_endpoint: Arc<ParEndpoint>,
    pub(super) par_store: Arc<ParStore>,
    pub(super) request_object_jti_store: Arc<RequestObjectJtiStore>,
    pub(super) stepup_store: Arc<StepUpStore>,
}

pub(super) fn protocol_runtime_stores_from_shared_env(
    cfg: &ServerConfig,
    metrics: Arc<MetricsIntegration>,
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<ProtocolRuntimeStores> {
    let par_store = Arc::new(ParStore::try_new_from_shared_store_env_with_expires_in(
        cfg.par_expires_in_secs,
        runtime_state_namespace,
    )?);
    let par_endpoint = Arc::new(ParEndpoint::new(metrics, par_store.clone()));
    let request_object_jti_store = Arc::new(
        RequestObjectJtiStore::try_from_shared_store_env_with_ttl_secs(
            cfg.request_object_jti_ttl_secs,
            runtime_state_namespace,
        )?,
    );
    let stepup_store = Arc::new(StepUpStore::try_from_shared_store_env_with_ttl_secs(
        cfg.stepup_challenge_ttl_secs,
        runtime_state_namespace,
    )?);

    Ok(ProtocolRuntimeStores {
        par_endpoint,
        par_store,
        request_object_jti_store,
        stepup_store,
    })
}
