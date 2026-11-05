use std::sync::Arc;

use crate::config::{RuntimeStateNamespace, ServerConfig};
use crate::metrics_integration::MetricsIntegration;
use crate::par::{ParEndpoint, ParStore};
use crate::request_object_store::RequestObjectJtiStore;
use crate::stepup::StepUpStore;
use anyhow::Result;

pub(super) struct ProtocolRuntimeStores {
    pub(super) par_endpoint: Arc<ParEndpoint>,
    pub(super) par_store: Arc<ParStore>,
    pub(super) request_object_jti_store: Arc<RequestObjectJtiStore>,
    pub(super) stepup_store: Arc<StepUpStore>,
}

pub(super) fn protocol_runtime_stores_from_postgres(
    cfg: &ServerConfig,
    database: &crate::authcode::store::PostgresGrantDatabase,
    metrics: Arc<MetricsIntegration>,
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<ProtocolRuntimeStores> {
    let par_store = Arc::new(ParStore::from_postgres(
        cfg.par_expires_in_secs,
        database.clone(),
    )?);
    let par_endpoint = Arc::new(ParEndpoint::new(metrics, par_store.clone()));
    let request_object_jti_store = Arc::new(RequestObjectJtiStore::from_postgres(
        cfg.request_object_jti_ttl_secs,
        database.clone(),
    )?);
    let stepup_store = Arc::new(StepUpStore::from_postgres(
        database.pool.clone(),
        runtime_state_namespace,
        cfg.stepup_challenge_ttl_secs,
    )?);

    Ok(ProtocolRuntimeStores {
        par_endpoint,
        par_store,
        request_object_jti_store,
        stepup_store,
    })
}
