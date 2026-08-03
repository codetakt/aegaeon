use aegaeon_server::client_registry::ClientRegistry;
use aegaeon_server::runtime_authority::RuntimeAuthorityState;
use aegaeon_server::runtime_configuration::DatabaseRuntimeConfiguration;
use anyhow::Result;
use sqlx::PgPool;

use super::client_runtime::hydrate_runtime_clients_for_authority;

#[derive(Clone)]
pub(super) struct RuntimeSyncPlan {
    pub(super) config_monitor_interval_secs: u64,
}

pub(super) async fn prepare_runtime_sync_for_authority(
    db_pool: &PgPool,
    database_runtime_config: &DatabaseRuntimeConfiguration,
    runtime_authority: &RuntimeAuthorityState,
    clients: &ClientRegistry,
) -> Result<RuntimeSyncPlan> {
    let policy = &database_runtime_config.state.policy;
    let config_monitor_interval_secs = u64::from(policy.runtime_config_monitor_interval_seconds);

    hydrate_runtime_clients_for_authority(
        db_pool,
        database_runtime_config,
        runtime_authority,
        clients,
    )
    .await?;

    Ok(RuntimeSyncPlan {
        config_monitor_interval_secs,
    })
}
