use std::sync::Arc;

use anyhow::Result;
use sqlx::PgPool;
use tracing::info;

use aegaeon_server::config::{BootstrapConfig, ServerConfig};
use aegaeon_server::oidc::OidcConfig;
use aegaeon_server::runtime_configuration::{
    load_database_runtime_configuration, DatabaseRuntimeConfiguration,
};

pub(super) async fn hydrate_database_runtime_config(
    bootstrap_config: BootstrapConfig,
    db_pool: &PgPool,
    issuer_host: &str,
) -> Result<(ServerConfig, DatabaseRuntimeConfiguration)> {
    let runtime_config = load_database_runtime_configuration(db_pool, issuer_host).await?;
    let server_config = bootstrap_config.into_runtime_baseline();
    let server_config = server_config.with_management_policy(&runtime_config.state.policy)?;
    info!(
        issuer_host = %runtime_config.issuer_host,
        issuer_url = %runtime_config.issuer_url,
        configuration_version_id = %runtime_config.active_configuration_version_id,
        "Hydrated runtime configuration from management database"
    );
    Ok((server_config, runtime_config))
}

pub(super) fn runtime_issuer_for_authority(
    database_runtime_config: &DatabaseRuntimeConfiguration,
) -> String {
    database_runtime_config.issuer_url.clone()
}

pub(super) async fn oidc_runtime_from_authority(
    runtime_issuer: &str,
    database_runtime_config: &DatabaseRuntimeConfiguration,
) -> Result<Option<Arc<OidcConfig>>> {
    let config = OidcConfig::from_management_snapshot_async(
        runtime_issuer,
        &database_runtime_config.state.policy,
        &database_runtime_config.runtime_keys,
    )
    .await?;
    Ok(config.map(Arc::new))
}

pub(super) fn validate_runtime_boundaries_for_authority(
    server_config: &ServerConfig,
    oidc_enabled: bool,
    _database_runtime_config: &DatabaseRuntimeConfiguration,
) -> Result<()> {
    server_config.validate_runtime_boundaries_with_key_material(oidc_enabled, false, false)?;
    Ok(())
}

pub(super) fn log_runtime_state_boundary(_server_config: &ServerConfig) {
    info!("runtime shared-store preflight completed");
}
