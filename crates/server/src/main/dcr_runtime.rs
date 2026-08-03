use anyhow::Result;
use std::collections::HashSet;

use aegaeon_server::config::ServerConfig;
use aegaeon_server::dcr::DcrValidationConfig;
use aegaeon_server::dcr_persistence::load_dcr_bearer_token_hash_for_issuer_host;
use aegaeon_server::management::types::PolicyDocument;
use aegaeon_server::runtime_configuration::DatabaseRuntimeConfiguration;
use sqlx::PgPool;

use super::client_runtime::runtime_client_jwt_allowed_algorithm_set;

pub(super) struct DcrRuntime {
    pub(super) enabled: bool,
    pub(super) require_client_jwt_kid: bool,
    pub(super) allowed_algs: HashSet<String>,
    pub(super) validation_config: DcrValidationConfig,
    pub(super) required_bearer_hash: Option<String>,
    pub(super) scope_allowlist: Vec<String>,
}

pub(super) async fn dcr_runtime_for_authority(
    db_pool: &PgPool,
    cfg: &ServerConfig,
    policy: &PolicyDocument,
    database_runtime_config: &DatabaseRuntimeConfiguration,
) -> Result<DcrRuntime> {
    let require_client_jwt_kid = policy.client_jwt_require_kid;
    let allowed_alg_names = &policy.client_jwt_allowed_algs;
    let allowed_algs = runtime_client_jwt_allowed_algorithm_set(allowed_alg_names)?;
    let grant_runtime = cfg.grant_runtime();
    let validation_config = DcrValidationConfig::try_from_policy(
        policy,
        grant_runtime.jwt_bearer_enabled(),
        grant_runtime.token_exchange_enabled(),
        grant_runtime.device_authorization_enabled(),
        cfg.dcr_everparse_runtime_enabled,
        cfg.jose_header_max_len,
    )?;
    let required_bearer_hash =
        dcr_required_bearer_hash_for_authority(db_pool, database_runtime_config).await?;

    Ok(DcrRuntime {
        enabled: policy.dcr_enabled,
        require_client_jwt_kid,
        allowed_algs,
        validation_config,
        required_bearer_hash,
        scope_allowlist: database_runtime_config.state.scope_allowlist.clone(),
    })
}

async fn dcr_required_bearer_hash_for_authority(
    db_pool: &PgPool,
    database_runtime_config: &DatabaseRuntimeConfiguration,
) -> Result<Option<String>> {
    load_dcr_bearer_token_hash_for_issuer_host(db_pool, &database_runtime_config.issuer_host)
        .await
        .map_err(anyhow::Error::from)
}
