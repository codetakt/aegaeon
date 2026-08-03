use anyhow::Result;
use std::collections::HashSet;
use tracing::info;

use aegaeon_server::client_registry::{
    ClientAssertionRuntimePolicy, ClientRegistry, JwksRuntimePolicy,
};
use aegaeon_server::config::{RuntimeStateNamespace, ServerConfig};
use aegaeon_server::management::types::PolicyDocument;
use aegaeon_server::runtime_authority::RuntimeAuthorityState;
use aegaeon_server::runtime_configuration::DatabaseRuntimeConfiguration;
use sqlx::PgPool;

fn runtime_client_jwt_alg(raw: &str) -> Result<Option<String>> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "" => Ok(None),
        "RS256" => Ok(Some("RS256".to_string())),
        other => Err(anyhow::anyhow!(
            "client_jwt_allowed_algs contains unsupported algorithm {other:?}"
        )),
    }
}

fn runtime_client_jwt_allowed_algorithms(algorithm_names: &[String]) -> Result<Vec<String>> {
    let selected = algorithm_names
        .iter()
        .map(|alg| runtime_client_jwt_alg(alg))
        .collect::<Result<Vec<_>>>()?;
    Ok(selected.into_iter().flatten().collect())
}

pub(super) fn runtime_client_jwt_allowed_algorithm_set(
    algorithm_names: &[String],
) -> Result<HashSet<String>> {
    let allowed = runtime_client_jwt_allowed_algorithms(algorithm_names)?
        .into_iter()
        .collect::<HashSet<_>>();
    if allowed.is_empty() {
        Err(anyhow::anyhow!(
            "client JWT allowed algorithms leave no algorithms enabled for the active crypto profile"
        ))
    } else {
        Ok(allowed)
    }
}

pub(super) fn client_registry_for_runtime_authority(
    policy: &PolicyDocument,
    cfg: &ServerConfig,
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<ClientRegistry> {
    client_registry_from_management_policy(policy, cfg, runtime_state_namespace)
}

pub(super) async fn hydrate_runtime_clients_for_authority(
    db_pool: &PgPool,
    database_runtime_config: &DatabaseRuntimeConfiguration,
    runtime_authority: &RuntimeAuthorityState,
    clients: &ClientRegistry,
) -> Result<()> {
    let synchronized = runtime_authority
        .try_synchronize_client_projection_from_database(db_pool, clients)
        .await?;
    log_runtime_client_hydration(
        &database_runtime_config.issuer_host,
        synchronized.synchronized_client_count(),
    );
    Ok(())
}

fn log_runtime_client_hydration(issuer_host: &str, hydrated: usize) {
    info!(
        issuer_host = %issuer_host,
        "Hydrated {hydrated} database-backed OAuth clients into issuer-scoped runtime registry"
    );
}

fn client_registry_from_management_policy(
    policy: &PolicyDocument,
    cfg: &ServerConfig,
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<ClientRegistry> {
    let allowed_algorithms =
        runtime_client_jwt_allowed_algorithms(&policy.client_jwt_allowed_algs)?;
    let client_assertion_policy = ClientAssertionRuntimePolicy::try_new(
        allowed_algorithms,
        policy.client_jwt_require_kid,
        cfg.jwt_runtime().leeway_secs(),
        cfg.jose_header_max_len,
        cfg.pkjwt_jti_window_secs,
        cfg.jwt_bearer_jti_window_secs,
    )
    .map_err(anyhow::Error::from)?;
    let jwks_runtime_policy = JwksRuntimePolicy::try_from_management_policy(policy)?;

    ClientRegistry::from_shared_store_env_with_runtime_policy(
        client_assertion_policy,
        jwks_runtime_policy,
        runtime_state_namespace,
    )
    .map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_jwt_algorithm_selection_is_rs256_only() -> Result<()> {
        assert_eq!(
            runtime_client_jwt_alg(" rs256 ")?,
            Some("RS256".to_string())
        );
        assert!(runtime_client_jwt_alg("ES256").is_err());
        assert!(runtime_client_jwt_alg("HS256").is_err());
        Ok(())
    }

    #[test]
    fn client_jwt_algorithm_set_fails_closed_when_profile_filters_everything() -> Result<()> {
        let err = runtime_client_jwt_allowed_algorithm_set(&[String::new()])
            .err()
            .ok_or_else(|| anyhow::anyhow!("empty runtime algorithm set must fail closed"))?;
        assert!(err
            .to_string()
            .contains("leave no algorithms enabled for the active crypto profile"));
        Ok(())
    }
}
