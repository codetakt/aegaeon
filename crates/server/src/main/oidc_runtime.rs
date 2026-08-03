use std::sync::Arc;

use aegaeon_server::authcode::TokenValidator;
use aegaeon_server::config::RuntimeStateNamespace;
use aegaeon_server::oidc::{OidcConfig, OidcSessionStore, UserinfoEndpoint};
use anyhow::Result;
use sqlx::PgPool;

pub(super) fn oidc_sessions_from_shared_env(
    oidc: Option<&OidcConfig>,
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<Option<OidcSessionStore>> {
    oidc.map(|cfg| {
        OidcSessionStore::try_new_from_shared_store_env_with_ttl_secs(
            cfg.logout_session_ttl_secs,
            runtime_state_namespace,
        )
    })
    .transpose()
    .map_err(anyhow::Error::from)
}

pub(super) fn effective_issuer(runtime_issuer: &str, oidc: Option<&OidcConfig>) -> String {
    oidc.map_or_else(|| runtime_issuer.to_string(), |cfg| cfg.issuer.clone())
}

pub(super) fn userinfo_endpoint_for_oidc_runtime(
    oidc: Option<&OidcConfig>,
    token_validator: &TokenValidator,
    db_pool: &PgPool,
    issuer: &str,
) -> Option<Arc<UserinfoEndpoint>> {
    oidc.filter(|cfg| cfg.userinfo_enabled).map(|_| {
        Arc::new(UserinfoEndpoint::new(
            token_validator.clone(),
            db_pool.clone(),
            issuer.to_string(),
        ))
    })
}
