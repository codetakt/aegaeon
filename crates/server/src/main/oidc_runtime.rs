use std::sync::Arc;

use crate::authcode::store::PostgresGrantDatabase;
use crate::authcode::TokenValidator;
use crate::oidc::{OidcConfig, OidcSessionStore, UserinfoEndpoint};
use anyhow::Result;
use sqlx::PgPool;

pub(super) fn oidc_sessions_from_postgres(
    oidc: Option<&OidcConfig>,
    database: &PostgresGrantDatabase,
) -> Result<Option<OidcSessionStore>> {
    oidc.map(|cfg| OidcSessionStore::from_postgres(cfg.logout_session_ttl_secs, database.clone()))
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
