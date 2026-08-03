use axum::response::Response;
use serde::Deserialize;
use sqlx::PgPool;

mod auth;
mod errors;
mod query;
mod rows;

pub(super) use auth::authenticate_upstream_refresh_caller;

#[derive(Deserialize)]
pub(super) struct UpstreamRefreshQuery {
    pub(super) upstream_issuer: Option<String>,
}

pub(super) struct UpstreamRefreshCaller {
    user_id: String,
    caller_client_id: String,
}

pub(super) struct UpstreamRefreshLink {
    pub(super) account_link_id: uuid::Uuid,
    pub(super) link_env_id: uuid::Uuid,
    pub(super) upstream_issuer: String,
    pub(super) upstream_sub_hash: String,
    pub(super) upstream_refresh_token_generation: i64,
    pub(super) upstream_refresh_token: String,
    pub(super) upstream_connection_id: uuid::Uuid,
    pub(super) upstream_connection_identifier: String,
    pub(super) upstream_client_id: String,
    pub(super) upstream_auth_method: String,
    pub(super) upstream_client_secret: Option<String>,
}

struct AccountLinkIdentity {
    account_link_id: uuid::Uuid,
    environment_id: uuid::Uuid,
    upstream_issuer: String,
    upstream_sub_hash: String,
    refresh_token_generation: i64,
}

struct UpstreamClient {
    connection_id: uuid::Uuid,
    connection_identifier: String,
    client_id: String,
    auth_method: String,
}

pub(super) async fn load_upstream_refresh_link(
    pool: &PgPool,
    caller: &UpstreamRefreshCaller,
    upstream_issuer: Option<&str>,
    issuer_base: &str,
) -> Result<UpstreamRefreshLink, Response> {
    let caller_env_id = query::resolve_caller_environment_id(pool, caller, issuer_base).await?;
    let row = query::load_unique_upstream_refresh_row(
        pool,
        caller,
        caller_env_id,
        upstream_issuer,
        issuer_base,
    )
    .await?;
    let identity = rows::read_link_identity_from_row(&row, issuer_base)?;
    let upstream_refresh_token = rows::open_refresh_token_from_row(&row, &identity, issuer_base)?;
    let client = rows::read_upstream_client_from_row(&row, issuer_base)?;
    let upstream_client_secret =
        rows::open_optional_upstream_client_secret(&row, &identity, &client, issuer_base)?;

    Ok(UpstreamRefreshLink {
        account_link_id: identity.account_link_id,
        link_env_id: identity.environment_id,
        upstream_issuer: identity.upstream_issuer,
        upstream_sub_hash: identity.upstream_sub_hash,
        upstream_refresh_token_generation: identity.refresh_token_generation,
        upstream_refresh_token,
        upstream_connection_id: client.connection_id,
        upstream_connection_identifier: client.connection_identifier,
        upstream_client_id: client.client_id,
        upstream_auth_method: client.auth_method,
        upstream_client_secret,
    })
}
