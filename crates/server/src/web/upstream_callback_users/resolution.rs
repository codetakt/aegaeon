use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};

use crate::oidc::IdToken;
use crate::upstream::UpstreamAuthRequest;

use super::super::oauth_errors::json_error_with_iss;
use super::super::upstream_callback_exchange::UpstreamCallbackExchange;
use super::account_link::resolve_linked_upstream_callback_user;
use super::jit::resolve_provisioned_upstream_callback_user;
use super::types::UpstreamCallbackUserResolution;

fn upstream_callback_auth_time(id_token: &IdToken, issuer_base: &str) -> Result<i64, Response> {
    let auth_time = id_token.claims.auth_time.unwrap_or(id_token.claims.iat);
    if auth_time < 0 {
        Err(json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "invalid_grant",
            Some("upstream id_token auth_time is invalid"),
            issuer_base,
        ))
    } else {
        Ok(auth_time)
    }
}

pub(in crate::web) async fn resolve_upstream_callback_user(
    tx: &mut Transaction<'_, Postgres>,
    request: &UpstreamAuthRequest,
    exchange: &UpstreamCallbackExchange,
    issuer_base: &str,
    request_id: &str,
) -> Result<UpstreamCallbackUserResolution, Response> {
    let auth_time = upstream_callback_auth_time(&exchange.id_token, issuer_base)?;
    if let Some(linked_user) = resolve_linked_upstream_callback_user(
        tx,
        request,
        &exchange.upstream_sub_hash,
        issuer_base,
        request_id,
    )
    .await?
    {
        return Ok(UpstreamCallbackUserResolution {
            user_id: linked_user.subject,
            local_end_user_id: Some(linked_user.end_user_id),
            auth_time,
        });
    }
    let (user_id, local_end_user_id) = resolve_provisioned_upstream_callback_user(
        tx,
        request,
        &exchange.id_token,
        &exchange.upstream_sub_hash,
        issuer_base,
        request_id,
    )
    .await?;
    Ok(UpstreamCallbackUserResolution {
        user_id,
        local_end_user_id,
        auth_time,
    })
}
