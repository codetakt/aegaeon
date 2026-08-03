use super::super::oauth_errors::json_error_with_iss;
use super::super::upstream_callback_exchange::UpstreamCallbackExchange;
use super::super::upstream_refresh_token_envelope::{
    seal_upstream_refresh_token, upstream_refresh_token_envelope_error_response,
};
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Row, Transaction};

use crate::upstream::UpstreamAuthRequest;

struct CallbackRefreshLinkState {
    account_link_id: uuid::Uuid,
    connection_id: uuid::Uuid,
    generation: i64,
}

async fn load_callback_refresh_link_state(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: uuid::Uuid,
    upstream_issuer: &str,
    upstream_sub_hash: &str,
    issuer_base: &str,
) -> Result<CallbackRefreshLinkState, Response> {
    let row = sqlx::query(
        r"
SELECT id, connection_id, upstream_refresh_token_generation
FROM aegaeon.account_links
WHERE environment_id = $1
  AND upstream_issuer = $2
  AND upstream_sub_hash = $3
        ",
    )
    .bind(environment_id)
    .bind(upstream_issuer)
    .bind(upstream_sub_hash)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("failed to load upstream account link for refresh token persistence"),
            issuer_base,
        )
    })?
    .ok_or_else(|| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("upstream account link not found for refresh token persistence"),
            issuer_base,
        )
    })?;

    Ok(CallbackRefreshLinkState {
        account_link_id: row.try_get("id").map_err(|_| {
            json_error_with_iss(
                StatusCode::BAD_GATEWAY,
                "server_error",
                Some("upstream account link row is corrupted"),
                issuer_base,
            )
        })?,
        connection_id: row.try_get("connection_id").map_err(|_| {
            json_error_with_iss(
                StatusCode::BAD_GATEWAY,
                "server_error",
                Some("upstream account link row is corrupted"),
                issuer_base,
            )
        })?,
        generation: row
            .try_get("upstream_refresh_token_generation")
            .map_err(|_| {
                json_error_with_iss(
                    StatusCode::BAD_GATEWAY,
                    "server_error",
                    Some("upstream account link row is corrupted"),
                    issuer_base,
                )
            })?,
    })
}

fn next_callback_refresh_generation(current: i64, issuer_base: &str) -> Result<i64, Response> {
    current.checked_add(1).ok_or_else(|| {
        json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("upstream refresh token generation overflow"),
            issuer_base,
        )
    })
}

pub(in crate::web) async fn persist_upstream_callback_refresh_token(
    tx: &mut Transaction<'_, Postgres>,
    request: &UpstreamAuthRequest,
    exchange: &UpstreamCallbackExchange,
    issuer_base: &str,
) -> Result<(), Response> {
    let Some(refresh_token) = exchange.token_response.refresh_token.as_ref() else {
        return Ok(());
    };
    let context = request.managed_connection_context();
    let link_state = load_callback_refresh_link_state(
        tx,
        context.environment_id,
        request.issuer.as_str(),
        exchange.upstream_sub_hash.as_str(),
        issuer_base,
    )
    .await?;
    if link_state.connection_id != context.connection_id {
        return Err(json_error_with_iss(
            StatusCode::FORBIDDEN,
            "access_denied",
            Some("upstream account link is associated with another connection"),
            issuer_base,
        ));
    }
    let next_generation = next_callback_refresh_generation(link_state.generation, issuer_base)?;
    let encrypted_refresh_token = seal_upstream_refresh_token(
        refresh_token,
        context.environment_id,
        request.issuer.as_str(),
        exchange.upstream_sub_hash.as_str(),
        context.connection_id,
        next_generation,
    )
    .map_err(|error| {
        upstream_refresh_token_envelope_error_response(
            error,
            "failed to encrypt upstream refresh token",
            issuer_base,
        )
    })?;
    let result = sqlx::query(
        "UPDATE aegaeon.account_links \
         SET upstream_refresh_token_encrypted = $1, \
             upstream_refresh_token_connection_id = $2, \
             upstream_refresh_token_generation = $3, \
             last_used_at = now() \
         WHERE id = $4 \
           AND environment_id = $5 \
           AND upstream_issuer = $6 \
           AND upstream_sub_hash = $7 \
           AND connection_id = $2 \
           AND upstream_refresh_token_generation = $8",
    )
    .bind(encrypted_refresh_token)
    .bind(context.connection_id)
    .bind(next_generation)
    .bind(link_state.account_link_id)
    .bind(context.environment_id)
    .bind(&request.issuer)
    .bind(&exchange.upstream_sub_hash)
    .bind(link_state.generation)
    .execute(&mut **tx)
    .await
    .map_err(|_| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("failed to persist upstream refresh token"),
            issuer_base,
        )
    })?;
    if result.rows_affected() == 0 {
        return Err(json_error_with_iss(
            StatusCode::CONFLICT,
            "invalid_grant",
            Some("upstream refresh token generation is stale"),
            issuer_base,
        ));
    }
    Ok(())
}
