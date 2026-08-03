use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};

use crate::upstream::UpstreamAuthRequest;

use super::super::oauth_errors::json_error_with_iss;
use super::super::upstream_users::{load_linked_upstream_user, UpstreamResolvedUser};
use super::audit::record_upstream_account_link_audit;

pub(in crate::web) const UPSTREAM_ACCOUNT_LINK_UPSERT_SQL: &str = r"
INSERT INTO aegaeon.account_links (environment_id, connection_id, upstream_issuer, upstream_sub_hash, end_user_id)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (environment_id, upstream_issuer, upstream_sub_hash) DO UPDATE
SET last_used_at = now()
WHERE aegaeon.account_links.end_user_id = EXCLUDED.end_user_id
  AND aegaeon.account_links.connection_id = EXCLUDED.connection_id
";

pub(super) async fn upsert_upstream_account_link(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: uuid::Uuid,
    connection_id: uuid::Uuid,
    upstream_issuer: &str,
    upstream_sub_hash: &str,
    end_user_id: uuid::Uuid,
    issuer_base: &str,
) -> Result<(), Response> {
    let result = sqlx::query(UPSTREAM_ACCOUNT_LINK_UPSERT_SQL)
        .bind(environment_id)
        .bind(connection_id)
        .bind(upstream_issuer)
        .bind(upstream_sub_hash)
        .bind(end_user_id)
        .execute(&mut **tx)
        .await
        .map_err(|_| {
            json_error_with_iss(
                StatusCode::BAD_GATEWAY,
                "server_error",
                Some("failed to persist upstream account link"),
                issuer_base,
            )
        })?;

    if result.rows_affected() == 0 {
        return Err(json_error_with_iss(
            StatusCode::FORBIDDEN,
            "access_denied",
            Some("upstream account link is associated with another user or connection"),
            issuer_base,
        ));
    }

    Ok(())
}

async fn touch_upstream_account_link(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: uuid::Uuid,
    upstream_issuer: &str,
    upstream_sub_hash: &str,
    issuer_base: &str,
) -> Result<(), Response> {
    let result = sqlx::query(
        "UPDATE aegaeon.account_links SET last_used_at = now() \
         WHERE environment_id = $1 AND upstream_issuer = $2 AND upstream_sub_hash = $3",
    )
    .bind(environment_id)
    .bind(upstream_issuer)
    .bind(upstream_sub_hash)
    .execute(&mut **tx)
    .await
    .map_err(|_| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("failed to update upstream account link"),
            issuer_base,
        )
    })?;

    if result.rows_affected() == 0 {
        return Err(json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("upstream account link disappeared"),
            issuer_base,
        ));
    }

    Ok(())
}

pub(super) async fn resolve_linked_upstream_callback_user(
    tx: &mut Transaction<'_, Postgres>,
    request: &UpstreamAuthRequest,
    upstream_sub_hash: &str,
    issuer_base: &str,
    request_id: &str,
) -> Result<Option<UpstreamResolvedUser>, Response> {
    let context = request.managed_connection_context();
    let linked_user = load_linked_upstream_user(
        tx,
        context.environment_id,
        &request.issuer,
        upstream_sub_hash,
    )
    .await
    .map_err(|_| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("failed to load linked upstream user"),
            issuer_base,
        )
    })?;
    if let Some(linked_user) = linked_user {
        if linked_user.account_link_connection_id != Some(context.connection_id) {
            return Err(json_error_with_iss(
                StatusCode::FORBIDDEN,
                "access_denied",
                Some("upstream account link is associated with another connection"),
                issuer_base,
            ));
        }
        if linked_user.status == "SUSPENDED" {
            return Err(json_error_with_iss(
                StatusCode::FORBIDDEN,
                "access_denied",
                Some("linked upstream user is blocked"),
                issuer_base,
            ));
        }
        record_upstream_account_link_audit(
            tx,
            request,
            &linked_user.subject,
            upstream_sub_hash,
            "upstream.account_link.used.v1",
            issuer_base,
            request_id,
        )
        .await?;
        touch_upstream_account_link(
            tx,
            context.environment_id,
            &request.issuer,
            upstream_sub_hash,
            issuer_base,
        )
        .await?;
        Ok(Some(linked_user))
    } else {
        Ok(None)
    }
}
