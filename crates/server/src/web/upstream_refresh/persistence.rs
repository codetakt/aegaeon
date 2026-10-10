use super::super::upstream_refresh_token_envelope::{
    seal_upstream_refresh_token, upstream_refresh_token_envelope_error_response,
};
use super::*;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

fn persistence_error(issuer_base: &str) -> Response {
    json_error_with_iss(
        StatusCode::BAD_GATEWAY,
        "server_error",
        Some("failed to persist upstream refresh response"),
        issuer_base,
    )
}

pub(super) async fn lock_current_connection(
    tx: &mut Transaction<'_, Postgres>,
    link: &UpstreamRefreshLink,
    profile: &crate::oauth_profile::ResolvedProfile,
    issuer_base: &str,
) -> Result<(), Response> {
    // Lock the view's underlying lifecycle/configuration rows before the connection,
    // matching management's environment-before-connection lock order. No network
    // work occurs in this transaction. FOR KEY SHARE would not block client changes.
    let version = sqlx::query_scalar::<_, Uuid>(
        "SELECT configuration_version_id FROM aegaeon.active_runtime_environments \
         WHERE environment_id = $1 FOR SHARE",
    )
    .bind(link.link_env_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| persistence_error(issuer_base))?;
    let current = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM aegaeon.connections \
         WHERE id = $1 AND environment_id = $2 AND configuration_version_id = $3 \
           AND status = 'ACTIVE' AND issuer_url = $4 AND client_id = $5 \
           AND connection_identifier = $6 AND client_auth_method = $7 \
           AND client_secret_encrypted IS NOT DISTINCT FROM $8 FOR SHARE",
    )
    .bind(link.upstream_connection_id)
    .bind(link.link_env_id)
    .bind(version)
    .bind(&link.upstream_issuer)
    .bind(&link.upstream_client_id)
    .bind(&link.upstream_connection_identifier)
    .bind(&link.upstream_auth_method)
    .bind(&link.upstream_client_secret_encrypted)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| persistence_error(issuer_base))?;
    if current.is_none() {
        return Err(json_error_with_iss(
            StatusCode::CONFLICT,
            "invalid_grant",
            Some("upstream connection is no longer current"),
            issuer_base,
        ));
    }
    lock_current_profile(tx, link, profile, issuer_base).await
}

pub(super) async fn persist_upstream_refresh_exchange(
    pool: &PgPool,
    link: &UpstreamRefreshLink,
    token_response: &UpstreamTokenResponse,
    profile: &crate::oauth_profile::ResolvedProfile,
    issuer_base: &str,
) -> Result<(), Response> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| persistence_error(issuer_base))?;
    lock_current_connection(&mut tx, link, profile, issuer_base).await?;
    persist_locked_upstream_refresh_exchange(&mut tx, link, token_response, issuer_base).await?;
    tx.commit()
        .await
        .map_err(|_| persistence_error(issuer_base))
}

fn next_upstream_refresh_generation(current: i64, issuer_base: &str) -> Result<i64, Response> {
    current.checked_add(1).ok_or_else(|| {
        json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("upstream refresh token generation overflow"),
            issuer_base,
        )
    })
}

pub(super) async fn persist_locked_upstream_refresh_exchange(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    link: &UpstreamRefreshLink,
    token_response: &UpstreamTokenResponse,
    issuer_base: &str,
) -> Result<(), Response> {
    if let Some(new_refresh_token) = token_response.refresh_token.as_ref() {
        let next_generation =
            next_upstream_refresh_generation(link.upstream_refresh_token_generation, issuer_base)?;
        let encrypted_refresh_token = seal_upstream_refresh_token(
            new_refresh_token,
            link.link_env_id,
            link.upstream_issuer.as_str(),
            link.upstream_sub_hash.as_str(),
            link.upstream_connection_id,
            next_generation,
            &link.original_authentication,
        )
        .map_err(|error| {
            upstream_refresh_token_envelope_error_response(
                error,
                "failed to encrypt rotated upstream refresh token",
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
               AND upstream_refresh_token_connection_id = $2 \
               AND upstream_refresh_token_generation = $8",
        )
        .bind(encrypted_refresh_token)
        .bind(link.upstream_connection_id)
        .bind(next_generation)
        .bind(link.account_link_id)
        .bind(link.link_env_id)
        .bind(&link.upstream_issuer)
        .bind(&link.upstream_sub_hash)
        .bind(link.upstream_refresh_token_generation)
        .execute(&mut **tx)
        .await
        .map_err(|_| {
            json_error_with_iss(
                StatusCode::BAD_GATEWAY,
                "server_error",
                Some("failed to persist rotated upstream refresh token"),
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
        return Ok(());
    }
    let result = sqlx::query(
        "UPDATE aegaeon.account_links SET last_used_at = now() \
         WHERE id = $1 \
           AND environment_id = $2 \
           AND upstream_issuer = $3 \
           AND upstream_sub_hash = $4 \
           AND connection_id = $5 \
           AND upstream_refresh_token_connection_id = $5 \
           AND upstream_refresh_token_generation = $6",
    )
    .bind(link.account_link_id)
    .bind(link.link_env_id)
    .bind(&link.upstream_issuer)
    .bind(&link.upstream_sub_hash)
    .bind(link.upstream_connection_id)
    .bind(link.upstream_refresh_token_generation)
    .execute(&mut **tx)
    .await
    .map_err(|_| {
        json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("failed to persist upstream refresh metadata"),
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

async fn lock_current_profile(
    tx: &mut Transaction<'_, Postgres>,
    link: &UpstreamRefreshLink,
    original: &crate::oauth_profile::ResolvedProfile,
    issuer_base: &str,
) -> Result<(), Response> {
    let stale = || {
        json_error_with_iss(
            StatusCode::CONFLICT,
            "invalid_grant",
            Some("upstream OAuth profile is no longer current"),
            issuer_base,
        )
    };
    let id = Uuid::parse_str(&original.id).map_err(|_| stale())?;
    // Both explicit and default selection are stabilized: c is locked above and
    // changing the default requires updating the previously selected profile row.
    let locked = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM aegaeon.oauth_profiles WHERE id=$1 AND environment_id=$2 FOR SHARE",
    )
    .bind(id)
    .bind(link.link_env_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| persistence_error(issuer_base))?;
    if locked.is_none() {
        return Err(stale());
    }
    let current = crate::oauth_profile::resolve_upstream_profile_in_tx(
        tx,
        issuer_base,
        &link.upstream_connection_identifier,
    )
    .await
    .map_err(|e| match e {
        crate::oauth_profile::ProfileError::Database(_) => persistence_error(issuer_base),
        _ => stale(),
    })?;
    if &current != original {
        return Err(stale());
    }
    Ok(())
}
