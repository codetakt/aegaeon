use super::super::oauth_errors::{apply_oauth_authenticate_header, json_error_with_iss};
use super::errors::internal_server_error;
use super::UpstreamRefreshCaller;
use crate::util;
use axum::{http::StatusCode, response::Response};
use sqlx::{postgres::PgRow, PgPool};

const UPSTREAM_REFRESH_LINK_QUERY_ENV_AND_ISSUER: &str = r"
SELECT al.id AS account_link_id,
       al.environment_id,
       al.upstream_issuer,
       al.upstream_sub_hash,
       al.upstream_refresh_token_generation,
       al.upstream_refresh_token_encrypted,
       c.id AS connection_id, c.connection_identifier, c.issuer_url, c.client_id, c.client_auth_method,
       c.client_secret_encrypted
FROM aegaeon.account_links al
JOIN aegaeon.end_users u ON u.id = al.end_user_id AND u.status = 'ACTIVE'
  AND u.environment_id = al.environment_id
JOIN aegaeon.connections c ON c.id = al.upstream_refresh_token_connection_id AND c.status = 'ACTIVE'
  AND c.environment_id = al.environment_id
JOIN aegaeon.active_runtime_environments rt ON rt.environment_id = al.environment_id
  AND rt.configuration_version_id = c.configuration_version_id
WHERE al.environment_id = $1
  AND u.subject = $2
  AND al.upstream_issuer = $3
  AND al.upstream_refresh_token_encrypted IS NOT NULL
  AND al.upstream_refresh_token_connection_id = al.connection_id
LIMIT 2
";

const UPSTREAM_REFRESH_LINK_QUERY_ENV_ONLY: &str = r"
SELECT al.id AS account_link_id,
       al.environment_id,
       al.upstream_issuer,
       al.upstream_sub_hash,
       al.upstream_refresh_token_generation,
       al.upstream_refresh_token_encrypted,
       c.id AS connection_id, c.connection_identifier, c.issuer_url, c.client_id, c.client_auth_method,
       c.client_secret_encrypted
FROM aegaeon.account_links al
JOIN aegaeon.end_users u ON u.id = al.end_user_id AND u.status = 'ACTIVE'
  AND u.environment_id = al.environment_id
JOIN aegaeon.connections c ON c.id = al.upstream_refresh_token_connection_id AND c.status = 'ACTIVE'
  AND c.environment_id = al.environment_id
JOIN aegaeon.active_runtime_environments rt ON rt.environment_id = al.environment_id
  AND rt.configuration_version_id = c.configuration_version_id
WHERE al.environment_id = $1
  AND u.subject = $2
  AND al.upstream_refresh_token_encrypted IS NOT NULL
  AND al.upstream_refresh_token_connection_id = al.connection_id
LIMIT 2
";

#[derive(Debug, PartialEq, Eq)]
enum CallerEnvironmentResolutionError {
    Missing,
    Ambiguous,
}

#[derive(Debug, PartialEq, Eq)]
enum UpstreamRefreshLinkResolutionError {
    QueryFailed,
    Ambiguous,
}

fn resolve_unique_caller_environment_id(
    environment_ids: &[uuid::Uuid],
) -> Result<uuid::Uuid, CallerEnvironmentResolutionError> {
    match environment_ids {
        [] => Err(CallerEnvironmentResolutionError::Missing),
        [environment_id] => Ok(*environment_id),
        _ => Err(CallerEnvironmentResolutionError::Ambiguous),
    }
}

fn resolve_unique_upstream_refresh_link_row<Row>(
    mut rows: Vec<Row>,
) -> Result<Option<Row>, UpstreamRefreshLinkResolutionError> {
    match rows.len() {
        0 => Ok(None),
        1 => Ok(rows.pop()),
        _ => Err(UpstreamRefreshLinkResolutionError::Ambiguous),
    }
}

async fn resolve_upstream_refresh_link_row(
    pool: &PgPool,
    user_id: &str,
    caller_env_id: uuid::Uuid,
    upstream_issuer: Option<&str>,
) -> Result<Option<PgRow>, UpstreamRefreshLinkResolutionError> {
    match upstream_issuer {
        Some(upstream_issuer) => {
            let rows = sqlx::query(UPSTREAM_REFRESH_LINK_QUERY_ENV_AND_ISSUER)
                .bind(caller_env_id)
                .bind(user_id)
                .bind(upstream_issuer)
                .fetch_all(pool)
                .await
                .map_err(|_| UpstreamRefreshLinkResolutionError::QueryFailed)?;
            resolve_unique_upstream_refresh_link_row(rows)
        }
        None => {
            let rows = sqlx::query(UPSTREAM_REFRESH_LINK_QUERY_ENV_ONLY)
                .bind(caller_env_id)
                .bind(user_id)
                .fetch_all(pool)
                .await
                .map_err(|_| UpstreamRefreshLinkResolutionError::QueryFailed)?;
            resolve_unique_upstream_refresh_link_row(rows)
        }
    }
}

pub(super) async fn resolve_caller_environment_id(
    pool: &PgPool,
    caller: &UpstreamRefreshCaller,
    issuer_base: &str,
) -> Result<uuid::Uuid, Response> {
    let caller_env_ids = sqlx::query_scalar::<_, uuid::Uuid>(
        "SELECT c.environment_id FROM aegaeon.clients c \
         JOIN aegaeon.active_runtime_environments rt ON rt.environment_id = c.environment_id \
         WHERE c.client_identifier = $1 \
           AND c.status = 'ACTIVE' \
           AND rt.configuration_version_id = c.configuration_version_id \
         ORDER BY c.created_at ASC \
         LIMIT 2",
    )
    .bind(&caller.caller_client_id)
    .fetch_all(pool)
    .await
    .map_err(|_| internal_server_error(issuer_base, "failed to look up caller client"))?;

    resolve_unique_caller_environment_id(&caller_env_ids).map_err(|err| {
        tracing::warn!(
            caller_client_id = %caller.caller_client_id,
            error = ?err,
            "upstream refresh caller client environment is not uniquely resolved"
        );
        let mut response = json_error_with_iss(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            Some("caller client environment is unavailable"),
            issuer_base,
        );
        apply_oauth_authenticate_header(&mut response, "Bearer", "invalid_token");
        util::apply_no_cache_headers(&mut response);
        response
    })
}

pub(super) async fn load_unique_upstream_refresh_row(
    pool: &PgPool,
    caller: &UpstreamRefreshCaller,
    caller_env_id: uuid::Uuid,
    upstream_issuer: Option<&str>,
    issuer_base: &str,
) -> Result<PgRow, Response> {
    resolve_upstream_refresh_link_row(pool, &caller.user_id, caller_env_id, upstream_issuer)
        .await
        .map_err(|err| match err {
            UpstreamRefreshLinkResolutionError::QueryFailed => {
                internal_server_error(issuer_base, "failed to look up account link")
            }
            UpstreamRefreshLinkResolutionError::Ambiguous => {
                let message = if upstream_issuer.is_some() {
                    "multiple upstream refresh tokens matched this upstream_issuer"
                } else {
                    "upstream_issuer is required when multiple upstream refresh tokens exist"
                };
                json_error_with_iss(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    Some(message),
                    issuer_base,
                )
            }
        })?
        .ok_or_else(|| {
            json_error_with_iss(
                StatusCode::NOT_FOUND,
                "invalid_request",
                Some("no upstream refresh token found for this user"),
                issuer_base,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_refresh_caller_environment_requires_exactly_one_active_match() {
        let env_id = uuid::Uuid::new_v4();

        assert_eq!(resolve_unique_caller_environment_id(&[env_id]), Ok(env_id));
        assert_eq!(
            resolve_unique_caller_environment_id(&[]),
            Err(CallerEnvironmentResolutionError::Missing)
        );
        assert_eq!(
            resolve_unique_caller_environment_id(&[env_id, uuid::Uuid::new_v4()]),
            Err(CallerEnvironmentResolutionError::Ambiguous)
        );
    }

    #[test]
    fn upstream_refresh_link_resolution_requires_unique_match() {
        assert_eq!(
            resolve_unique_upstream_refresh_link_row::<i32>(vec![]),
            Ok(None)
        );
        assert_eq!(
            resolve_unique_upstream_refresh_link_row(vec![7]),
            Ok(Some(7))
        );
        assert_eq!(
            resolve_unique_upstream_refresh_link_row(vec![7, 8]),
            Err(UpstreamRefreshLinkResolutionError::Ambiguous)
        );
    }

    #[test]
    fn upstream_refresh_link_queries_require_active_connection_configuration() {
        for query in [
            UPSTREAM_REFRESH_LINK_QUERY_ENV_AND_ISSUER,
            UPSTREAM_REFRESH_LINK_QUERY_ENV_ONLY,
        ] {
            assert!(query.contains("JOIN aegaeon.active_runtime_environments rt"));
            assert!(query.contains("rt.configuration_version_id = c.configuration_version_id"));
        }
    }
}
