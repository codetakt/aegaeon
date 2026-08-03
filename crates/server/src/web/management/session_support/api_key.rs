use axum::{
    http::{header, HeaderMap, StatusCode},
    response::Response,
};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::management::types::ApiKeyCapability;

use super::super::{
    error_response, management_single_header, sha256_array, state::ManagementSession,
};

const MANAGEMENT_API_KEY_PREFIX_CHARS: usize = 12;
const MANAGEMENT_API_KEY_LAST_USED_UPDATE_INTERVAL_SECS: i64 = 60;

struct AuthenticatedApiKey {
    api_key_id: Uuid,
    team_id: Uuid,
    service_administrator_id: Uuid,
    capabilities: Vec<ApiKeyCapability>,
}

pub(in crate::web::management) fn management_bearer_api_key<'a>(
    headers: &'a HeaderMap,
    request_id: &str,
) -> Result<Option<&'a str>, Response> {
    let Some(value) = management_single_header(
        headers,
        header::AUTHORIZATION.as_str(),
        "Authorization",
        request_id,
    )?
    else {
        return Ok(None);
    };
    let trimmed = value.trim();
    let Some((scheme, token)) = trimmed.split_once(' ') else {
        return Err(invalid_api_key(request_id));
    };
    let token = token.trim();
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.chars().any(char::is_whitespace)
    {
        return Err(invalid_api_key(request_id));
    }
    Ok(Some(token))
}

pub(super) async fn authenticate_management_api_key(
    pool: &PgPool,
    raw_api_key: &str,
    now_epoch_secs: u64,
    request_id: &str,
) -> Result<ManagementSession, Response> {
    if !raw_api_key.starts_with("aeg_")
        || raw_api_key.chars().count() < MANAGEMENT_API_KEY_PREFIX_CHARS
    {
        return Err(invalid_api_key(request_id));
    }
    let key_prefix: String = raw_api_key
        .chars()
        .take(MANAGEMENT_API_KEY_PREFIX_CHARS)
        .collect();
    let provided_hash = sha256_array(raw_api_key.as_bytes());
    let rows = sqlx::query(
        r"
SELECT
	  ak.id AS api_key_id,
	  ak.team_id,
	  ak.service_administrator_id,
	  ak.key_hash,
	  ARRAY(
	    SELECT akc.capability::text
	    FROM aegaeon.api_key_capabilities akc
	    WHERE akc.api_key_id = ak.id
	    ORDER BY akc.capability::text
	  ) AS capabilities
	FROM aegaeon.api_keys ak
	JOIN aegaeon.administrators a
  ON a.id = ak.service_administrator_id
WHERE ak.key_prefix = $1
  AND ak.status = 'ACTIVE'
  AND (ak.expires_at IS NULL OR ak.expires_at > now())
  AND a.status = 'ACTIVE'
  AND a.kind = 'SERVICE'
        ",
    )
    .bind(key_prefix)
    .fetch_all(pool)
    .await
    .map_err(|_| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "API key store unavailable",
            None,
            Some(request_id),
        )
    })?;

    let Some(authenticated) = authenticate_api_key_candidate_rows(rows, &provided_hash) else {
        return Err(invalid_api_key(request_id));
    };

    if !confirm_api_key_active_and_touch_last_used(
        pool,
        authenticated.api_key_id,
        &provided_hash,
        request_id,
    )
    .await?
    {
        return Err(invalid_api_key(request_id));
    }

    Ok(ManagementSession::api_key(
        authenticated.service_administrator_id,
        now_epoch_secs,
        authenticated.api_key_id,
        authenticated.team_id,
        authenticated.capabilities,
    ))
}

fn authenticate_api_key_candidate_rows(
    rows: Vec<sqlx::postgres::PgRow>,
    provided_hash: &[u8; 32],
) -> Option<AuthenticatedApiKey> {
    let mut authenticated = None;
    for row in rows {
        let api_key_id = row.try_get::<Uuid, _>("api_key_id").ok();
        let team_id = row.try_get::<Uuid, _>("team_id").ok();
        let service_administrator_id = row.try_get::<Uuid, _>("service_administrator_id").ok();
        let stored_hash = row.try_get::<Vec<u8>, _>("key_hash").ok();
        let capabilities = row.try_get::<Vec<String>, _>("capabilities").ok();
        let stored_hash_matches = stored_hash
            .as_deref()
            .is_some_and(|stored_hash| crate::util::constant_time_eq(provided_hash, stored_hash));

        if stored_hash_matches && authenticated.is_none() {
            authenticated = api_key_id
                .zip(team_id)
                .zip(service_administrator_id)
                .zip(capabilities.and_then(|values| {
                    let capabilities = values
                        .iter()
                        .map(String::as_str)
                        .map(ApiKeyCapability::from_db_value)
                        .collect::<Option<Vec<_>>>()?;
                    (!capabilities.is_empty()).then_some(capabilities)
                }))
                .map(
                    |(((api_key_id, team_id), service_administrator_id), capabilities)| {
                        AuthenticatedApiKey {
                            api_key_id,
                            team_id,
                            service_administrator_id,
                            capabilities,
                        }
                    },
                );
        }
    }
    authenticated
}

async fn confirm_api_key_active_and_touch_last_used(
    pool: &PgPool,
    api_key_id: Uuid,
    provided_hash: &[u8; 32],
    request_id: &str,
) -> Result<bool, Response> {
    sqlx::query_scalar::<_, bool>(
        r"
WITH active_key AS MATERIALIZED (
  SELECT ak.id, ak.last_used_at
  FROM aegaeon.api_keys ak
  JOIN aegaeon.administrators a
    ON a.id = ak.service_administrator_id
  WHERE ak.id = $1
    AND ak.status = 'ACTIVE'
    AND ak.key_hash = $3
    AND (ak.expires_at IS NULL OR ak.expires_at > now())
    AND a.status = 'ACTIVE'
    AND a.kind = 'SERVICE'
  FOR UPDATE OF ak, a
),
updated AS (
  UPDATE aegaeon.api_keys ak
  SET last_used_at = now()
  FROM active_key
  WHERE ak.id = active_key.id
    AND (
      active_key.last_used_at IS NULL
      OR active_key.last_used_at < now() - make_interval(secs => $2)
    )
  RETURNING ak.id
)
SELECT EXISTS (SELECT 1 FROM active_key)
        ",
    )
    .bind(api_key_id)
    .bind(MANAGEMENT_API_KEY_LAST_USED_UPDATE_INTERVAL_SECS)
    .bind(provided_hash.as_slice())
    .fetch_one(pool)
    .await
    .map_err(|_| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "API key store unavailable",
            None,
            Some(request_id),
        )
    })
}

fn invalid_api_key(request_id: &str) -> Response {
    error_response(
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "Invalid management API key",
        None,
        Some(request_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_api_key_parser_accepts_case_insensitive_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "bearer aeg_test_value".parse().unwrap(),
        );

        assert_eq!(
            management_bearer_api_key(&headers, "req-1").unwrap(),
            Some("aeg_test_value")
        );
    }

    #[test]
    fn bearer_api_key_parser_rejects_malformed_values() {
        for value in [
            "aeg_test_value",
            "Bearer",
            "Bearer ",
            "Basic abc",
            "Bearer a b",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, value.parse().unwrap());
            assert!(management_bearer_api_key(&headers, "req-1").is_err());
        }
    }
}
