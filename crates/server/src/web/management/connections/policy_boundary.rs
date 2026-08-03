use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::super::connections_support::ConnectionInput;
use super::super::normalization::normalize_lower_list;
use super::super::{error_response, management_internal_error};

struct ConnectionEffectiveProfilePolicy {
    token_endpoint_auth_methods_allowed: Vec<String>,
}

pub(in crate::web::management::connections) async fn validate_connection_policy_boundary(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    oauth_profile_id: Option<Uuid>,
    input: &ConnectionInput,
    request_id: &str,
) -> Result<(), Response> {
    let profile = load_effective_upstream_profile_policy(
        tx,
        environment_id,
        configuration_version_id,
        oauth_profile_id,
        request_id,
    )
    .await?;
    let profile_auth_methods = normalize_lower_list(&profile.token_endpoint_auth_methods_allowed);

    reject_non_member(
        input.client_auth_method.as_str(),
        &profile_auth_methods,
        request_id,
        "clientAuthMethod must be allowed by the effective upstream OAuth profile",
    )
}

fn reject_non_member(
    requested: &str,
    allowed: &[String],
    request_id: &str,
    message: &str,
) -> Result<(), Response> {
    allowed
        .iter()
        .any(|allowed| allowed == requested)
        .then_some(())
        .ok_or_else(|| invalid_connection_policy(request_id, message))
}

fn invalid_connection_policy(request_id: &str, message: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        message,
        None,
        Some(request_id),
    )
}

async fn load_effective_upstream_profile_policy(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    oauth_profile_id: Option<Uuid>,
    request_id: &str,
) -> Result<ConnectionEffectiveProfilePolicy, Response> {
    let row = sqlx::query(
        r"
SELECT token_endpoint_auth_methods_allowed
FROM aegaeon.oauth_profiles
WHERE environment_id = $1
  AND configuration_version_id = $2
  AND profile_type = 'UPSTREAM'
  AND status = 'ACTIVE'
  AND (expires_at IS NULL OR expires_at > now())
  AND (
    ($3::uuid IS NOT NULL AND id = $3::uuid)
    OR ($3::uuid IS NULL AND is_default = true)
  )
LIMIT 1
        ",
    )
    .bind(environment_id)
    .bind(configuration_version_id)
    .bind(oauth_profile_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    let Some(row) = row else {
        return Err(invalid_connection_policy(
            request_id,
            "An active upstream OAuth profile is required for connection policy validation",
        ));
    };

    Ok(ConnectionEffectiveProfilePolicy {
        token_endpoint_auth_methods_allowed: row
            .try_get("token_endpoint_auth_methods_allowed")
            .map_err(|_| {
                management_internal_error(request_id, "Failed to read OAuth profile policy")
            })?,
    })
}

#[cfg(test)]
mod tests {
    use super::reject_non_member;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn auth_method_boundary_accepts_profile_member() {
        assert!(reject_non_member(
            "client_secret_post",
            &strings(&["client_secret_basic", "client_secret_post"]),
            "req-1",
            "auth method boundary",
        )
        .is_ok());
    }

    #[test]
    fn auth_method_boundary_rejects_profile_non_member() {
        assert!(reject_non_member(
            "none",
            &strings(&["client_secret_basic", "client_secret_post"]),
            "req-1",
            "auth method boundary",
        )
        .is_err());
    }
}
