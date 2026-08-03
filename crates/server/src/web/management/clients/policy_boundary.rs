use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::super::client_input::ClientInput;
use super::super::configuration_version_store::load_environment_policy_document_in_transaction;
use super::super::normalization::normalize_lower_list;
use super::super::{error_response, management_internal_error};

struct ClientEffectiveProfilePolicy {
    allowed_grant_types: Vec<String>,
    token_endpoint_auth_methods_allowed: Vec<String>,
}

pub(in crate::web::management::clients) async fn validate_client_policy_boundary(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    input: &ClientInput,
    request_id: &str,
) -> Result<(), Response> {
    let policy =
        load_environment_policy_document_in_transaction(tx, environment_id, request_id).await?;
    let profile = load_effective_downstream_profile_policy(
        tx,
        environment_id,
        configuration_version_id,
        input.oauth_profile_id,
        request_id,
    )
    .await?;
    let scope_allowlist =
        load_environment_scope_allowlist(tx, environment_id, configuration_version_id, request_id)
            .await?;

    let policy_grants = normalize_lower_list(&policy.allowed_grant_types);
    let profile_grants = normalize_lower_list(&profile.allowed_grant_types);
    let profile_auth_methods = normalize_lower_list(&profile.token_endpoint_auth_methods_allowed);

    reject_non_subset(
        &input.allowed_grant_types,
        &policy_grants,
        request_id,
        "allowedGrantTypes must be a subset of the active environment policy",
    )?;
    reject_non_subset(
        &input.allowed_grant_types,
        &profile_grants,
        request_id,
        "allowedGrantTypes must be a subset of the effective downstream OAuth profile",
    )?;
    reject_non_member(
        &input.token_endpoint_authentication_method,
        &profile_auth_methods,
        request_id,
        "tokenEndpointAuthenticationMethod must be allowed by the effective downstream OAuth profile",
    )?;
    reject_non_subset(
        &input.allowed_scopes,
        &scope_allowlist,
        request_id,
        "allowedScopes must be a subset of the active scopeAllowlist",
    )
}

fn reject_non_subset(
    requested: &[String],
    allowed: &[String],
    request_id: &str,
    message: &str,
) -> Result<(), Response> {
    requested
        .iter()
        .all(|value| allowed.iter().any(|allowed| allowed == value))
        .then_some(())
        .ok_or_else(|| invalid_client_policy(request_id, message))
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
        .ok_or_else(|| invalid_client_policy(request_id, message))
}

fn invalid_client_policy(request_id: &str, message: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        message,
        None,
        Some(request_id),
    )
}

async fn load_effective_downstream_profile_policy(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    oauth_profile_id: Option<Uuid>,
    request_id: &str,
) -> Result<ClientEffectiveProfilePolicy, Response> {
    let row = sqlx::query(
        r"
SELECT
  allowed_grant_types,
  token_endpoint_auth_methods_allowed
FROM aegaeon.oauth_profiles
WHERE environment_id = $1
  AND configuration_version_id = $2
  AND profile_type = 'DOWNSTREAM'
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
        return Err(invalid_client_policy(
            request_id,
            "An active downstream OAuth profile is required for client policy validation",
        ));
    };

    Ok(ClientEffectiveProfilePolicy {
        allowed_grant_types: row.try_get("allowed_grant_types").map_err(|_| {
            management_internal_error(request_id, "Failed to read OAuth profile policy")
        })?,
        token_endpoint_auth_methods_allowed: row
            .try_get("token_endpoint_auth_methods_allowed")
            .map_err(|_| {
                management_internal_error(request_id, "Failed to read OAuth profile policy")
            })?,
    })
}

async fn load_environment_scope_allowlist(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    request_id: &str,
) -> Result<Vec<String>, Response> {
    let rows = sqlx::query(
        r"
SELECT scope
FROM aegaeon.environment_scope_allowlist
WHERE environment_id = $1
  AND configuration_version_id = $2
ORDER BY scope
        ",
    )
    .bind(environment_id)
    .bind(configuration_version_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    rows.into_iter()
        .map(|row| {
            row.try_get("scope").map_err(|_| {
                management_internal_error(request_id, "Failed to read scope allowlist")
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{reject_non_member, reject_non_subset};

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn subset_check_accepts_only_values_inside_boundary() {
        assert!(reject_non_subset(
            &strings(&["authorization_code"]),
            &strings(&["authorization_code", "refresh_token"]),
            "req-1",
            "grant boundary",
        )
        .is_ok());
        assert!(reject_non_subset(
            &strings(&["client_credentials"]),
            &strings(&["authorization_code", "refresh_token"]),
            "req-1",
            "grant boundary",
        )
        .is_err());
    }

    #[test]
    fn member_check_accepts_only_profile_auth_methods() {
        assert!(reject_non_member(
            "client_secret_basic",
            &strings(&["client_secret_basic"]),
            "req-1",
            "auth boundary",
        )
        .is_ok());
        assert!(reject_non_member(
            "none",
            &strings(&["client_secret_basic"]),
            "req-1",
            "auth boundary",
        )
        .is_err());
    }
}
