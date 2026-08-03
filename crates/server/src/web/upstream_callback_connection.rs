use super::oauth_errors::json_error_with_iss;
use axum::{http::StatusCode, response::Response};
use sqlx::{postgres::PgRow, PgPool, Row};

use crate::upstream::{
    open_upstream_client_secret, upstream_client_auth_method_uses_secret, UpstreamAuthRequest,
};

struct CurrentUpstreamCallbackConnection {
    configuration_version_id: uuid::Uuid,
    connection_identifier: String,
    issuer_url: String,
    client_id: String,
    client_auth_method: String,
    client_secret_encrypted: Option<Vec<u8>>,
}

fn stale_upstream_callback_connection_error(issuer_base: &str, message: &'static str) -> Response {
    json_error_with_iss(
        StatusCode::FORBIDDEN,
        "access_denied",
        Some(message),
        issuer_base,
    )
}

fn validate_current_upstream_callback_connection(
    request: &UpstreamAuthRequest,
    callback_connection_identifier: &str,
    current: &CurrentUpstreamCallbackConnection,
    issuer_base: &str,
) -> Result<(), Response> {
    if current.configuration_version_id != request.context.configuration_version_id {
        return Err(stale_upstream_callback_connection_error(
            issuer_base,
            "upstream connection configuration changed during authorization",
        ));
    }
    if current.connection_identifier != callback_connection_identifier {
        return Err(stale_upstream_callback_connection_error(
            issuer_base,
            "upstream callback connection identifier is no longer current",
        ));
    }
    if current.issuer_url != request.issuer
        || current.client_id != request.client_id
        || current.client_auth_method != request.client_auth_method
    {
        return Err(stale_upstream_callback_connection_error(
            issuer_base,
            "upstream connection changed during authorization",
        ));
    }
    Ok(())
}

fn current_connection_from_row(
    row: &PgRow,
    issuer_base: &str,
) -> Result<CurrentUpstreamCallbackConnection, Response> {
    let invalid_row = || {
        json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("upstream connection row invalid"),
            issuer_base,
        )
    };
    Ok(CurrentUpstreamCallbackConnection {
        configuration_version_id: row
            .try_get("configuration_version_id")
            .map_err(|_| invalid_row())?,
        connection_identifier: row
            .try_get("connection_identifier")
            .map_err(|_| invalid_row())?,
        issuer_url: row.try_get("issuer_url").map_err(|_| invalid_row())?,
        client_id: row.try_get("client_id").map_err(|_| invalid_row())?,
        client_auth_method: row
            .try_get("client_auth_method")
            .map_err(|_| invalid_row())?,
        client_secret_encrypted: row
            .try_get("client_secret_encrypted")
            .map_err(|_| invalid_row())?,
    })
}

async fn load_current_upstream_callback_connection(
    pool: &PgPool,
    request: &UpstreamAuthRequest,
    issuer_base: &str,
) -> Result<Option<CurrentUpstreamCallbackConnection>, Response> {
    let context = request.managed_connection_context();
    let row = sqlx::query(
        r"
SELECT
  c.configuration_version_id,
  c.connection_identifier,
  c.issuer_url,
  c.client_id,
  c.client_auth_method,
  c.client_secret_encrypted
FROM aegaeon.connections c
JOIN aegaeon.active_runtime_environments rt
  ON rt.environment_id = c.environment_id
  AND rt.configuration_version_id = c.configuration_version_id
WHERE c.id = $1
  AND c.environment_id = $2
  AND c.status = 'ACTIVE'
        ",
    )
    .bind(context.connection_id)
    .bind(context.environment_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| {
        json_error_with_iss(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            Some("failed to load upstream connection"),
            issuer_base,
        )
    })?;
    row.as_ref()
        .map(|row| current_connection_from_row(row, issuer_base))
        .transpose()
}

pub(super) async fn validate_and_hydrate_upstream_callback_connection(
    pool: &PgPool,
    request: &mut UpstreamAuthRequest,
    callback_connection_identifier: &str,
    issuer_base: &str,
) -> Result<(), Response> {
    let context = request.managed_connection_context();
    let Some(current) =
        load_current_upstream_callback_connection(pool, request, issuer_base).await?
    else {
        return Err(stale_upstream_callback_connection_error(
            issuer_base,
            "upstream connection is no longer active",
        ));
    };
    validate_current_upstream_callback_connection(
        request,
        callback_connection_identifier,
        &current,
        issuer_base,
    )?;
    if !upstream_client_auth_method_uses_secret(&request.client_auth_method)
        || request.client_secret.is_some()
    {
        return Ok(());
    }
    let Some(encrypted) = current.client_secret_encrypted.as_ref() else {
        return Err(json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("upstream connection client_secret is not configured"),
            issuer_base,
        ));
    };
    let secret =
        open_upstream_client_secret(encrypted, context.environment_id, context.connection_id)
            .map_err(|_| {
                json_error_with_iss(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    Some("upstream connection client_secret is unavailable"),
                    issuer_base,
                )
            })?;
    request.client_secret = Some(secret);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::UpstreamConnectionContext;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    fn callback_request() -> UpstreamAuthRequest {
        let issued_at = SystemTime::UNIX_EPOCH;
        UpstreamAuthRequest {
            state: "state".to_string(),
            nonce: "nonce".to_string(),
            code_verifier: None,
            acr: None,
            issuer: "https://idp.example.com".to_string(),
            client_id: "client".to_string(),
            client_secret: None,
            client_auth_method: "client_secret_basic".to_string(),
            context: UpstreamConnectionContext::new(
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
            ),
            token_endpoint: "https://idp.example.com/oauth/token".to_string(),
            jwks_uri: "https://idp.example.com/.well-known/jwks.json".to_string(),
            redirect_uri: "https://issuer.example.com/oauth/upstream/auth0/callback".to_string(),
            return_to: None,
            max_age: None,
            require_iss_parameter: true,
            jit_provisioning_policy: None,
            attribute_mappings: Vec::new(),
            claim_release_policy: None,
            logout_policy: None,
            issued_at,
            expires_at: issued_at + Duration::from_secs(300),
        }
    }

    fn current_connection() -> CurrentUpstreamCallbackConnection {
        CurrentUpstreamCallbackConnection {
            configuration_version_id: Uuid::new_v4(),
            connection_identifier: "auth0".to_string(),
            issuer_url: "https://idp.example.com".to_string(),
            client_id: "client".to_string(),
            client_auth_method: "client_secret_basic".to_string(),
            client_secret_encrypted: None,
        }
    }

    #[test]
    fn callback_current_connection_validation_accepts_exact_current_connection() {
        let request = callback_request();
        let mut current = current_connection();
        current.configuration_version_id = request.context.configuration_version_id;

        assert!(validate_current_upstream_callback_connection(
            &request,
            "auth0",
            &current,
            "https://issuer.example.com",
        )
        .is_ok());
    }

    #[test]
    fn callback_current_connection_validation_rejects_identifier_change() {
        let request = callback_request();
        let mut current = current_connection();
        current.configuration_version_id = request.context.configuration_version_id;
        current.connection_identifier = "google".to_string();

        let response = validate_current_upstream_callback_connection(
            &request,
            "auth0",
            &current,
            "https://issuer.example.com",
        )
        .expect_err("connection identifier drift must be rejected");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn callback_current_connection_validation_rejects_identity_or_auth_drift() {
        let mutations: [fn(&mut CurrentUpstreamCallbackConnection); 3] = [
            |current: &mut CurrentUpstreamCallbackConnection| {
                current.issuer_url = "https://other.example.com".to_string();
            },
            |current: &mut CurrentUpstreamCallbackConnection| {
                current.client_id = "other-client".to_string();
            },
            |current: &mut CurrentUpstreamCallbackConnection| {
                current.client_auth_method = "none".to_string();
            },
        ];
        for mutate in mutations {
            let request = callback_request();
            let mut current = current_connection();
            current.configuration_version_id = request.context.configuration_version_id;
            mutate(&mut current);

            let response = validate_current_upstream_callback_connection(
                &request,
                "auth0",
                &current,
                "https://issuer.example.com",
            )
            .expect_err("connection identity drift must be rejected");

            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }

    #[test]
    fn callback_current_connection_validation_rejects_configuration_version_drift() {
        let request = callback_request();
        let current = current_connection();

        let response = validate_current_upstream_callback_connection(
            &request,
            "auth0",
            &current,
            "https://issuer.example.com",
        )
        .expect_err("configuration version drift must be rejected");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
