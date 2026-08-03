use super::super::super::connections_store::{
    connection_client_secret_present, connection_not_found, ensure_connection_identifier_available,
    load_connection, validate_connection_oauth_profile_reference,
};
use super::super::super::connections_support::{
    connection_client_secret_action_from_update, connection_input_from_update,
    resolve_connection_client_secret_action, validate_connection_input,
};
use super::super::super::{
    ensure_base_configuration_matches, error_response, load_management_configuration_policy,
    parse_optional_uuid_param, parse_uuid_param, ManagementEnvironmentRecord,
};
use super::PreparedConnectionUpdate;
use crate::management::types::UpdateConnectionRequest;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;
use uuid::Uuid;

fn reject_connection_issuer_url_change(
    req: &UpdateConnectionRequest,
    existing_issuer_url: &str,
    request_id: &str,
) -> Result<(), Response> {
    if req
        .issuer_url
        .as_deref()
        .map(str::trim)
        .is_some_and(|issuer_url| issuer_url != existing_issuer_url)
    {
        return Err(error_response(
            StatusCode::CONFLICT,
            "conflict",
            "issuerUrl is immutable after connection creation; create a new connection for a different issuer",
            None,
            Some(request_id),
        ));
    }
    Ok(())
}

pub(in crate::web::management::connections) async fn prepare_connection_update(
    pool: &PgPool,
    environment: &ManagementEnvironmentRecord,
    connection_id: Uuid,
    req: &UpdateConnectionRequest,
    request_id: &str,
) -> Result<PreparedConnectionUpdate, Response> {
    let base_configuration_version_id = parse_uuid_param(
        &req.base_configuration_version_id,
        "baseConfigurationVersionId",
        request_id,
    )?;
    ensure_base_configuration_matches(base_configuration_version_id, environment, request_id)?;

    let Some(existing_connection) = load_connection(
        pool,
        environment.scope.team,
        environment.scope.environment,
        connection_id,
        request_id,
    )
    .await?
    else {
        return Err(connection_not_found(request_id));
    };

    let configuration_version_id = parse_uuid_param(
        &existing_connection.configuration_version_id,
        "configurationVersionId",
        request_id,
    )?;
    if configuration_version_id != base_configuration_version_id {
        return Err(connection_not_found(request_id));
    }
    reject_connection_issuer_url_change(req, &existing_connection.issuer_url, request_id)?;
    load_management_configuration_policy(pool, environment, configuration_version_id, request_id)
        .await?;

    let mut input = connection_input_from_update(&existing_connection, req);
    validate_connection_input(&mut input, request_id)?;
    let existing_client_secret_present = connection_client_secret_present(
        pool,
        environment.scope.environment,
        connection_id,
        request_id,
    )
    .await?;
    let client_secret_action = resolve_connection_client_secret_action(
        &input,
        connection_client_secret_action_from_update(req),
        existing_client_secret_present,
        request_id,
    )?;
    let oauth_profile_id = parse_optional_uuid_param(
        input.oauth_profile_id.as_deref(),
        "oauthProfileId",
        request_id,
    )?;
    validate_connection_oauth_profile_reference(
        pool,
        environment.scope.environment,
        configuration_version_id,
        oauth_profile_id,
        request_id,
    )
    .await?;
    if input.connection_identifier != existing_connection.connection_identifier {
        ensure_connection_identifier_available(
            pool,
            environment.scope.environment,
            &input.connection_identifier,
            Some(connection_id),
            request_id,
        )
        .await?;
    }

    Ok(PreparedConnectionUpdate {
        existing_connection,
        input,
        configuration_version_id,
        oauth_profile_id,
        client_secret_action,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update_request_with_issuer(issuer_url: Option<&str>) -> UpdateConnectionRequest {
        UpdateConnectionRequest {
            base_configuration_version_id: Uuid::nil().to_string(),
            connection_identifier: None,
            name: None,
            connection_type: None,
            issuer_url: issuer_url.map(ToString::to_string),
            client_id: None,
            client_auth_method: None,
            client_secret: None,
            status: None,
            oauth_profile_id: None,
        }
    }

    #[test]
    fn reject_connection_issuer_url_change_allows_absent_or_same_issuer() {
        let existing = "https://idp.example.com";

        assert!(reject_connection_issuer_url_change(
            &update_request_with_issuer(None),
            existing,
            "req"
        )
        .is_ok());
        assert!(reject_connection_issuer_url_change(
            &update_request_with_issuer(Some(" https://idp.example.com ")),
            existing,
            "req",
        )
        .is_ok());
    }

    #[test]
    fn reject_connection_issuer_url_change_rejects_different_issuer() {
        let response = reject_connection_issuer_url_change(
            &update_request_with_issuer(Some("https://other.example.com")),
            "https://idp.example.com",
            "req",
        )
        .expect_err("issuerUrl update must be rejected");

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
