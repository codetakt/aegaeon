use super::ConnectionInput;
use crate::upstream::upstream_client_auth_method_supported;
use crate::web::management::{error_response, normalize_optional_text};
use axum::{http::StatusCode, response::Response};
use url::Url;

pub(in crate::web::management) fn validate_connection_input(
    input: &mut ConnectionInput,
    request_id: &str,
) -> Result<(), Response> {
    input.connection_identifier = input.connection_identifier.trim().to_string();
    require_nonempty(
        &input.connection_identifier,
        "connectionIdentifier is required",
        request_id,
    )?;

    input.name = input.name.trim().to_string();
    require_nonempty(&input.name, "name is required", request_id)?;

    input.connection_type = input.connection_type.trim().to_ascii_uppercase();
    if input.connection_type != "OIDC" {
        return Err(invalid_connection_input(
            "connectionType must be OIDC",
            request_id,
        ));
    }

    input.issuer_url = input.issuer_url.trim().to_string();
    validate_issuer_url(&input.issuer_url, request_id)?;

    input.client_id = input.client_id.trim().to_string();
    require_nonempty(&input.client_id, "clientId is required", request_id)?;

    input.client_auth_method = input.client_auth_method.trim().to_ascii_lowercase();
    if !upstream_client_auth_method_supported(&input.client_auth_method) {
        return Err(invalid_connection_input(
            "clientAuthMethod must be client_secret_basic, client_secret_post, or none",
            request_id,
        ));
    }

    input.status = input.status.trim().to_ascii_uppercase();
    if !matches!(input.status.as_str(), "ACTIVE" | "DISABLED") {
        return Err(invalid_connection_input(
            "status must be ACTIVE or DISABLED",
            request_id,
        ));
    }

    input.oauth_profile_id = normalize_optional_text(input.oauth_profile_id.as_deref());

    Ok(())
}

fn validate_issuer_url(raw: &str, request_id: &str) -> Result<(), Response> {
    require_nonempty(raw, "issuerUrl is required", request_id)?;
    let Ok(issuer_url) = Url::parse(raw) else {
        return Err(invalid_connection_input(
            "issuerUrl must be a valid https URL",
            request_id,
        ));
    };
    if issuer_url.scheme() != "https" {
        return Err(invalid_connection_input(
            "issuerUrl must use https",
            request_id,
        ));
    }
    if issuer_url.host_str().is_none() {
        return Err(invalid_connection_input(
            "issuerUrl must include a host",
            request_id,
        ));
    }
    if issuer_url.query().is_some() || issuer_url.fragment().is_some() {
        return Err(invalid_connection_input(
            "issuerUrl must not include a query or fragment",
            request_id,
        ));
    }
    if !issuer_url.username().is_empty() || issuer_url.password().is_some() {
        return Err(invalid_connection_input(
            "issuerUrl must not include userinfo",
            request_id,
        ));
    }
    if crate::ssrf::validate_url_host_not_non_routable_literal(&issuer_url).is_err() {
        return Err(invalid_connection_input(
            "issuerUrl must not target non-routable hosts",
            request_id,
        ));
    }
    Ok(())
}

fn require_nonempty(value: &str, message: &str, request_id: &str) -> Result<(), Response> {
    if value.is_empty() {
        return Err(invalid_connection_input(message, request_id));
    }
    Ok(())
}

fn invalid_connection_input(message: &str, request_id: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        message,
        None,
        Some(request_id),
    )
}
