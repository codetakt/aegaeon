use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use super::oauth_errors::no_cache_json_error_with_iss;
use crate::dcr::ClientRegistration;
use crate::util;

pub(super) fn invalid_client_metadata_response(message: impl Into<String>) -> Response {
    let mut response = (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "invalid_client_metadata",
            "error_description": message.into(),
        })),
    )
        .into_response();
    util::apply_no_cache_headers(&mut response);
    response
}

fn include_client_secret_once(
    response_body: &mut Value,
    client: &crate::client_registry::RegisteredClient,
) {
    if let Some(secret) = client.client_secret.as_ref() {
        response_body["client_secret"] = json!(secret);
        response_body["client_secret_expires_at"] = json!(0);
    }
}

fn include_scope_if_present(
    response_body: &mut Value,
    client: &crate::client_registry::RegisteredClient,
) {
    if let Some(scope) = crate::oauth_scope::scope_string(&client.allowed_scopes) {
        response_body["scope"] = json!(scope);
    }
}

pub(super) fn dcr_response_types(meta: &ClientRegistration) -> Vec<String> {
    meta.response_types
        .clone()
        .unwrap_or_else(|| vec!["code".to_string()])
}

pub(super) fn dcr_update_response_types(
    meta: &ClientRegistration,
    existing_response_types: &[String],
) -> Vec<String> {
    meta.response_types
        .clone()
        .unwrap_or_else(|| existing_response_types.to_vec())
}

fn dcr_client_integrity_error_response(issuer_base: &str, field: &'static str) -> Response {
    tracing::error!(
        target: "dcr",
        field,
        "dynamic client registration response missing required client state"
    );
    no_cache_json_error_with_iss(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        Some("dynamic client registration state invalid"),
        issuer_base,
    )
}

pub(super) fn required_dcr_registration_access_token<'a>(
    issuer_base: &str,
    client: &'a crate::client_registry::RegisteredClient,
) -> Result<&'a str, Response> {
    match client.registration_access_token.as_deref() {
        Some(token) if !token.trim().is_empty() => Ok(token),
        _ => Err(dcr_client_integrity_error_response(
            issuer_base,
            "registration_access_token",
        )),
    }
}

fn required_dcr_client_id_issued_at(
    issuer_base: &str,
    client: &crate::client_registry::RegisteredClient,
) -> Result<u64, Response> {
    client
        .client_id_issued_at
        .ok_or_else(|| dcr_client_integrity_error_response(issuer_base, "client_id_issued_at"))
}

pub(super) fn build_registration_created_response(
    issuer_base: &str,
    client: &crate::client_registry::RegisteredClient,
    meta: &ClientRegistration,
) -> Response {
    let registration_access_token =
        match required_dcr_registration_access_token(issuer_base, client) {
            Ok(token) => token,
            Err(response) => return response,
        };
    let client_id_issued_at = match required_dcr_client_id_issued_at(issuer_base, client) {
        Ok(issued_at) => issued_at,
        Err(response) => return response,
    };
    let mut response_body = json!({
        "client_id": client.client_id,
        "client_id_issued_at": client_id_issued_at,
        "registration_access_token": registration_access_token,
        "registration_client_uri": format!("{issuer_base}/register/{}", client.client_id),
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "redirect_uris": client.redirect_uris,
        "grant_types": client.allowed_grant_types,
        "response_types": dcr_response_types(meta),
    });
    include_client_secret_once(&mut response_body, client);
    include_scope_if_present(&mut response_body, client);
    if let Some(jwks_uri) = client.jwks_uri.as_ref() {
        response_body["jwks_uri"] = json!(jwks_uri);
    }
    if let Some(jwks) = client.inline_jwks.as_ref() {
        response_body["jwks"] = jwks.as_value().clone();
    }
    if let Some(alg) = client.token_endpoint_auth_signing_alg.as_ref() {
        response_body["token_endpoint_auth_signing_alg"] = json!(alg);
    }
    let mut response = (StatusCode::CREATED, Json(response_body)).into_response();
    util::apply_no_cache_headers(&mut response);
    response
}

pub(super) fn build_registration_update_response(
    issuer_base: &str,
    client: &crate::client_registry::RegisteredClient,
    response_types: &[String],
    include_client_secret: bool,
) -> Response {
    let registration_access_token =
        match required_dcr_registration_access_token(issuer_base, client) {
            Ok(token) => token,
            Err(response) => return response,
        };
    let mut response_body = build_client_read_response_with_response_types(client, response_types);
    response_body["registration_access_token"] = json!(registration_access_token);
    response_body["registration_client_uri"] =
        json!(format!("{issuer_base}/register/{}", client.client_id));
    if include_client_secret {
        include_client_secret_once(&mut response_body, client);
    }
    let mut response = (StatusCode::OK, Json(response_body)).into_response();
    util::apply_no_cache_headers(&mut response);
    response
}

pub(super) fn build_client_read_response_with_response_types(
    client: &crate::client_registry::RegisteredClient,
    response_types: &[String],
) -> Value {
    let mut body = json!({
        "client_id": client.client_id,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "redirect_uris": client.redirect_uris,
        "grant_types": client.allowed_grant_types,
        "response_types": response_types,
    });
    if let Some(ts) = client.client_id_issued_at {
        body["client_id_issued_at"] = json!(ts);
    }
    if let Some(ref uri) = client.jwks_uri {
        body["jwks_uri"] = json!(uri);
    }
    if let Some(jwks) = client.inline_jwks.as_ref() {
        body["jwks"] = jwks.as_value().clone();
    }
    if let Some(alg) = client.token_endpoint_auth_signing_alg.as_ref() {
        body["token_endpoint_auth_signing_alg"] = json!(alg);
    }
    if !client.post_logout_redirect_uris.is_empty() {
        body["post_logout_redirect_uris"] = json!(client.post_logout_redirect_uris);
    }
    if let Some(ref uri) = client.backchannel_logout_uri {
        body["backchannel_logout_uri"] = json!(uri);
    }
    if client.backchannel_logout_session_required {
        body["backchannel_logout_session_required"] = json!(true);
    }
    include_scope_if_present(&mut body, client);
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_client(
        registration_access_token: Option<String>,
        client_id_issued_at: Option<u64>,
    ) -> crate::client_registry::RegisteredClient {
        crate::client_registry::RegisteredClient {
            client_id: "client-id".to_string(),
            client_secret: None,
            redirect_uris: vec!["https://client.example.com/callback".to_string()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            token_endpoint_auth_method: "none".to_string(),
            jwks_pem: None,
            inline_jwks: None,
            jwks_uri: None,
            token_endpoint_auth_signing_alg: None,
            allowed_scopes: vec!["read".to_string()],
            allowed_grant_types: vec!["authorization_code".to_string()],
            registration_access_token,
            client_id_issued_at,
        }
    }

    #[test]
    fn create_response_fails_closed_without_registration_access_token() {
        let response = build_registration_created_response(
            "https://issuer.example",
            &response_client(None, Some(1)),
            &ClientRegistration::default(),
        );

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn create_response_fails_closed_without_client_id_issued_at() {
        let response = build_registration_created_response(
            "https://issuer.example",
            &response_client(Some("registration-token".to_string()), None),
            &ClientRegistration::default(),
        );

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn update_response_fails_closed_without_registration_access_token() {
        let response = build_registration_update_response(
            "https://issuer.example",
            &response_client(None, Some(1)),
            &["code".to_string()],
            false,
        );

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn read_response_includes_registered_scope_string() {
        let body = build_client_read_response_with_response_types(
            &response_client(Some("rat".into()), Some(1)),
            &[],
        );

        assert_eq!(body["scope"], json!("read"));
    }

    #[test]
    fn update_response_types_preserve_existing_when_omitted() {
        let existing = vec!["code id_token".to_string()];
        assert_eq!(
            dcr_update_response_types(&ClientRegistration::default(), &existing),
            existing
        );
        assert_eq!(
            dcr_update_response_types(
                &ClientRegistration {
                    response_types: Some(vec!["code".to_string()]),
                    ..ClientRegistration::default()
                },
                &["code id_token".to_string()],
            ),
            vec!["code".to_string()]
        );
    }
}
