use super::request_admission::{enforce_content_type, enforce_no_credentials_in_uri};
use super::{
    downstream_profile_violation_response, resolve_downstream_profile_for_endpoint,
    transport_rejection, validate_downstream_par_profile_policy, AppState,
};
use axum::{
    extract::{ConnectInfo, OriginalUri, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::net::SocketAddr;

use crate::policy::AUTHORIZATION_CODE_GRANT_TYPE;
use crate::util;

mod client_auth;
mod form;
mod resolution;

use self::client_auth::{authenticate_par_client, ParClientContext};
pub(super) use self::form::parse_par_form;
#[cfg(test)]
pub(super) use self::resolution::{finalize_par_resolved_parameters, ParResolvedDraft};
use self::resolution::{resolve_par_parameters, ParResolvedParameters};
use super::oauth_errors::registry_state_error_response;

async fn enforce_par_downstream_profile(
    state: &AppState,
    client_context: &ParClientContext,
    resolved: &ParResolvedParameters,
    issuer_base: &str,
) -> Result<(), Response> {
    let profile = resolve_downstream_profile_for_endpoint(
        state,
        issuer_base,
        &client_context.client_id,
        "par",
    )
    .await?;
    validate_downstream_par_profile_policy(
        &profile,
        &resolved.response_type,
        resolved.state.as_deref(),
        resolved.iss.as_deref(),
        client_context.client_auth_method,
        issuer_base,
    )
    .map_err(|violation| {
        downstream_profile_violation_response(violation, "par", "oauth", issuer_base)
    })
}

fn lookup_registered_par_client(
    state: &AppState,
    client_id: &str,
    redirect_uri: &str,
) -> Result<crate::client_registry::RegisteredClient, Response> {
    let redirect_uri_valid = state
        .clients
        .try_validate_redirect_uri(client_id, redirect_uri)
        .map_err(|error| {
            registry_state_error_response(state.issuer.as_str(), "par_validate_redirect_uri", error)
        })?;
    if !redirect_uri_valid {
        let mut response = (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_redirect_uri" })),
        )
            .into_response();
        util::apply_no_cache_headers(&mut response);
        return Err(response);
    }
    state
        .clients
        .try_get(client_id)
        .map_err(|error| {
            registry_state_error_response(state.issuer.as_str(), "par_get_client", error)
        })?
        .ok_or_else(|| {
            let mut response = (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid_client" })),
            )
                .into_response();
            util::apply_no_cache_headers(&mut response);
            response
        })
}

fn enforce_registered_par_scope_subset(
    state: &AppState,
    client_id: &str,
    scope: Option<&str>,
) -> Result<(), Response> {
    let requested = crate::oauth_scope::parse_optional_scope_string(scope).map_err(|error| {
        let mut response = (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_scope",
                "error_description": error.to_string(),
            })),
        )
            .into_response();
        util::apply_no_cache_headers(&mut response);
        response
    })?;
    if requested.is_empty() {
        return Ok(());
    }
    let scope_allowed = state
        .clients
        .try_validate_scope_subset(client_id, &requested)
        .map_err(|error| {
            registry_state_error_response(state.issuer.as_str(), "par_validate_scope_subset", error)
        })?;
    if scope_allowed {
        return Ok(());
    }
    let mut response = (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "invalid_scope",
            "error_description": "requested scope is not allowed for this client",
        })),
    )
        .into_response();
    util::apply_no_cache_headers(&mut response);
    Err(response)
}

fn enforce_registered_par_authorization_code_grant(
    client: &crate::client_registry::RegisteredClient,
) -> Result<(), Response> {
    if client
        .allowed_grant_types
        .iter()
        .any(|grant| grant == AUTHORIZATION_CODE_GRANT_TYPE)
    {
        return Ok(());
    }

    let mut response = (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "unauthorized_client",
            "error_description": "client is not allowed to use authorization_code grant",
        })),
    )
        .into_response();
    util::apply_no_cache_headers(&mut response);
    Err(response)
}

pub(super) fn par_error_response_body_and_status(e: &crate::par::ParError) -> (Value, StatusCode) {
    if e.error == "server_error" {
        if let Some(description) = e.error_description.as_deref() {
            tracing::error!(
                target: "oauth",
                error = %description,
                "PAR request failed internally"
            );
        }
        (
            json!({
                "error": e.error.as_str(),
                "error_description": "PAR request processing failed internally",
            }),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    } else {
        (
            json!({
                "error": e.error.as_str(),
                "error_description": e.error_description.as_deref(),
            }),
            StatusCode::BAD_REQUEST,
        )
    }
}

pub(super) async fn par(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
) -> Response {
    let issuer_base = state.issuer.as_str();
    if let Err(kind) = state.transport.enforce(Some(remote), &headers) {
        return transport_rejection(&state, kind);
    }
    if let Err(resp) = enforce_no_credentials_in_uri(&uri, issuer_base) {
        return resp;
    }
    if let Err(resp) =
        enforce_content_type(&headers, "application/x-www-form-urlencoded", issuer_base)
    {
        return resp;
    }
    let form = match parse_par_form(form, issuer_base) {
        Ok(form) => form,
        Err(resp) => return resp,
    };
    let client_context = match authenticate_par_client(&state, &headers, &form).await {
        Ok(context) => context,
        Err(resp) => return resp,
    };
    let resolved =
        match resolve_par_parameters(&state, &form, &client_context.client_id, issuer_base).await {
            Ok(resolved) => resolved,
            Err(resp) => return resp,
        };
    let registered_client = match lookup_registered_par_client(
        &state,
        &client_context.client_id,
        &resolved.redirect_uri,
    ) {
        Ok(client) => client,
        Err(resp) => return resp,
    };
    if let Err(resp) = enforce_registered_par_authorization_code_grant(&registered_client) {
        return resp;
    }
    if let Err(resp) = enforce_registered_par_scope_subset(
        &state,
        &client_context.client_id,
        resolved.scope.as_deref(),
    ) {
        return resp;
    }
    if let Err(resp) =
        enforce_par_downstream_profile(&state, &client_context, &resolved, issuer_base).await
    {
        return resp;
    }

    let par_request = crate::par::ParRequest {
        client_id: client_context.client_id,
        redirect_uri: resolved.redirect_uri,
        response_type: resolved.response_type,
        iss: resolved.iss,
        resource: resolved.resource,
        state: resolved.state,
        code_challenge: Some(resolved.code_challenge),
        code_challenge_method: Some(resolved.code_challenge_method),
        scope: resolved.scope,
        nonce: resolved.nonce,
        acr_values: resolved.acr_values,
        max_age: resolved.max_age,
        authorization_details: resolved.authorization_details,
        client_secret: client_context.client_secret_for_store,
        client_authenticated: client_context.client_authenticated,
        request_object: resolved.request_object,
        request_object_claims: resolved.request_object_claims,
    };

    let (body, status) = state
        .protocol
        .par_endpoint
        .handle_par_request(par_request)
        .map_or_else(
            |err| par_error_response_body_and_status(&err),
            |resp| {
                (
                    serde_json::to_value(resp).unwrap_or_else(|_| json!({})),
                    StatusCode::CREATED,
                )
            },
        );

    let mut response = (status, Json(body)).into_response();
    util::apply_no_cache_headers(&mut response);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registered_client_with_grants(grants: &[&str]) -> crate::client_registry::RegisteredClient {
        crate::client_registry::RegisteredClient {
            client_id: "client-1".to_string(),
            client_secret: Some("secret".to_string()),
            redirect_uris: vec!["https://app.example.com/callback".to_string()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            jwks_pem: None,
            inline_jwks: None,
            jwks_uri: None,
            token_endpoint_auth_signing_alg: None,
            allowed_scopes: vec!["openid".to_string()],
            allowed_grant_types: grants.iter().map(|grant| (*grant).to_string()).collect(),
            registration_access_token: None,
            client_id_issued_at: None,
        }
    }

    #[test]
    fn par_admission_requires_registered_authorization_code_grant() {
        let client = registered_client_with_grants(&["client_credentials"]);
        let response = enforce_registered_par_authorization_code_grant(&client)
            .expect_err("PAR must reject clients without authorization_code grant");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn par_admission_accepts_registered_authorization_code_grant() {
        let client = registered_client_with_grants(&[AUTHORIZATION_CODE_GRANT_TYPE]);

        assert!(enforce_registered_par_authorization_code_grant(&client).is_ok());
    }
}
