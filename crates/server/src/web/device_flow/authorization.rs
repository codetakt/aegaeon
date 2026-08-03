mod client_auth;
mod form;
mod policy;
mod response;

use super::super::form_helpers::form_parse_error_response;
use super::super::oauth_errors::no_cache_json_error_with_iss;
use super::super::{scope_members, AppState};
use axum::{
    extract::{ConnectInfo, OriginalUri, State},
    http::HeaderMap,
    response::Response,
};
use std::net::SocketAddr;

use client_auth::authenticate_device_authorization_client;
use form::device_authorization_form_from_params;
use policy::{enforce_device_authorization_admission, enforce_device_authorization_policy};
use response::create_device_authorization_response;

pub(in crate::web) async fn device_authorization(
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

    if let Err(response) =
        enforce_device_authorization_admission(&state, remote, &uri, &headers, issuer_base)
    {
        return response;
    }

    let Ok(axum::extract::Form(params)) = form else {
        return form_parse_error_response(issuer_base);
    };

    let device_form = match device_authorization_form_from_params(&params, issuer_base) {
        Ok(form) => form,
        Err(response) => return response,
    };

    let client_context = match authenticate_device_authorization_client(
        &state,
        &headers,
        &device_form.token_form,
        issuer_base,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };

    let requested_scopes = match scope_members(device_form.scope.as_deref()) {
        Ok(scopes) => scopes,
        Err(error) => {
            return no_cache_json_error_with_iss(
                axum::http::StatusCode::BAD_REQUEST,
                "invalid_scope",
                Some(&error.to_string()),
                issuer_base,
            );
        }
    };
    if let Err(response) =
        enforce_device_authorization_policy(&state, issuer_base, &client_context, &requested_scopes)
            .await
    {
        return response;
    }

    create_device_authorization_response(&state, issuer_base, &client_context, &device_form).await
}
