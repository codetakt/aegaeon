use super::oauth_audit::{require_oauth_audit, OAuthAuditEvent};
use super::oauth_errors::no_cache_json_error_with_iss;
use super::request_admission::{enforce_content_type, enforce_no_credentials_in_uri};
use super::{
    downstream_profile_violation_response, request_id_from_headers,
    resolve_downstream_profile_for_endpoint, transport_rejection,
    validate_downstream_endpoint_auth_profile, AppState,
};
use axum::{
    extract::{ConnectInfo, OriginalUri, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::net::SocketAddr;

use crate::authcode::store::ClientBoundRevocationOutcome;
use crate::authcode::types::AccessToken;
use crate::util;

mod client_auth;
mod forms;
mod introspection;
mod jwt_introspection;

use client_auth::{
    introspection_requesting_client_id, revocation_requesting_client_id, EndpointClientAuthContext,
};
pub(super) use forms::{parse_introspect_form, parse_revoke_form};
use forms::{required_lifecycle_token, IntrospectForm};
use introspection::{
    active_introspection_body, finalize_introspection_response,
    introspection_token_visible_to_client, require_introspection_token,
};

async fn authenticate_introspection_client(
    state: &AppState,
    headers: &HeaderMap,
    form: &IntrospectForm,
    issuer_base: &str,
) -> Result<EndpointClientAuthContext, Response> {
    let introspect_client = match introspection_requesting_client_id(state, headers, form).await {
        Ok(context) => context,
        Err(resp) => return Err(resp),
    };
    if let Some(client_id) = introspect_client.client_id.as_deref() {
        let profile = match resolve_downstream_profile_for_endpoint(
            state,
            issuer_base,
            client_id,
            "introspection",
        )
        .await
        {
            Ok(profile) => profile,
            Err(response) => return Err(response),
        };
        if let Err(violation) = validate_downstream_endpoint_auth_profile(
            &profile,
            introspect_client.client_auth_method,
        ) {
            return Err(downstream_profile_violation_response(
                violation,
                "introspection",
                "token_introspection",
                issuer_base,
            ));
        }
    }
    Ok(introspect_client)
}

fn record_access_token_introspection(active: bool) {
    crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
        metrics.record_introspection("access_token", active);
    });
}

fn inactive_introspection_response(
    state: &AppState,
    headers: &HeaderMap,
    introspect_client: &EndpointClientAuthContext,
) -> Response {
    record_access_token_introspection(false);
    finalize_introspection_response(
        state,
        headers,
        json!({ "active": false }),
        introspect_client.client_id.as_deref(),
    )
}

fn token_store_introspection_error(state: &AppState, err: impl std::fmt::Display) -> Response {
    tracing::error!(
        target: "oauth",
        error = %err,
        "token store access lookup failed during introspection"
    );
    no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("token store unavailable"),
        state.issuer.as_str(),
    )
}

async fn active_access_token_introspection_response(
    state: &AppState,
    headers: &HeaderMap,
    token: &str,
    access_token: &AccessToken,
    introspect_client: &EndpointClientAuthContext,
) -> Response {
    let visible = match introspection_token_visible_to_client(
        state,
        token,
        access_token,
        introspect_client.client_id.as_deref(),
    )
    .await
    {
        Ok(visible) => visible,
        Err(response) => return response,
    };
    if !visible {
        return inactive_introspection_response(state, headers, introspect_client);
    }
    record_access_token_introspection(true);
    let body = match active_introspection_body(state, token, access_token).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    finalize_introspection_response(state, headers, body, introspect_client.client_id.as_deref())
}

async fn introspect_access_token(
    state: &AppState,
    headers: &HeaderMap,
    token: &str,
    introspect_client: &EndpointClientAuthContext,
) -> Response {
    match state
        .tokens
        .store
        .try_verify_access_token_async(token.to_string())
        .await
    {
        Ok(Some(access_token)) => {
            active_access_token_introspection_response(
                state,
                headers,
                token,
                &access_token,
                introspect_client,
            )
            .await
        }
        Ok(None) => inactive_introspection_response(state, headers, introspect_client),
        Err(err) => token_store_introspection_error(state, err),
    }
}

pub(super) async fn introspect(
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
    let form = match parse_introspect_form(form, issuer_base) {
        Ok(form) => form,
        Err(resp) => return resp,
    };
    let introspect_client =
        match authenticate_introspection_client(&state, &headers, &form, issuer_base).await {
            Ok(context) => context,
            Err(resp) => return resp,
        };
    let token = match require_introspection_token(form, issuer_base) {
        Ok(token) => token,
        Err(resp) => return resp,
    };
    introspect_access_token(&state, &headers, &token, &introspect_client).await
}

pub(super) async fn revoke(
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
    let request_id = request_id_from_headers(&headers);
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
    let form = match parse_revoke_form(form, issuer_base) {
        Ok(form) => form,
        Err(resp) => return resp,
    };

    let revoke_client = match revocation_requesting_client_id(&state, &headers, &form).await {
        Ok(context) => context,
        Err(resp) => return resp,
    };
    if let Some(client_id) = revoke_client.client_id.as_deref() {
        let profile = match resolve_downstream_profile_for_endpoint(
            &state,
            issuer_base,
            client_id,
            "revocation",
        )
        .await
        {
            Ok(profile) => profile,
            Err(response) => return response,
        };
        if let Err(violation) =
            validate_downstream_endpoint_auth_profile(&profile, revoke_client.client_auth_method)
        {
            return downstream_profile_violation_response(
                violation,
                "revocation",
                "token_revocation",
                issuer_base,
            );
        }
    }

    let token = match required_lifecycle_token(form.token, issuer_base) {
        Ok(token) => token,
        Err(response) => return response,
    };

    if let Err(response) = require_oauth_audit(
        &state,
        issuer_base,
        OAuthAuditEvent {
            event_type: "oauth.token.revocation.requested.v1",
            category: "token",
            outcome: "requested",
            severity: "info",
            actor_type: "client",
            actor_id: revoke_client.client_id.as_deref(),
            target_type: "token",
            target_id: None,
            request_id: request_id.as_str(),
            data: json!({
                "tokenHash": util::secret_log_fingerprint(&token)
            }),
        },
    )
    .await
    {
        return response;
    }

    match state
        .tokens
        .store
        .try_revoke_token_for_client_async(token.clone(), revoke_client.client_id.clone())
        .await
    {
        Ok(ClientBoundRevocationOutcome::Revoked | ClientBoundRevocationOutcome::Unknown) => {}
        Ok(ClientBoundRevocationOutcome::OwnerMismatch) => {
            return util::invalid_client_response(
                "token_revocation",
                "Client authentication failed",
            );
        }
        Err(err) => {
            tracing::error!(error=%err, "token revocation store operation failed");
            return no_cache_json_error_with_iss(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                Some("token revocation store unavailable"),
                issuer_base,
            );
        }
    }

    let mut response = StatusCode::OK.into_response();
    util::apply_no_cache_headers(&mut response);
    response
}
