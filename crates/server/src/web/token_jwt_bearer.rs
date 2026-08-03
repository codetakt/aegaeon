use axum::{http::StatusCode, response::Response};

use crate::authcode::types::TokenResponse as IssuerTokenResp;
use crate::client_registry::ClientAssertionValidationError;

use super::{
    oauth_audit::require_token_issue_audit, token_error_response, token_internal_error_response,
    token_issuer_error_response, token_json_response, token_registry_state_error_response,
    token_success_body, validate_token_scope_subset, AppState, TokenEndpointContext,
};

async fn validate_jwt_bearer_grant(
    state: &AppState,
    ctx: &TokenEndpointContext,
) -> Result<(String, Option<String>), Response> {
    if !state.cfg.grant_runtime().jwt_bearer_enabled() {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            None,
        ));
    }
    let grant_allowed = state
        .clients
        .try_allows_grant(
            &ctx.client_id,
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        )
        .map_err(|error| token_registry_state_error_response("jwt_bearer_allows_grant", error))?;
    if !grant_allowed {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            None,
        ));
    }
    let assertion = ctx
        .form
        .assertion
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            token_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("assertion is required"),
            )
        })?;
    let scope = validate_token_scope_subset(
        state,
        &ctx.client_id,
        ctx.form.scope.as_deref(),
        "openid scope is not allowed for the jwt-bearer grant",
    )?;
    let issuer = state.issuer.trim_end_matches('/');
    let token_audience = format!("{issuer}/token");
    let issuer_audience = issuer.to_string();
    let clients = state.clients.clone();
    let client_id = ctx.client_id.clone();
    let assertion = assertion.to_string();
    let allow_client_subject = state.cfg.allow_jwt_bearer_client_subject;
    let crypto_profile = state.cfg.crypto_profile;
    let validation = tokio::task::spawn_blocking(move || {
        clients.try_validate_jwt_bearer_grant_assertion(
            &client_id,
            &assertion,
            &token_audience,
            &issuer_audience,
            allow_client_subject,
            crypto_profile,
        )
    })
    .await
    .map_err(|_| {
        token_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("jwt-bearer assertion validation task failed"),
        )
    })?;
    let subject = match validation {
        Ok(Some(subject)) => subject,
        Ok(None) | Err(ClientAssertionValidationError::InvalidAssertion) => {
            return Err(token_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                Some("invalid jwt-bearer assertion"),
            ));
        }
        Err(ClientAssertionValidationError::Internal(message)) => {
            tracing::error!(
                target: "oauth",
                assertion_kind = "jwt_bearer",
                error = %message,
                "client assertion validation failed internally"
            );
            return Err(token_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                Some("client assertion parser backend misconfigured"),
            ));
        }
    };
    Ok((subject, scope))
}

pub(super) async fn handle_token_jwt_bearer_grant(
    state: &AppState,
    ctx: &TokenEndpointContext,
) -> Response {
    if let Err(response) = require_token_issue_audit(state, state.issuer.as_str(), ctx, None).await
    {
        return response;
    }
    let (subject, scope) = match validate_jwt_bearer_grant(state, ctx).await {
        Ok(values) => values,
        Err(response) => return response,
    };
    match state
        .tokens
        .issuer
        .issue_jwt_bearer_token_bound_async(
            ctx.client_id.clone(),
            subject,
            scope.clone(),
            ctx.resource.clone(),
            ctx.cnf_for_at.clone(),
            ctx.sender_binding.clone(),
        )
        .await
    {
        Ok(IssuerTokenResp::Success {
            access_token,
            token_type,
            expires_in,
            refresh_token,
            scope,
            id_token,
            authorization_details,
        }) => token_json_response(
            StatusCode::OK,
            token_success_body(
                &access_token,
                &token_type,
                expires_in,
                refresh_token,
                scope,
                id_token,
                authorization_details,
            ),
        ),
        Ok(IssuerTokenResp::Error {
            error,
            error_description,
        }) => token_issuer_error_response(&error, error_description.as_deref()),
        Err(error) => {
            token_internal_error_response("jwt_bearer_token_issuer", Some(error.as_str()))
        }
    }
}
