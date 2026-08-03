use axum::{http::StatusCode, response::Response};

use crate::authcode::store::RefreshRotationError;
use crate::authcode::types::{RefreshToken, TokenResponse as IssuerTokenResp};

use super::{
    oauth_audit::require_token_issue_audit, refresh_sender_binding_violation, token_error_response,
    token_issuer_error_response, token_json_response, token_success_body, AppState,
    TokenEndpointContext,
};

struct ValidatedRefreshGrant {
    previous_refresh_token: String,
    refresh: RefreshToken,
}

async fn load_refresh_token_for_client(
    state: &AppState,
    ctx: &TokenEndpointContext,
) -> Result<ValidatedRefreshGrant, Response> {
    let refresh_token = ctx
        .issuer_req
        .refresh_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| {
            token_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("refresh_token is required"),
            )
        })?;
    let refresh = state
        .tokens
        .store
        .prepare_refresh_rotation_async(refresh_token.clone())
        .await
        .map_err(|err| match err {
            RefreshRotationError::BackendUnavailable => {
                tracing::error!(
                    target: "oauth",
                    "token store refresh lookup failed during refresh grant"
                );
                token_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    Some("token store unavailable"),
                )
            }
            RefreshRotationError::Invalid
            | RefreshRotationError::Expired
            | RefreshRotationError::Reused
            | RefreshRotationError::InconsistentGrant => token_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                Some("invalid refresh_token"),
            ),
        })?;
    if refresh.client_id != ctx.client_id {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            Some("refresh_token client mismatch"),
        ));
    }
    if let Some(reason) = refresh_sender_binding_violation(
        &refresh,
        ctx.sender_binding.as_ref(),
        ctx.sender_constraint,
        ctx.enforce_refresh_sender_binding,
    ) {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            Some(reason),
        ));
    }
    Ok(ValidatedRefreshGrant {
        previous_refresh_token: refresh_token,
        refresh,
    })
}

pub(super) async fn handle_token_refresh_grant(
    state: &AppState,
    ctx: &TokenEndpointContext,
) -> Response {
    if !ctx.refresh_grant_allowed {
        return token_error_response(StatusCode::BAD_REQUEST, "unauthorized_client", None);
    }
    if let Err(response) = require_token_issue_audit(state, state.issuer.as_str(), ctx, None).await
    {
        return response;
    }
    let prepared_refresh = match load_refresh_token_for_client(state, ctx).await {
        Ok(prepared_refresh) => prepared_refresh,
        Err(response) => return response,
    };
    match state
        .tokens
        .issuer
        .refresh_prepared_access_token_bound_async(
            prepared_refresh.previous_refresh_token,
            prepared_refresh.refresh,
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
        Err(_) => token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            Some("invalid or rotated refresh_token"),
        ),
    }
}
