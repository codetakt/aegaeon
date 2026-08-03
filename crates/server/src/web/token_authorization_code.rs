use axum::{http::StatusCode, response::Response};

use crate::authcode::types::TokenResponse as IssuerTokenResp;

use super::{
    oauth_audit::require_token_issue_audit, token_error_response, token_issuer_error_response,
    token_json_response, token_success_body, AppState, TokenEndpointContext,
};

pub(super) async fn handle_token_authorization_code_grant(
    state: &AppState,
    ctx: &TokenEndpointContext,
) -> Response {
    let issuer_base = state.issuer.as_str();
    if let Err(response) = require_token_issue_audit(state, issuer_base, ctx, None).await {
        return response;
    }
    match state
        .tokens
        .issuer
        .exchange_code_for_tokens_bound_with_grant_policy_for_token_endpoint_async(
            ctx.issuer_req.clone(),
            ctx.cnf_for_at.as_ref(),
            ctx.sender_binding.as_ref(),
            ctx.authorization_code_grant_allowed,
            ctx.refresh_grant_allowed,
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
        Err(error) => token_error_response(
            StatusCode::BAD_REQUEST,
            error.oauth_error_code(),
            Some(error.oauth_error_description()),
        ),
    }
}
