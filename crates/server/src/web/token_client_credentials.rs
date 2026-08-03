use axum::{http::StatusCode, response::Response};

use crate::authcode::types::TokenResponse as IssuerTokenResp;

use super::{
    oauth_audit::require_token_issue_audit, token_error_response, token_internal_error_response,
    token_issuer_error_response, token_json_response, token_registry_state_error_response,
    token_success_body, validate_token_scope_subset, AppState, TokenEndpointContext,
};

pub(super) async fn handle_token_client_credentials_grant(
    state: &AppState,
    ctx: &TokenEndpointContext,
) -> Response {
    let grant_allowed = match state
        .clients
        .try_allows_grant(&ctx.client_id, "client_credentials")
    {
        Ok(allowed) => allowed,
        Err(error) => {
            return token_registry_state_error_response("client_credentials_allows_grant", error);
        }
    };
    if !grant_allowed {
        return token_error_response(StatusCode::BAD_REQUEST, "unauthorized_client", None);
    }
    let scope = match validate_token_scope_subset(
        state,
        &ctx.client_id,
        ctx.form.scope.as_deref(),
        "openid scope is not allowed for the client_credentials grant",
    ) {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    if let Err(response) = require_token_issue_audit(
        state,
        state.issuer.as_str(),
        ctx,
        Some(ctx.client_id.as_str()),
    )
    .await
    {
        return response;
    }
    match state
        .tokens
        .issuer
        .issue_client_credentials_token_bound_async(
            ctx.client_id.clone(),
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
            token_internal_error_response("client_credentials_token_issuer", Some(&error))
        }
    }
}
