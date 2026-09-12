use axum::{http::StatusCode, response::Response};
use std::time::SystemTime;

use crate::authcode::types::AccessToken;
use crate::authcode::BearerAccessTokenMint;

use super::{
    oauth_audit::require_token_issue_audit, persist_access_with_meta_async, token_error_response,
    token_internal_error_response, token_registry_state_error_response, AccessTokenPersistence,
    AppState, TokenEndpointContext, TOKEN_EXCHANGE_GRANT_TYPE,
};

mod request;
mod resolution;
mod response;
mod subject;

use request::parse_token_exchange_request;
#[cfg(test)]
pub(super) use resolution::token_exchange_expires_in;
use resolution::{resolve_exchange, resolve_token_exchange_expires_in};
use response::token_exchange_success_response;
use subject::resolve_token_exchange_subject;
pub(super) use subject::validate_token_exchange_sender_binding;

#[expect(
    clippy::too_many_lines,
    reason = "existing token exchange workflow; new oversized functions remain gated"
)]
pub(super) async fn handle_token_exchange_grant(
    state: &AppState,
    ctx: &TokenEndpointContext,
    issuer_base: &str,
) -> Response {
    if !state.cfg.grant_runtime().token_exchange_enabled() {
        return token_error_response(StatusCode::BAD_REQUEST, "unsupported_grant_type", None);
    }
    let grant_allowed = match state
        .clients
        .try_allows_grant(&ctx.client_id, TOKEN_EXCHANGE_GRANT_TYPE)
    {
        Ok(allowed) => allowed,
        Err(error) => {
            return token_registry_state_error_response("token_exchange_allows_grant", error);
        }
    };
    if !grant_allowed {
        return token_error_response(StatusCode::BAD_REQUEST, "unauthorized_client", None);
    }
    let request = match parse_token_exchange_request(ctx, issuer_base) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let (_, subject_meta) =
        match resolve_token_exchange_subject(state, ctx, &request.subject_token).await {
            Ok(values) => values,
            Err(response) => return response,
        };
    if let Err(response) = validate_token_exchange_sender_binding(ctx, &subject_meta) {
        return response;
    }
    let resolved = match resolve_exchange(state, ctx, issuer_base, &subject_meta) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    let audience = resolved.audience;
    let scope = resolved.scope;
    if let Err(response) =
        require_token_issue_audit(state, issuer_base, ctx, Some(subject_meta.user_id.as_str()))
            .await
    {
        return response;
    }
    let now = SystemTime::now();
    let expires_in = match resolve_token_exchange_expires_in(
        &subject_meta,
        state.tokens.issuer.access_token_ttl_secs(),
        now,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let token_type = if matches!(
        ctx.sender_binding,
        Some(crate::authcode::types::SenderBinding::DPoP { .. })
    ) {
        "DPoP"
    } else {
        "Bearer"
    };
    let authorization_details = if resolved.grant.is_some() {
        None
    } else {
        subject_meta.authorization_details.clone()
    };

    let token = match state
        .tokens
        .issuer
        .mint_bearer_access_token(BearerAccessTokenMint {
            client_id: &ctx.client_id,
            subject: &subject_meta.user_id,
            scope: scope.as_deref(),
            audience: &audience,
            issued_at: now,
            expires_in,
            auth_time_epoch_secs: None,
            acr: None,
            cnf: ctx.cnf_for_at.as_ref(),
        }) {
        Ok(token) => token,
        Err(error) => {
            return token_internal_error_response(
                "token_exchange_access_token_mint",
                Some(error.as_str()),
            );
        }
    };
    let access = AccessToken {
        exchange_root: None,
        token: token.clone(),
        token_type: token_type.to_string(),
        client_id: ctx.client_id.clone(),
        user_id: subject_meta.user_id.clone(),
        scope: scope.clone(),
        expires_in,
        created_at: now,
        cnf: None,
    };
    let refresh_parent = state
        .cfg
        .security_policy
        .retain_refresh_chain()
        .then(|| subject_meta.refresh_parent.clone())
        .flatten();
    if let Err(error) = persist_access_with_meta_async(
        &state.tokens.store,
        access,
        AccessTokenPersistence {
            audience,
            refresh_parent,
            sender_binding: ctx.sender_binding.clone(),
            authorization_details: authorization_details.clone(),
            exchange_grant: resolved.grant.clone(),
            exchange_subject: subject_meta.clone(),
            auth_time_epoch_secs: subject_meta.auth_time_epoch_secs,
            acr: subject_meta.acr.clone(),
        },
    )
    .await
    {
        return response::token_exchange_commit_error(error);
    }
    token_exchange_success_response(&token, expires_in, scope, authorization_details, token_type)
}

#[cfg(test)]
pub(crate) mod tests;
