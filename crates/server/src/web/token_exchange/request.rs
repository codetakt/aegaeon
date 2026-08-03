use axum::{http::StatusCode, response::Response};

use super::super::{
    optional_token_param, required_token_param, token_error_response, TokenEndpointContext,
    OAUTH_TOKEN_TYPE_ACCESS_TOKEN,
};

pub(super) struct TokenExchangeRequest {
    pub(super) subject_token: String,
}

pub(super) fn parse_token_exchange_request(
    ctx: &TokenEndpointContext,
    issuer_base: &str,
) -> Result<TokenExchangeRequest, Response> {
    if ctx.params.iter().any(|(key, _)| key == "audience") {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some("audience parameter is not supported"),
        ));
    }
    let subject_token = required_token_param(&ctx.params, "subject_token", issuer_base)?;
    let subject_token_type = required_token_param(&ctx.params, "subject_token_type", issuer_base)?;
    if subject_token_type != OAUTH_TOKEN_TYPE_ACCESS_TOKEN {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("unsupported subject_token_type"),
        ));
    }
    let actor_token = optional_token_param(&ctx.params, "actor_token", issuer_base)?;
    let actor_token_type = optional_token_param(&ctx.params, "actor_token_type", issuer_base)?;
    if actor_token.is_some() != actor_token_type.is_some() {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("actor_token and actor_token_type must be provided together"),
        ));
    }
    if actor_token.is_some() {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("actor_token is not supported"),
        ));
    }
    let requested_token_type =
        optional_token_param(&ctx.params, "requested_token_type", issuer_base)?;
    if requested_token_type
        .as_deref()
        .is_some_and(|value| value != OAUTH_TOKEN_TYPE_ACCESS_TOKEN)
    {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("unsupported requested_token_type"),
        ));
    }
    Ok(TokenExchangeRequest { subject_token })
}
