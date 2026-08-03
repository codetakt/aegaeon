use axum::{http::StatusCode, response::Response};
use std::collections::HashSet;
use std::time::SystemTime;

use crate::authcode::types::BearerTokenMeta;

use super::super::{
    scope_members, token_error_response, token_registry_state_error_response, AppState,
    TokenEndpointContext,
};

pub(super) fn resolve_token_exchange_audience(
    ctx: &TokenEndpointContext,
    subject_meta: &BearerTokenMeta,
) -> Result<String, Response> {
    match (ctx.resource.as_deref(), subject_meta.audience.as_str()) {
        (Some(requested), audience) if requested != audience => Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some("resource does not match subject_token audience"),
        )),
        (None, audience) if audience != ctx.client_id => Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some("resource is required to match subject_token audience"),
        )),
        _ => Ok(ctx
            .resource
            .clone()
            .unwrap_or_else(|| ctx.client_id.clone())),
    }
}

pub(super) fn resolve_token_exchange_scope(
    state: &AppState,
    ctx: &TokenEndpointContext,
    subject_meta: &BearerTokenMeta,
) -> Result<Option<String>, Response> {
    let requested_scopes = scope_members(ctx.form.scope.as_deref()).map_err(|error| {
        token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            Some(&error.to_string()),
        )
    })?;
    let subject_scope_set: HashSet<&str> = subject_meta
        .granted_scopes
        .iter()
        .map(String::as_str)
        .collect();
    let final_scopes = if requested_scopes.is_empty() {
        subject_meta.granted_scopes.clone()
    } else {
        if requested_scopes
            .iter()
            .any(|scope| !subject_scope_set.contains(scope.as_str()))
        {
            return Err(token_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                Some("requested scope is not allowed by subject_token"),
            ));
        }
        requested_scopes
    };
    if final_scopes.iter().any(|scope| scope == "openid") {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            Some("openid scope is not allowed for the token-exchange grant"),
        ));
    }
    let client_scope_allowed = if final_scopes.is_empty() {
        true
    } else {
        state
            .clients
            .try_validate_scope_subset(&ctx.client_id, &final_scopes)
            .map_err(|error| {
                token_registry_state_error_response("token_exchange_validate_scope_subset", error)
            })?
    };
    if !client_scope_allowed {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            Some("requested scope is not allowed for this client"),
        ));
    }
    Ok((!final_scopes.is_empty()).then(|| final_scopes.join(" ")))
}

pub(in crate::web) fn token_exchange_expires_in(
    subject_expires_at: SystemTime,
    now: SystemTime,
    access_token_ttl_secs: u64,
) -> Option<u64> {
    let remaining = subject_expires_at.duration_since(now).ok()?.as_secs();
    if remaining == 0 {
        None
    } else {
        Some(remaining.min(access_token_ttl_secs))
    }
}

pub(super) fn resolve_token_exchange_expires_in(
    subject_meta: &BearerTokenMeta,
    access_token_ttl_secs: u64,
) -> Result<u64, Response> {
    token_exchange_expires_in(
        subject_meta.expires_at,
        SystemTime::now(),
        access_token_ttl_secs,
    )
    .ok_or_else(|| {
        token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("invalid subject_token"),
        )
    })
}
