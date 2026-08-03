use axum::{
    extract::{ConnectInfo, OriginalUri, State},
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use std::net::SocketAddr;

use crate::authcode::types::{CnfClaim, SenderBinding, TokenRequest as IssuerTokenReq};
use crate::policy::SenderConstraint;

use super::auth_session::AuthSession;
use super::form_helpers::{auth_session_cookie, form_parse_error_response};
use super::oauth_errors::{authorization_header, no_cache_header_error, token_header_error};
use super::request_admission::{enforce_content_type, enforce_no_credentials_in_uri};
use super::token_authorization_code::handle_token_authorization_code_grant;
use super::token_client_credentials::handle_token_client_credentials_grant;
use super::token_device_code::handle_token_device_code_grant;
use super::token_exchange::handle_token_exchange_grant;
use super::token_form::{token_form_from_params, token_resource_from_params, TokenForm};
use super::token_jwt_bearer::handle_token_jwt_bearer_grant;
use super::token_refresh::handle_token_refresh_grant;
use super::token_response::{token_error_response, token_registry_state_error_response};
use super::token_sender_binding::{token_cnf_from_sender_binding, token_resolve_sender_binding};
use super::{
    auth_session_store_lookup_error_response, request_id_from_headers, scope_members,
    transport_rejection, AppState, DEVICE_CODE_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE,
};

mod client_auth;
mod policy;
pub(super) use client_auth::{
    client_auth_presence, multiple_client_auth_methods_present, token_auth_presence,
    token_client_auth_method, validate_private_key_jwt_client_assertion, ClientAuthPresence,
};
use client_auth::{token_resolve_client_id, token_validate_client_authentication};
use policy::token_resolve_policy;

/// Resolve the authenticated user from session cookie, if present.
async fn resolve_auth_session(
    state: &AppState,
    headers: &HeaderMap,
    issuer_base: &str,
) -> Result<Option<(String, AuthSession)>, Response> {
    let Some(sid) = auth_session_cookie(headers)
        .map_err(|err| no_cache_header_error(issuer_base, "Cookie", err))?
        .filter(|sid| !sid.is_empty())
    else {
        return Ok(None);
    };
    state
        .browser_auth
        .auth_sessions
        .try_get_async(sid.clone())
        .await
        .map(|session| session.map(|session| (sid, session)))
        .map_err(|err| auth_session_store_lookup_error_response(issuer_base, &err))
}

/// Resolve the authenticated user from session cookie, if present.
pub(super) async fn resolve_session_user(
    state: &AppState,
    headers: &HeaderMap,
    issuer_base: &str,
) -> Result<Option<String>, Response> {
    resolve_auth_session(state, headers, issuer_base)
        .await
        .map(|session| session.map(|(_, session)| session.user_id))
}

pub(super) struct TokenEndpointContext {
    pub(super) request_id: String,
    pub(super) params: Vec<(String, String)>,
    pub(super) form: TokenForm,
    pub(super) grant_type: String,
    pub(super) client_id: String,
    pub(super) resource: Option<String>,
    pub(super) sender_constraint: SenderConstraint,
    pub(super) enforce_refresh_sender_binding: bool,
    pub(super) authorization_code_grant_allowed: bool,
    pub(super) refresh_grant_allowed: bool,
    pub(super) sender_binding: Option<SenderBinding>,
    pub(super) issuer_req: IssuerTokenReq,
    pub(super) cnf_for_at: Option<CnfClaim>,
}

async fn build_token_context(
    state: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
    params: Vec<(String, String)>,
    issuer_base: &str,
    request_id: String,
) -> Result<TokenEndpointContext, Response> {
    let form = token_form_from_params(&params, issuer_base)?;
    let grant_type = form.grant_type.trim().to_ascii_lowercase();
    let resource = token_resource_from_params(&params)?;
    let auth_header =
        authorization_header(headers).map_err(|err| token_header_error("Authorization", err))?;
    let (client_id, client_auth_presence) = token_resolve_client_id(auth_header, &form)?;
    let client_auth_method = token_client_auth_method(client_auth_presence);
    token_validate_client_authentication(
        state,
        &form,
        &client_id,
        auth_header,
        &grant_type,
        client_auth_method,
    )
    .await?;
    let policy = token_resolve_policy(
        state,
        &client_id,
        &grant_type,
        issuer_base,
        client_auth_method,
    )
    .await?;
    let sender_binding =
        token_resolve_sender_binding(state, uri, headers, policy.sender_constraint, issuer_base)?;
    let issuer_req = IssuerTokenReq {
        grant_type: grant_type.clone(),
        code: form.code.clone(),
        redirect_uri: form.redirect_uri.clone(),
        client_id: client_id.clone(),
        client_secret: form.client_secret.clone(),
        refresh_token: form.refresh_token.clone(),
        code_verifier: form.code_verifier.clone(),
        resource: resource.clone(),
        request_object_claims: None,
    };
    Ok(TokenEndpointContext {
        request_id,
        params,
        form,
        grant_type,
        client_id,
        resource,
        sender_constraint: policy.sender_constraint,
        enforce_refresh_sender_binding: policy.enforce_refresh_sender_binding,
        authorization_code_grant_allowed: policy.authorization_code_grant_allowed,
        refresh_grant_allowed: policy.refresh_grant_allowed,
        cnf_for_at: token_cnf_from_sender_binding(sender_binding.as_ref()),
        sender_binding,
        issuer_req,
    })
}

pub(super) fn validate_token_scope_subset(
    state: &AppState,
    client_id: &str,
    scope: Option<&str>,
    openid_error: &str,
) -> Result<Option<String>, Response> {
    let requested_scopes = scope_members(scope).map_err(|error| {
        token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            Some(&error.to_string()),
        )
    })?;
    if requested_scopes.iter().any(|scope| scope == "openid") {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            Some(openid_error),
        ));
    }
    let client_scope_allowed = if requested_scopes.is_empty() {
        true
    } else {
        state
            .clients
            .try_validate_scope_subset(client_id, &requested_scopes)
            .map_err(|error| {
                token_registry_state_error_response("token_validate_scope_subset", error)
            })?
    };
    if !client_scope_allowed {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            Some("requested scope is not allowed for this client"),
        ));
    }
    Ok(crate::oauth_scope::scope_string(&requested_scopes))
}

pub(super) async fn token(
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

    let Ok(axum::extract::Form(params)) = form else {
        return form_parse_error_response(issuer_base);
    };
    let request_id = request_id_from_headers(&headers);
    let ctx =
        match build_token_context(&state, &uri, &headers, params, issuer_base, request_id).await {
            Ok(ctx) => ctx,
            Err(response) => return response,
        };
    match ctx.grant_type.as_str() {
        "authorization_code" => handle_token_authorization_code_grant(&state, &ctx).await,
        "refresh_token" => handle_token_refresh_grant(&state, &ctx).await,
        "urn:ietf:params:oauth:grant-type:jwt-bearer" => {
            handle_token_jwt_bearer_grant(&state, &ctx).await
        }
        TOKEN_EXCHANGE_GRANT_TYPE => handle_token_exchange_grant(&state, &ctx, issuer_base).await,
        "client_credentials" => handle_token_client_credentials_grant(&state, &ctx).await,
        DEVICE_CODE_GRANT_TYPE => handle_token_device_code_grant(&state, &ctx).await,
        _ => token_error_response(StatusCode::BAD_REQUEST, "unsupported_grant_type", None),
    }
}
