use axum::{
    http::{StatusCode, Uri},
    response::Response,
};

use crate::authcode::types::AuthorizationRequest as AuthzReq;
use crate::oauth_profile;

use super::authorize_request::{
    parse_authorize_request_with_runtime_blocking, request_object_extra_string,
    request_object_resolution_error_response, OwnedRequestObjectAuthorizeDeps, RawAuthzQuery,
    RequestObjectAuthorizeDeps,
};
use super::authorize_validation::{
    authorize_error_response, validate_authorize_request, AuthorizeErrorContext,
    AuthorizeValidationContext,
};
use super::oauth_errors::{json_error_with_iss, registry_state_error_response};
use super::profile_policy::{record_downstream_profile_rejection, record_downstream_profile_usage};
use super::request_admission::{validate_raw_query, DEFAULT_QUERY_LIMITS};
use super::AppState;

pub(super) struct AuthorizeRequestContext {
    pub(super) request_id: String,
    pub(super) req: AuthzReq,
    pub(super) par_authorize_continuation: Option<String>,
    pub(super) response_mode: crate::form_post::ResponseMode,
    pub(super) prompt: String,
    pub(super) client_id_for_error: String,
    pub(super) state_for_echo: Option<String>,
    pub(super) redirect_uri_for_error: Option<String>,
    pub(super) pkce_required: bool,
    pub(super) profile_pkce_required: bool,
}

struct AuthorizePolicyDecision {
    pkce_required: bool,
    profile_pkce_required: bool,
}

pub(super) fn authorize_request_object_deps(state: &AppState) -> RequestObjectAuthorizeDeps<'_> {
    let request_object_decryption_key = state.oidc.config.as_deref().and_then(|cfg| {
        cfg.request_object_encryption_key
            .as_ref()
            .map(crate::oidc::config::OidcRequestObjectEncryptionKey::pkcs8_der)
    });
    RequestObjectAuthorizeDeps {
        clients: state.clients.as_ref(),
        request_object_jti_store: state.protocol.request_object_jti_store.as_ref(),
        jose_header_max_len: state.cfg.jose_header_max_len,
        request_object_decryption_key_pkcs8_der: request_object_decryption_key,
        crypto_profile: state.cfg.crypto_profile,
        jwt_leeway_secs: state.cfg.jwt_runtime().leeway_secs(),
        request_object_everparse_runtime_enabled: state
            .cfg
            .request_object_everparse_runtime_enabled,
    }
}

fn owned_authorize_request_object_deps(state: &AppState) -> OwnedRequestObjectAuthorizeDeps {
    let request_object_decryption_key = state.oidc.config.as_deref().and_then(|cfg| {
        cfg.request_object_encryption_key
            .as_ref()
            .map(crate::oidc::config::OidcRequestObjectEncryptionKey::pkcs8_der)
            .map(|der| der.to_vec())
    });
    OwnedRequestObjectAuthorizeDeps {
        clients: state.clients.clone(),
        request_object_jti_store: state.protocol.request_object_jti_store.clone(),
        jose_header_max_len: state.cfg.jose_header_max_len,
        request_object_decryption_key_pkcs8_der: request_object_decryption_key,
        crypto_profile: state.cfg.crypto_profile,
        jwt_leeway_secs: state.cfg.jwt_runtime().leeway_secs(),
        request_object_everparse_runtime_enabled: state
            .cfg
            .request_object_everparse_runtime_enabled,
    }
}

fn authorize_prompt_from_request(
    req: &AuthzReq,
    outer_prompt: Option<String>,
    issuer_base: &str,
) -> Result<String, Response> {
    let Some(claims) = req.request_object_claims.as_ref() else {
        return Ok(outer_prompt.map_or_else(String::new, std::convert::identity));
    };
    request_object_extra_string(claims, "prompt")
        .map(|prompt| prompt.map_or_else(String::new, std::convert::identity))
        .map_err(|err| request_object_resolution_error_response(issuer_base, &err))
}

fn authorize_error_context<'a>(
    state: &'a AppState,
    req: &'a AuthzReq,
    response_mode: crate::form_post::ResponseMode,
    issuer_base: &'a str,
) -> AuthorizeErrorContext<'a> {
    AuthorizeErrorContext::for_request(
        state.cfg.as_ref(),
        state.clients.as_ref(),
        req,
        response_mode,
        issuer_base,
    )
}

async fn authorize_parse_request_context(
    state: &AppState,
    uri: &Uri,
    issuer_base: &str,
) -> Result<
    (
        AuthzReq,
        String,
        crate::form_post::ResponseMode,
        Option<String>,
    ),
    Response,
> {
    let raw_query = uri.query().unwrap_or("");
    validate_raw_query(uri.query(), DEFAULT_QUERY_LIMITS).map_err(|error| {
        json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some(&error.description("authorize request")),
            issuer_base,
        )
    })?;
    let raw: RawAuthzQuery = serde_urlencoded::from_str(raw_query).map_err(|_| {
        json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("query string malformed"),
            issuer_base,
        )
    })?;
    let prompt_raw = raw.prompt.clone();
    let response_mode_raw = raw.response_mode.clone();
    let parsed = parse_authorize_request_with_runtime_blocking(
        raw,
        state.protocol.par_store.clone(),
        issuer_base.to_string(),
        state.cfg.authorization_details_types_supported.clone(),
        Some(owned_authorize_request_object_deps(state)),
        state.cfg.require_pushed_authorization_requests,
    )
    .await?;
    let req = parsed.request;
    let prompt = authorize_prompt_from_request(&req, prompt_raw, issuer_base)?;
    let response_mode_source = req
        .request_object_claims
        .as_ref()
        .and_then(|claims| claims.response_mode.as_deref())
        .or(response_mode_raw.as_deref());
    let response_mode =
        crate::form_post::parse_response_mode(response_mode_source).map_err(|_| {
            authorize_error_response(
                authorize_error_context(
                    state,
                    &req,
                    crate::form_post::ResponseMode::Query,
                    issuer_base,
                ),
                "unsupported_response_mode",
                Some("response_mode is not supported"),
            )
        })?;
    Ok((
        req,
        prompt,
        response_mode,
        parsed.par_authorize_continuation,
    ))
}

async fn authorize_resolve_profile(
    state: &AppState,
    req: &AuthzReq,
    response_mode: crate::form_post::ResponseMode,
    issuer_base: &str,
) -> Result<oauth_profile::ResolvedProfile, Response> {
    let profile = match oauth_profile::resolve_downstream_profile(
        &state.db_pool,
        issuer_base,
        &req.client_id,
    )
    .await
    {
        Ok(profile) => profile,
        Err(oauth_profile::ProfileError::MissingProfile) => {
            record_downstream_profile_rejection("profile_missing", "authorize");
            return Err(authorize_error_response(
                authorize_error_context(state, req, response_mode, issuer_base),
                "invalid_request",
                Some("oauth profile is required"),
            ));
        }
        Err(oauth_profile::ProfileError::InvalidIssuer) => {
            record_downstream_profile_rejection("issuer_invalid", "authorize");
            return Err(authorize_error_response(
                authorize_error_context(state, req, response_mode, issuer_base),
                "server_error",
                Some("issuer is invalid"),
            ));
        }
        Err(oauth_profile::ProfileError::Database(_)) => {
            record_downstream_profile_rejection("lookup_failed", "authorize");
            return Err(authorize_error_response(
                authorize_error_context(state, req, response_mode, issuer_base),
                "server_error",
                Some("oauth profile lookup failed"),
            ));
        }
    };
    record_downstream_profile_usage(&profile, "authorize");
    Ok(profile)
}

fn authorize_enforce_profile_issuer(
    state: &AppState,
    req: &AuthzReq,
    response_mode: crate::form_post::ResponseMode,
    profile: &oauth_profile::ResolvedProfile,
    issuer_base: &str,
) -> Result<(), Response> {
    if !profile.require_iss_parameter {
        return Ok(());
    }
    let iss = req
        .iss
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match iss {
        Some(value) if value == issuer_base => Ok(()),
        Some(_) => {
            record_downstream_profile_rejection("iss_mismatch", "authorize");
            Err(authorize_error_response(
                authorize_error_context(state, req, response_mode, issuer_base),
                "invalid_request",
                Some("iss must match issuer"),
            ))
        }
        None => {
            record_downstream_profile_rejection("iss_required", "authorize");
            Err(authorize_error_response(
                authorize_error_context(state, req, response_mode, issuer_base),
                "invalid_request",
                Some("iss is required"),
            ))
        }
    }
}

fn authorize_validate_policy(
    state: &AppState,
    req: &AuthzReq,
    response_mode: crate::form_post::ResponseMode,
    profile: &oauth_profile::ResolvedProfile,
    issuer_base: &str,
) -> Result<AuthorizePolicyDecision, Response> {
    let require_state = state.cfg.require_state || profile.require_state_parameter;
    validate_authorize_request(AuthorizeValidationContext {
        error: authorize_error_context(state, req, response_mode, issuer_base),
        oidc: state.oidc.config.as_deref(),
        require_state,
    })?;
    let response_type = oauth_profile::normalize_response_type(&req.response_type);
    if response_type != "code" {
        record_downstream_profile_rejection("response_type_not_allowed", "authorize");
        return Err(authorize_error_response(
            authorize_error_context(state, req, response_mode, issuer_base),
            "unauthorized_client",
            Some("response_type is not allowed"),
        ));
    }
    if !profile
        .allowed_grant_types
        .iter()
        .any(|value| value == "authorization_code")
    {
        record_downstream_profile_rejection("grant_type_not_allowed", "authorize");
        return Err(authorize_error_response(
            authorize_error_context(state, req, response_mode, issuer_base),
            "unauthorized_client",
            Some("authorization_code grant is not allowed"),
        ));
    }
    let client_confidential =
        state
            .clients
            .try_is_confidential(&req.client_id)
            .map_err(|error| {
                registry_state_error_response(
                    issuer_base,
                    "authorize_policy_is_confidential",
                    error,
                )
            })?;
    let base_pkce_required = state.cfg.security_policy.require_pkce && !client_confidential;
    let pkce_required = base_pkce_required || profile.require_pkce;
    let profile_pkce_required = profile.require_pkce;
    Ok(AuthorizePolicyDecision {
        pkce_required,
        profile_pkce_required,
    })
}

pub(super) async fn build_authorize_request_context(
    state: &AppState,
    uri: &Uri,
    issuer_base: &str,
    request_id: String,
) -> Result<AuthorizeRequestContext, Response> {
    let (req, prompt, response_mode, par_authorize_continuation) =
        authorize_parse_request_context(state, uri, issuer_base).await?;
    let profile = authorize_resolve_profile(state, &req, response_mode, issuer_base).await?;
    authorize_enforce_profile_issuer(state, &req, response_mode, &profile, issuer_base)?;
    let policy = authorize_validate_policy(state, &req, response_mode, &profile, issuer_base)?;
    Ok(AuthorizeRequestContext {
        request_id,
        client_id_for_error: req.client_id.clone(),
        state_for_echo: req.state.clone(),
        redirect_uri_for_error: req.redirect_uri.clone(),
        par_authorize_continuation,
        req,
        response_mode,
        prompt,
        pkce_required: policy.pkce_required,
        profile_pkce_required: policy.profile_pkce_required,
    })
}
