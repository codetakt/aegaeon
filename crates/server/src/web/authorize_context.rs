use super::authorize_input::AdmittedAuthorizationInput;
use axum::response::Response;

use crate::authcode::types::AuthorizationRequest as AuthzReq;
use crate::oauth_profile;

use super::authorize_request::{
    parse_authorize_request_with_runtime_blocking, request_object_extra_string,
    OwnedRequestObjectAuthorizeDeps, RequestObjectAuthorizeDeps,
};
use super::authorize_validation::{
    authorize_error_response, validate_authorize_request, AuthorizeErrorContext,
    AuthorizeValidationContext,
};
use super::oauth_errors::registry_state_error_response;
use super::profile_policy::{record_downstream_profile_rejection, record_downstream_profile_usage};
use super::prompt::Prompt;
use super::AppState;

pub(super) struct AuthorizeRequestContext {
    pub(super) input: AdmittedAuthorizationInput,
    pub(super) observation: crate::runtime_configuration::AuthorizationObservation,
    pub(super) request_id: String,
    pub(super) req: AuthzReq,
    pub(super) par_authorize_continuation: Option<String>,
    pub(super) response_mode: crate::form_post::ResponseMode,
    pub(super) prompt: Prompt,
    pub(super) reauthenticated: bool,
    pub(super) reauthentication_session: Option<serde_json::Value>,
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
    state: &AppState,
    req: &AuthzReq,
    outer_prompt: Option<String>,
    response_mode: crate::form_post::ResponseMode,
    issuer_base: &str,
) -> Result<Prompt, Response> {
    let raw = match req.request_object_claims.as_ref() {
        Some(claims) => request_object_extra_string(claims, "prompt").map_err(|err| {
            authorize_error_response(
                authorize_error_context(state, req, response_mode, issuer_base),
                err.error,
                Some(&err.error_description),
            )
        })?,
        None => outer_prompt,
    };
    Prompt::parse(raw.unwrap_or_default()).map_err(|description| {
        authorize_error_response(
            authorize_error_context(state, req, response_mode, issuer_base),
            "invalid_request",
            Some(description),
        )
    })
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
    input: &AdmittedAuthorizationInput,
    par_continuation: Option<&str>,
    issuer_base: &str,
) -> Result<
    (
        crate::runtime_configuration::AuthorizationObservation,
        AuthzReq,
        Prompt,
        crate::form_post::ResponseMode,
        Option<String>,
    ),
    Response,
> {
    let raw = input
        .raw(par_continuation)
        .map_err(|error| error.into_response(issuer_base))?;
    let selected_client_id = raw.client_id.as_deref().unwrap_or("");
    // PAR has historically trimmed this selector; plain and direct JAR have not.
    let selected_client_id = if raw.request_uri.is_some() {
        selected_client_id.trim()
    } else {
        selected_client_id
    };
    let observation = observe_authorization(state, selected_client_id, issuer_base).await?;
    let selected_state = state_for_authorization_observation(state, &observation);
    let state = &selected_state;
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
    let prompt =
        authorize_prompt_from_request(state, &req, parsed.prompt, response_mode, issuer_base)?;
    Ok((
        observation,
        req,
        prompt,
        response_mode,
        parsed.par_authorize_continuation,
    ))
}

fn authorize_resolve_profile(
    state: &AppState,
    req: &AuthzReq,
    response_mode: crate::form_post::ResponseMode,
    issuer_base: &str,
    observation: &crate::runtime_configuration::AuthorizationObservation,
) -> Result<oauth_profile::ResolvedProfile, Response> {
    let profile = observation.profile.clone().ok_or_else(|| {
        record_downstream_profile_rejection("profile_missing", "authorize");
        authorize_error_response(
            authorize_error_context(state, req, response_mode, issuer_base),
            "invalid_request",
            Some("oauth profile is required"),
        )
    })?;
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

pub(super) async fn build_authorize_input_context(
    state: &AppState,
    input: AdmittedAuthorizationInput,
    par_continuation: Option<String>,
    issuer_base: &str,
    request_id: String,
) -> Result<AuthorizeRequestContext, Response> {
    let (observation, req, prompt, response_mode, par_authorize_continuation) =
        authorize_parse_request_context(state, &input, par_continuation.as_deref(), issuer_base)
            .await?;
    let selected_state = state_for_authorization_observation(state, &observation);
    let state = &selected_state;
    let profile = authorize_resolve_profile(state, &req, response_mode, issuer_base, &observation)?;
    authorize_enforce_profile_issuer(state, &req, response_mode, &profile, issuer_base)?;
    let policy = authorize_validate_policy(state, &req, response_mode, &profile, issuer_base)?;
    #[cfg(test)]
    if let Some(barriers) = state
        .runtime_authority
        .authorization_context_barriers
        .as_ref()
    {
        barriers.observed.wait().await;
        barriers.resume.wait().await;
    }
    Ok(AuthorizeRequestContext {
        input,
        observation,
        request_id,
        client_id_for_error: req.client_id.clone(),
        state_for_echo: req.state.clone(),
        redirect_uri_for_error: req.redirect_uri.clone(),
        par_authorize_continuation,
        req,
        response_mode,
        prompt,
        reauthenticated: false,
        reauthentication_session: None,
        pkce_required: policy.pkce_required,
        profile_pkce_required: policy.profile_pkce_required,
    })
}

/// All later session, issuance and error consumers use this same request view.
pub(super) fn state_for_authorization_observation(
    state: &AppState,
    observation: &crate::runtime_configuration::AuthorizationObservation,
) -> AppState {
    let mut selected = state.clone();
    selected.clients = observation.selected_clients.clone();
    selected
}

async fn observe_authorization(
    state: &AppState,
    client_id: &str,
    issuer: &str,
) -> Result<crate::runtime_configuration::AuthorizationObservation, Response> {
    let refused = || {
        super::oauth_errors::no_cache_json_error_with_iss(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            Some("authorization configuration snapshot unavailable"),
            issuer,
        )
    };
    let runtime = state
        .runtime_authority
        .authorization_runtime()
        .ok_or_else(refused)?;
    if !runtime.uses_instances(&state.cfg, state.oidc.config.as_ref()) {
        return Err(refused());
    }
    runtime
        .observe(
            &state.db_pool,
            state.environment_id,
            issuer,
            client_id,
            state.clients.as_ref(),
            #[cfg(test)]
            state.runtime_authority.authorization_read_barriers.as_ref(),
        )
        .await
        .map_err(|_| refused())
}

#[cfg(test)]
pub(super) async fn build_authorize_request_context(
    state: &AppState,
    uri: &axum::http::Uri,
    issuer_base: &str,
    request_id: String,
) -> Result<AuthorizeRequestContext, Response> {
    let input = AdmittedAuthorizationInput::query(uri).map_err(|e| e.into_response(issuer_base))?;
    build_authorize_input_context(state, input, None, issuer_base, request_id).await
}
