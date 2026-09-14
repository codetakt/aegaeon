use axum::{http::StatusCode, response::Response};

use crate::authcode::types::AuthorizationRequest as AuthzReq;
use crate::par::ParStore;
use crate::util;
use std::sync::Arc;

use super::oauth_errors::json_error_with_iss;

mod par;
mod plain;
mod query;
mod request_object;

use par::authorize_request_from_par;
#[cfg(test)]
pub(super) use par::par_authorize_error_response;
use plain::{authorize_request_from_plain_query, PlainAuthorizeInput};
pub(super) use query::RawAuthzQuery;

#[cfg(test)]
pub(super) use request_object::enforce_request_object_jti;
#[cfg(test)]
pub(super) use request_object::request_object_jti_retention;
pub(super) use request_object::{
    request_object_extra_string, request_object_jti_authorization_code_commit_context,
    request_object_resolution_error_json_response, request_object_resolution_error_response,
    resolve_authorize_request_object, resolve_authorize_request_object_blocking,
    OwnedRequestObjectAuthorizeDeps, RequestObjectAuthorizeDeps, RequestObjectReplayPolicy,
    ResolvedAuthorizeRequestObject,
};

struct AuthorizeRequestParsingRuntime<'a> {
    issuer_base: &'a str,
    authorization_details_types_supported: &'a [String],
    request_object_deps: Option<RequestObjectAuthorizeDeps<'a>>,
    require_pushed_authorization_requests: bool,
}

pub(super) struct ParsedAuthorizeRequest {
    pub(super) request: AuthzReq,
    // Selected by request source. Wrapped absence never falls back to the query.
    pub(super) prompt: Option<String>,
    pub(super) par_authorize_continuation: Option<String>,
}

fn require_authorize_client_id(
    client_id: Option<String>,
    runtime: &AuthorizeRequestParsingRuntime<'_>,
) -> Result<String, Response> {
    match client_id {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(authorize_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("client_id is required"),
            runtime.issuer_base,
        )),
    }
}

struct RequestObjectAuthorizeInput {
    client_id: Option<String>,
    request_jwt: String,
}

fn authorize_request_from_request_object(
    input: RequestObjectAuthorizeInput,
    runtime: &AuthorizeRequestParsingRuntime<'_>,
) -> Result<AuthzReq, Response> {
    let client_id = require_authorize_client_id(input.client_id, runtime)?;
    let Some(deps) = runtime.request_object_deps.as_ref() else {
        return Err(json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("request parameter unsupported in this context"),
            runtime.issuer_base,
        ));
    };
    let resolved = resolve_authorize_request_object(
        deps,
        &client_id,
        &input.request_jwt,
        runtime.issuer_base,
        runtime.authorization_details_types_supported,
        RequestObjectReplayPolicy::Defer,
    )
    .map_err(|err| request_object_resolution_error_response(runtime.issuer_base, &err))?;
    Ok(AuthzReq {
        response_type: resolved.response_type,
        client_id,
        // RFC 9101: use the admitted AS recipient, not JWT iss or an outer
        // query parameter. The original signed issuer remains in claims.
        iss: Some(resolved.authorization_server_issuer),
        redirect_uri: Some(resolved.redirect_uri),
        resource: resolved.resource,
        authorization_details: resolved.authorization_details,
        scope: Some(resolved.scope),
        state: resolved.state,
        nonce: resolved.nonce,
        code_challenge: Some(resolved.code_challenge),
        code_challenge_method: Some(resolved.code_challenge_method),
        request_uri: None,
        request_object: Some(resolved.request_object),
        request_object_claims: Some(resolved.request_object_claims),
        acr_values: resolved.acr_values,
        max_age: resolved.max_age,
    })
}

fn invalid_authorize_request_response(issuer_base: &str, description: &'static str) -> Response {
    authorize_json_error_with_iss(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        Some(description),
        issuer_base,
    )
}

fn authorize_json_error_with_iss(
    status: StatusCode,
    error: &str,
    description: Option<&str>,
    issuer_base: &str,
) -> Response {
    let mut response = json_error_with_iss(status, error, description, issuer_base);
    util::apply_no_cache_headers(&mut response);
    response
}

fn enforce_wrapped_authorize_request_exclusivity(
    request: Option<&str>,
    request_uri: Option<&str>,
    issuer_base: &str,
) -> Result<(), Response> {
    if request.is_some() && request_uri.is_some() {
        Err(invalid_authorize_request_response(
            issuer_base,
            "request and request_uri are mutually exclusive",
        ))
    } else {
        Ok(())
    }
}

fn wrapped_authorize_request_present(request: Option<&str>, request_uri: Option<&str>) -> bool {
    request.is_some() || request_uri.is_some()
}

fn enforce_wrapped_authorize_request_outer_policy(
    request: Option<&str>,
    request_uri: Option<&str>,
    resource: &[String],
    authorization_details: Option<&str>,
    prompt: Option<&str>,
    response_mode: Option<&str>,
    issuer_base: &str,
) -> Result<(), Response> {
    if !wrapped_authorize_request_present(request, request_uri) {
        return Ok(());
    }
    if !resource.is_empty() {
        return Err(invalid_authorize_request_response(
            issuer_base,
            "resource must not be supplied outside request or request_uri",
        ));
    }
    if authorization_details.is_some() {
        return Err(invalid_authorize_request_response(
            issuer_base,
            "authorization_details must not be supplied outside request or request_uri",
        ));
    }
    if prompt.is_some() {
        return Err(invalid_authorize_request_response(
            issuer_base,
            "prompt must not be supplied outside request or request_uri",
        ));
    }
    if response_mode.is_some() {
        return Err(invalid_authorize_request_response(
            issuer_base,
            "response_mode must not be supplied outside request or request_uri",
        ));
    }
    Ok(())
}

fn enforce_pushed_authorization_request_requirement(
    request_uri: Option<&str>,
    runtime: &AuthorizeRequestParsingRuntime<'_>,
) -> Result<(), Response> {
    if runtime.require_pushed_authorization_requests && request_uri.is_none() {
        return Err(invalid_authorize_request_response(
            runtime.issuer_base,
            "authorization request must use a pushed authorization request_uri",
        ));
    }
    Ok(())
}

fn parse_authorize_resource_indicator(
    resource: &[String],
    issuer_base: &str,
) -> Result<Option<String>, Response> {
    util::parse_single_resource_indicator(resource).map_err(|desc| {
        authorize_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some(&desc),
            issuer_base,
        )
    })
}

fn parse_authorize_request_with_runtime_inner(
    raw: RawAuthzQuery,
    par_store: &ParStore,
    issuer_base: &str,
    authorization_details_types_supported: &[String],
    request_object_deps: Option<RequestObjectAuthorizeDeps<'_>>,
    require_pushed_authorization_requests: bool,
) -> Result<ParsedAuthorizeRequest, Response> {
    let runtime = AuthorizeRequestParsingRuntime {
        issuer_base,
        authorization_details_types_supported,
        request_object_deps,
        require_pushed_authorization_requests,
    };
    let RawAuthzQuery {
        client_id,
        response_type,
        response_mode,
        iss,
        redirect_uri,
        resource,
        authorization_details,
        scope,
        state,
        nonce,
        prompt,
        max_age,
        acr_values,
        code_challenge,
        code_challenge_method,
        request,
        request_uri,
        aeg_par_continue,
    } = raw;

    enforce_wrapped_authorize_request_exclusivity(
        request.as_deref(),
        request_uri.as_deref(),
        issuer_base,
    )?;
    enforce_pushed_authorization_request_requirement(request_uri.as_deref(), &runtime)?;
    enforce_wrapped_authorize_request_outer_policy(
        request.as_deref(),
        request_uri.as_deref(),
        &resource,
        authorization_details.as_deref(),
        prompt.as_deref(),
        response_mode.as_deref(),
        issuer_base,
    )?;
    let resource = parse_authorize_resource_indicator(&resource, issuer_base)?;
    let raw_authorization_details = authorization_details;

    if let Some(request_uri) = request_uri {
        let parsed = authorize_request_from_par(
            par_store,
            client_id.as_deref(),
            request_uri.as_str(),
            aeg_par_continue.as_deref(),
            iss.as_deref(),
            runtime.issuer_base,
        )?;
        return Ok(ParsedAuthorizeRequest {
            request: parsed.request,
            prompt: parsed.prompt,
            par_authorize_continuation: Some(parsed.continuation),
        });
    }

    if let Some(request_jwt) = request {
        let request = authorize_request_from_request_object(
            RequestObjectAuthorizeInput {
                client_id,
                request_jwt,
            },
            &runtime,
        )?;
        return Ok(ParsedAuthorizeRequest {
            request,
            prompt: None,
            par_authorize_continuation: None,
        });
    }

    let request = authorize_request_from_plain_query(
        PlainAuthorizeInput {
            client_id,
            response_type,
            iss,
            redirect_uri,
            resource,
            raw_authorization_details,
            scope,
            state,
            nonce,
            code_challenge,
            code_challenge_method,
            acr_values,
            max_age,
        },
        &runtime,
    )?;
    Ok(ParsedAuthorizeRequest {
        request,
        prompt,
        par_authorize_continuation: None,
    })
}

#[cfg(test)]
pub(super) fn parse_authorize_request_with_runtime(
    raw: RawAuthzQuery,
    par_store: &ParStore,
    issuer_base: &str,
    authorization_details_types_supported: &[String],
    request_object_deps: Option<RequestObjectAuthorizeDeps<'_>>,
    require_pushed_authorization_requests: bool,
) -> Result<AuthzReq, Response> {
    parse_authorize_request_with_runtime_inner(
        raw,
        par_store,
        issuer_base,
        authorization_details_types_supported,
        request_object_deps,
        require_pushed_authorization_requests,
    )
    .map(|parsed| parsed.request)
}

pub(super) async fn parse_authorize_request_with_runtime_blocking(
    raw: RawAuthzQuery,
    par_store: Arc<ParStore>,
    issuer_base: String,
    authorization_details_types_supported: Vec<String>,
    request_object_deps: Option<OwnedRequestObjectAuthorizeDeps>,
    require_pushed_authorization_requests: bool,
) -> Result<ParsedAuthorizeRequest, Response> {
    let issuer_for_join_error = issuer_base.clone();
    tokio::task::spawn_blocking(move || {
        let request_object_deps = request_object_deps
            .as_ref()
            .map(OwnedRequestObjectAuthorizeDeps::as_borrowed);
        parse_authorize_request_with_runtime_inner(
            raw,
            par_store.as_ref(),
            &issuer_base,
            &authorization_details_types_supported,
            request_object_deps,
            require_pushed_authorization_requests,
        )
    })
    .await
    .map_err(|_| {
        json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("authorization request parser worker failed"),
            &issuer_for_join_error,
        )
    })?
}

#[cfg(test)]
pub(super) fn parse_authorize_request(
    raw: RawAuthzQuery,
    par_store: &ParStore,
    issuer_base: &str,
    authorization_details_types_supported: &[String],
) -> Result<AuthzReq, Response> {
    parse_authorize_request_with_runtime(
        raw,
        par_store,
        issuer_base,
        authorization_details_types_supported,
        None,
        false,
    )
}
