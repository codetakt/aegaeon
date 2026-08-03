use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::authcode::types::AuthorizationRequest as AuthzReq;
use crate::par::{reserve_authorize_with_par, resume_authorize_with_par, ParStore};
use crate::util;

use super::json_error_with_iss;

pub(super) struct ParAuthorizeRequest {
    pub(super) request: AuthzReq,
    pub(super) continuation: String,
}

pub(in crate::web) fn par_authorize_error_response(
    issuer_base: &str,
    err: &crate::par::ParError,
) -> Response {
    let mut body = json!({ "error": err.error.as_str(), "iss": issuer_base });
    if let Some(desc) = err.error_description.as_deref() {
        body["error_description"] = json!(desc);
    }
    let mut response = (StatusCode::BAD_REQUEST, Json(body)).into_response();
    util::apply_no_cache_headers(&mut response);
    response
}

fn authz_req_from_par_request(
    request_uri: &str,
    iss: Option<&str>,
    par_req: crate::par::ParRequest,
) -> Result<AuthzReq, crate::par::ParError> {
    let iss = merge_par_authorize_issuer(par_req.iss, iss)?;
    Ok(AuthzReq {
        response_type: par_req.response_type,
        client_id: par_req.client_id,
        iss,
        redirect_uri: Some(par_req.redirect_uri),
        resource: par_req.resource,
        authorization_details: par_req.authorization_details,
        scope: par_req.scope,
        state: par_req.state,
        nonce: par_req.nonce,
        code_challenge: par_req.code_challenge,
        code_challenge_method: par_req.code_challenge_method,
        request_uri: Some(request_uri.to_string()),
        request_object: par_req.request_object,
        request_object_claims: par_req.request_object_claims,
        acr_values: par_req.acr_values,
        max_age: par_req.max_age,
    })
}

fn merge_par_authorize_issuer(
    stored_iss: Option<String>,
    outer_iss: Option<&str>,
) -> Result<Option<String>, crate::par::ParError> {
    match (stored_iss, outer_iss) {
        (Some(stored), Some(outer)) if stored != outer => Err(crate::par::ParError {
            error: "invalid_request".to_string(),
            error_description: Some("request_uri iss mismatch".to_string()),
        }),
        (Some(stored), _) => Ok(Some(stored)),
        (None, outer) => Ok(outer.map(ToString::to_string)),
    }
}

pub(super) fn authorize_request_from_par(
    par_store: &ParStore,
    client_id: Option<&str>,
    request_uri: &str,
    continuation: Option<&str>,
    iss: Option<&str>,
    issuer_base: &str,
) -> Result<ParAuthorizeRequest, Response> {
    let Some(client_id) = client_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
    else {
        return Err(json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("client_id is required when request_uri is used"),
            issuer_base,
        ));
    };

    let (par_req, continuation) = continuation
        .map_or_else(
            || {
                reserve_authorize_with_par(par_store, request_uri, &client_id)
                    .map(|reserved| (reserved.request, reserved.continuation))
            },
            |continuation| {
                resume_authorize_with_par(par_store, request_uri, &client_id, continuation)
                    .map(|request| (request, continuation.to_string()))
            },
        )
        .and_then(|par_req| {
            if par_req.0.client_id == client_id {
                Ok(par_req)
            } else {
                Err(crate::par::ParError {
                    error: "invalid_request".to_string(),
                    error_description: Some("request_uri client_id mismatch".to_string()),
                })
            }
        })
        .map_err(|err| par_authorize_error_response(issuer_base, &err))?;
    let request = authz_req_from_par_request(request_uri, iss, par_req)
        .map_err(|err| par_authorize_error_response(issuer_base, &err))?;
    Ok(ParAuthorizeRequest {
        request,
        continuation,
    })
}
