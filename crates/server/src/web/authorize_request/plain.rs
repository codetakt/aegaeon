use axum::{http::StatusCode, response::Response};
use serde_json::Value;

use crate::authcode::types::AuthorizationRequest as AuthzReq;
use crate::util;

use super::{
    authorize_json_error_with_iss, require_authorize_client_id, AuthorizeRequestParsingRuntime,
};

pub(super) struct PlainAuthorizeInput {
    pub(super) client_id: Option<String>,
    pub(super) response_type: Option<String>,
    pub(super) iss: Option<String>,
    pub(super) redirect_uri: Option<String>,
    pub(super) resource: Option<String>,
    pub(super) raw_authorization_details: Option<String>,
    pub(super) scope: Option<String>,
    pub(super) state: Option<String>,
    pub(super) nonce: Option<String>,
    pub(super) code_challenge: Option<String>,
    pub(super) code_challenge_method: Option<String>,
    pub(super) acr_values: Option<String>,
    pub(super) max_age: Option<u64>,
}

fn parse_raw_authorization_details(
    raw: Option<&str>,
    authorization_details_types_supported: &[String],
    issuer_base: &str,
) -> Result<Option<Value>, Response> {
    match raw {
        Some(raw) => {
            match util::parse_authorization_details(raw, authorization_details_types_supported) {
                Ok(details) => Ok(Some(details)),
                Err(desc) => Err(authorize_json_error_with_iss(
                    StatusCode::BAD_REQUEST,
                    "invalid_authorization_details",
                    Some(&desc),
                    issuer_base,
                )),
            }
        }
        None => Ok(None),
    }
}

fn require_authorize_response_type(
    response_type: Option<String>,
    runtime: &AuthorizeRequestParsingRuntime<'_>,
) -> Result<String, Response> {
    match response_type {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(authorize_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("response_type is required"),
            runtime.issuer_base,
        )),
    }
}

pub(super) fn authorize_request_from_plain_query(
    input: PlainAuthorizeInput,
    runtime: &AuthorizeRequestParsingRuntime<'_>,
) -> Result<AuthzReq, Response> {
    let client_id = require_authorize_client_id(input.client_id, runtime)?;
    let response_type = require_authorize_response_type(input.response_type, runtime)?;
    let authorization_details = parse_raw_authorization_details(
        input.raw_authorization_details.as_deref(),
        runtime.authorization_details_types_supported,
        runtime.issuer_base,
    )?;

    Ok(AuthzReq {
        response_type,
        client_id,
        iss: input.iss,
        redirect_uri: input.redirect_uri,
        resource: input.resource,
        authorization_details,
        scope: input.scope,
        state: input.state,
        nonce: input.nonce,
        code_challenge: input.code_challenge,
        code_challenge_method: input.code_challenge_method,
        request_uri: None,
        request_object: None,
        request_object_claims: None,
        acr_values: input.acr_values,
        max_age: input.max_age,
    })
}
