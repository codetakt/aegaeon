use aegaeon_jose::RequestObjectClaims;
use serde_json::Value;

use crate::util;

use super::error::RequestObjectResolutionError;

pub(super) fn require_request_object_field(
    value: Option<&String>,
    field: &'static str,
) -> Result<String, RequestObjectResolutionError> {
    value
        .filter(|candidate| !candidate.trim().is_empty())
        .cloned()
        .ok_or_else(|| {
            RequestObjectResolutionError::invalid_request(format!(
                "Request Object {field} required"
            ))
        })
}

pub(super) fn validate_request_object_client_id(
    claims: &RequestObjectClaims,
    client_id: &str,
) -> Result<(), RequestObjectResolutionError> {
    let claim_client_id = claims
        .client_id
        .as_ref()
        .filter(|value| !value.trim().is_empty());
    let Some(claim_client_id) = claim_client_id else {
        return Err(RequestObjectResolutionError::invalid_request(
            "Request Object client_id required",
        ));
    };
    if claim_client_id != client_id {
        return Err(RequestObjectResolutionError::invalid_request(
            "Request Object client_id mismatch",
        ));
    }
    Ok(())
}

pub(super) fn validate_request_object_authorization_details(
    claims: &RequestObjectClaims,
    supported_authorization_details: &[String],
) -> Result<Option<Value>, RequestObjectResolutionError> {
    claims
        .authorization_details
        .clone()
        .map(|details| {
            util::validate_authorization_details(details, supported_authorization_details)
                .map_err(RequestObjectResolutionError::invalid_authorization_details)
        })
        .transpose()
}

fn request_object_extra_claim<'a>(claims: &'a RequestObjectClaims, key: &str) -> Option<&'a Value> {
    claims
        .extra
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|extra| extra.get(key))
}

fn validate_request_object_resource_value(value: &Value) -> Result<Option<String>, String> {
    match value {
        Value::Null => Ok(None),
        Value::String(resource) => util::validate_resource_indicator(resource).map(Some),
        Value::Array(resources) => match resources.as_slice() {
            [] => Ok(None),
            [Value::String(resource)] => util::validate_resource_indicator(resource).map(Some),
            [_] => Err("resource claim must be a string".to_string()),
            _ => Err("multiple resource values are not supported".to_string()),
        },
        _ => Err("resource claim must be a string or a one-element string array".to_string()),
    }
}

pub(super) fn validate_request_object_resource(
    claims: &RequestObjectClaims,
) -> Result<Option<String>, RequestObjectResolutionError> {
    request_object_extra_claim(claims, "resource")
        .map(validate_request_object_resource_value)
        .transpose()
        .map(Option::flatten)
        .map_err(RequestObjectResolutionError::invalid_target)
}

pub(in crate::web) fn request_object_extra_string(
    claims: &RequestObjectClaims,
    key: &'static str,
) -> Result<Option<String>, RequestObjectResolutionError> {
    match request_object_extra_claim(claims, key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(RequestObjectResolutionError::invalid_request(format!(
            "Request Object {key} claim must be a string"
        ))),
    }
}
