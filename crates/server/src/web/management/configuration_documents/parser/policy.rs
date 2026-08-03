use super::super::super::{error_response, management_internal_error};
use crate::management::types::PolicyDocument;
use axum::{http::StatusCode, response::Response};

pub(in crate::web::management) fn parse_configuration_policy_document(
    configuration_document: &serde_json::Value,
    request_id: &str,
) -> Result<PolicyDocument, Response> {
    require_configuration_policy_for_request(configuration_document, request_id)
}

pub(in crate::web::management) fn require_configuration_policy_for_request(
    configuration_document: &serde_json::Value,
    request_id: &str,
) -> Result<PolicyDocument, Response> {
    let Some(policy) = configuration_document.get("policy") else {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "configurationDocument.policy is required",
            None,
            Some(request_id),
        ));
    };

    serde_json::from_value(policy.clone()).map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "configurationDocument.policy is invalid",
            None,
            Some(request_id),
        )
    })
}

pub(in crate::web::management) fn load_policy_from_configuration_snapshot(
    configuration_document: &serde_json::Value,
    request_id: &str,
) -> Result<PolicyDocument, Response> {
    let Some(policy) = configuration_document.get("policy") else {
        return Err(management_internal_error(
            request_id,
            "Invalid configuration snapshot",
        ));
    };

    serde_json::from_value(policy.clone())
        .map_err(|_| management_internal_error(request_id, "Invalid configuration snapshot"))
}
