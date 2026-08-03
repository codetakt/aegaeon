use axum::response::Response;

use crate::dcr::{
    runtime_supported_sender_constrained_method, RUNTIME_SUPPORTED_DCR_SENDER_METHODS,
};
use crate::management::types::PolicyDocument;

use super::invalid_request;

pub(in crate::web::management::configuration_documents::policy_validation) fn validate_dcr_sender_methods(
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    let methods = normalized_dcr_sender_methods(policy);
    if methods.is_empty() {
        return Err(invalid_request(
            "DCR allowed sender methods must not be empty",
            request_id,
        ));
    }
    if methods
        .iter()
        .any(|method| !runtime_supported_sender_constrained_method(method))
    {
        return Err(invalid_request(
            &format!(
                "DCR sender-constrained methods currently support only {}",
                RUNTIME_SUPPORTED_DCR_SENDER_METHODS.join(",")
            ),
            request_id,
        ));
    }
    Ok(())
}

fn normalized_dcr_sender_methods(policy: &PolicyDocument) -> Vec<String> {
    policy
        .dcr_allowed_sender_methods
        .iter()
        .flat_map(|method| method.split(','))
        .map(str::trim)
        .filter(|method| !method.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}
