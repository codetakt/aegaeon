use axum::response::Response;

use crate::config::validate_public_base_url_value;
use crate::management::types::{PolicyDocument, PolicySenderConstraint};

use super::invalid_request;

pub(in crate::web::management::configuration_documents::policy_validation) fn validate_mtls_base_url(
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    if let Some(mtls_base_url) = policy.mtls_base_url.as_deref() {
        validate_public_base_url_value("mtls_base_url", mtls_base_url).map_err(|_| {
            invalid_request(
                "mTLS base URL must be an absolute URL using https except loopback http, with no userinfo, query, or fragment",
                request_id,
            )
        })?;
    }
    if policy.sender_constraint == PolicySenderConstraint::Mtls && !policy.mtls_enabled {
        return Err(invalid_request(
            "mTLS sender constraint requires mtlsEnabled=true",
            request_id,
        ));
    }

    Ok(())
}
