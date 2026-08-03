use axum::{http::StatusCode, response::Response};

use crate::management::types::PolicyDocument;

use super::super::super::error_response;

pub(super) fn validate_acr_values(
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    for (field, configured) in [
        ("defaultAcr", policy.default_acr.as_deref()),
        ("localPasswordAcr", policy.local_password_acr.as_deref()),
    ] {
        if let Some(configured) = configured {
            let supported = policy
                .acr_values_supported
                .iter()
                .any(|supported| supported == configured);
            if !policy.acr_values_supported.is_empty() && !supported {
                return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    &format!("{field} must be listed in acrValuesSupported"),
                    None,
                    Some(request_id),
                ));
            }
        }
    }

    Ok(())
}
