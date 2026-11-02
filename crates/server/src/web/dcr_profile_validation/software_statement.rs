use super::super::dcr_response::{invalid_client_metadata_response, invalid_redirect_uri_response};
use super::super::oauth_errors::no_cache_json_error_with_iss;
use axum::{http::StatusCode, response::Response};

use crate::dcr::{
    software_statement_profile_redirect_uris, validate_redirect_uris,
    validate_software_statement_metadata_consistency,
    verify_software_statement_profile_v1_with_config, ClientRegistration, DcrValidationConfig,
    SoftwareStatementVerificationError,
};

fn software_statement_verification_response(
    error: &SoftwareStatementVerificationError,
    issuer_base: &str,
) -> Response {
    match error {
        SoftwareStatementVerificationError::BackendPolicy(_)
        | SoftwareStatementVerificationError::Internal(_) => {
            tracing::error!(error = %error, "software statement verification failed internally");
            no_cache_json_error_with_iss(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                Some("software statement verification unavailable"),
                issuer_base,
            )
        }
        SoftwareStatementVerificationError::Unapproved => no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "unapproved_software_statement",
            Some("software statement is not approved"),
            issuer_base,
        ),
        SoftwareStatementVerificationError::Invalid(_) => no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_software_statement",
            Some("software statement is invalid"),
            issuer_base,
        ),
    }
}

pub(super) fn validate_registration_software_statement(
    dcr_config: &DcrValidationConfig,
    submitted: &ClientRegistration,
    effective: &ClientRegistration,
    issuer_base: &str,
) -> Result<(), Response> {
    let Some(ssa) = submitted.software_statement.as_ref() else {
        return Ok(());
    };
    let ssa_profile =
        verify_software_statement_profile_v1_with_config(ssa, dcr_config.software_statement())
            .map_err(|error| software_statement_verification_response(&error, issuer_base))?;
    validate_software_statement_metadata_consistency(effective, &ssa_profile.metadata)
        .map_err(invalid_client_metadata_response)?;
    let Some(redirect_uris) = software_statement_profile_redirect_uris(&ssa_profile) else {
        return Ok(());
    };
    validate_redirect_uris(&redirect_uris).map_err(invalid_redirect_uri_response)
}

#[cfg(test)]
mod error_tests;
