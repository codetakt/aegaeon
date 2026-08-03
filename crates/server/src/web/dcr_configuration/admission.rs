use axum::{
    http::{HeaderMap, Uri},
    response::Response,
};

use super::super::dcr_runtime::dcr_disabled_response;
use super::super::request_admission::{enforce_content_type, enforce_no_credentials_in_uri};
use super::super::AppState;

pub(in crate::web::dcr_configuration) fn enforce_registration_management_admission(
    state: &AppState,
    uri: &Uri,
    issuer_base: &str,
) -> Result<(), Response> {
    if !state.dcr_enabled {
        return Err(dcr_disabled_response(issuer_base));
    }
    enforce_no_credentials_in_uri(uri, issuer_base)
}

pub(in crate::web::dcr_configuration) fn enforce_registration_update_admission(
    state: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
    issuer_base: &str,
) -> Result<(), Response> {
    enforce_registration_management_admission(state, uri, issuer_base)?;
    enforce_content_type(headers, "application/json", issuer_base)
}
