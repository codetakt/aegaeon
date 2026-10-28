use axum::{
    http::{HeaderMap, Uri},
    response::Response,
};

use super::super::dcr_bearer::enforce_dcr_query_admission;
use super::super::dcr_runtime::dcr_disabled_response;
use super::super::request_admission::enforce_content_type;
use super::super::AppState;

pub(in crate::web::dcr_configuration) fn enforce_registration_management_admission(
    state: &AppState,
    uri: &Uri,
    issuer_base: &str,
) -> Result<(), Response> {
    if !state.dcr_enabled {
        return Err(dcr_disabled_response(issuer_base));
    }
    enforce_dcr_query_admission(uri, issuer_base, true)
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
