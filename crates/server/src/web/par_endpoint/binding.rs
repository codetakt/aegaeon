use super::super::{
    token_sender_binding::{dpop_binding_from_request, dpop_error_response},
    AppState,
};
use crate::{
    authcode::types::DpopKeyThumbprint,
    middleware::{dpop::DpopEndpointRole, DpopError},
};
use axum::{
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};

pub(super) fn resolve_par_dpop(
    state: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
    parameter: Option<&DpopKeyThumbprint>,
) -> Result<Option<DpopKeyThumbprint>, Response> {
    let role = DpopEndpointRole::AuthorizationServer;
    let issuer = state.issuer.as_str();
    // Match the token endpoint's external-URI policy; never trust an absolute request target.
    let path = uri
        .path_and_query()
        .map_or(uri.path(), axum::http::uri::PathAndQuery::as_str);
    let target: Uri = path
        .parse()
        .map_err(|_| dpop_error_response(issuer, role, DpopError::InvalidProof))?;
    let verified =
        dpop_binding_from_request(state.dpop.as_ref(), role, &Method::POST, &target, headers)
            .map_err(|error| dpop_error_response(issuer, role, error))?;
    let verified = verified
        .map(|binding| DpopKeyThumbprint::parse(&binding.jkt))
        .transpose()
        .map_err(|_| dpop_error_response(issuer, role, DpopError::InvalidProof))?;
    if let (Some(expected), Some(proved)) = (parameter, verified.as_ref()) {
        if expected != proved {
            return Err(super::super::oauth_errors::no_cache_json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("PAR DPoP key disagreement"),
                issuer,
            ));
        }
    }
    Ok(parameter.cloned().or(verified))
}
