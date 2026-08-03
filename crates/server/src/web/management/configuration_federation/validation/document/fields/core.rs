use super::super::urls::validate_https_url_field;
use super::scalar::required_string_field;
use crate::web::management::validate_redirect_uris;
use axum::response::Response;
use serde_json::{Map, Value};

pub(super) fn validate_federation_core_fields(
    federation: &Map<String, Value>,
    request_id: &str,
) -> Result<(), Response> {
    let upstream_issuer = required_string_field(
        federation,
        "upstreamIssuer",
        "configurationDocument.federation.upstreamIssuer is required",
        request_id,
    )?;
    let _ = validate_https_url_field(
        "configurationDocument.federation.upstreamIssuer",
        upstream_issuer,
        request_id,
    )?;

    let _client_id = required_string_field(
        federation,
        "clientId",
        "configurationDocument.federation.clientId is required",
        request_id,
    )?;

    let redirect_uri = required_string_field(
        federation,
        "redirectUri",
        "configurationDocument.federation.redirectUri is required",
        request_id,
    )?;
    let _ = validate_redirect_uris(&[redirect_uri.to_string()], request_id)?;
    Ok(())
}
