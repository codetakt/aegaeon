use axum::response::Response;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use super::common::{resolve_query_bounds_error, validate_federation_entity_id_parameter};

const FEDERATION_LIST_CURSOR_PREFIX: &str = "v1.";

pub(in crate::web) fn encode_federation_list_cursor(entity_id: &str) -> String {
    format!(
        "{FEDERATION_LIST_CURSOR_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(entity_id.as_bytes())
    )
}

pub(super) fn parse_optional_federation_list_cursor(
    values: &[String],
    issuer: &str,
) -> Result<Option<String>, Response> {
    let Some(value) = values.first() else {
        return Ok(None);
    };
    let value = value.trim();
    let Some(encoded) = value.strip_prefix(FEDERATION_LIST_CURSOR_PREFIX) else {
        return Err(resolve_query_bounds_error(
            "cursor query parameter must be a federation list cursor",
            issuer,
        ));
    };
    let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| {
        resolve_query_bounds_error("cursor query parameter must be base64url encoded", issuer)
    })?;
    let entity_id = String::from_utf8(decoded).map_err(|_| {
        resolve_query_bounds_error("cursor query parameter must decode to UTF-8", issuer)
    })?;
    validate_federation_entity_id_parameter("cursor", &entity_id, issuer).map(Some)
}
