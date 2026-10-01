use aegaeon_jose::{jwt::JwtClaims, raw_json::RawJsonSurface};
use axum::response::Response;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use super::super::{AppState, CLIENT_ASSERTION_TYPE_JWT_BEARER};
use crate::util::{self, JsonObjectParseError, SignedAssertionClaimsError};

/// Unverified lookup identity only. Every caller must authenticate the assertion
/// with the registered method and key before authorizing any endpoint effect.
pub(in crate::web) fn private_key_jwt_client_id(
    state: &AppState,
    explicit_client_id: Option<&str>,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
) -> Result<Option<String>, Response> {
    if !state.cfg.grant_runtime().private_key_jwt_enabled()
        || assertion_type != Some(CLIENT_ASSERTION_TYPE_JWT_BEARER)
    {
        return Ok(None);
    }
    let Some(assertion) = assertion.filter(|value| {
        !value.is_empty() && value.len() <= super::super::router::SERVER_REQUEST_BODY_LIMIT_BYTES
    }) else {
        return Ok(None);
    };
    match util::decode_compact_jwt_header_without_duplicate_keys_with_max_len(
        assertion,
        state.cfg.jose_header_max_len,
    ) {
        Ok(_) => {}
        Err(JsonObjectParseError::BackendPolicy) => return Err(backend_error(state)),
        Err(_) => return Ok(None),
    }
    // Header admission has established exactly three segments. Require signed
    // compact syntax, including a nonempty, strictly base64url signature.
    let Some(signature) = assertion.rsplit('.').next().filter(|part| !part.is_empty()) else {
        return Ok(None);
    };
    if URL_SAFE_NO_PAD.decode(signature).is_err() {
        return Ok(None);
    }
    let Some(payload) = util::decode_compact_jwt_payload(assertion) else {
        return Ok(None);
    };
    let claims = match JwtClaims::decode_registered_claims_for_surface(
        RawJsonSurface::PrivateKeyJwtPayload,
        &payload,
    ) {
        Ok(claims) => claims,
        Err(error) => {
            return match util::signed_assertion_claims_error_from_jwt_claims_decode(&error) {
                SignedAssertionClaimsError::BackendPolicy => Err(backend_error(state)),
                _ => Ok(None),
            };
        }
    };
    Ok(claims.sub.filter(|subject| {
        !subject.is_empty() && explicit_client_id.is_none_or(|explicit| explicit == subject)
    }))
}

fn backend_error(state: &AppState) -> Response {
    super::client_auth::client_assertion_internal_error_response(
        state.issuer.as_str(),
        "private_key_jwt",
        "client assertion lookup parser backend misconfigured",
    )
}
