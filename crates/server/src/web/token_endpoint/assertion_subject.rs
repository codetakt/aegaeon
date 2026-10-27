use aegaeon_jose::{jwt::JwtClaims, raw_json::RawJsonSurface};
use axum::response::Response;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use super::super::{AppState, CLIENT_ASSERTION_TYPE_JWT_BEARER};
use crate::util::{self, JsonObjectParseError, SignedAssertionClaimsError};

/// Unverified lookup identity only. Every caller must authenticate the assertion
/// with the registered method and key before authorizing any endpoint effect.
pub(in crate::web) async fn private_key_jwt_client_id(
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
    let assertion = assertion.to_owned();
    let explicit_client_id = explicit_client_id.map(str::to_owned);
    let header_max_len = state.cfg.jose_header_max_len;
    run_lookup_parser(move || {
        parse_client_id(&assertion, explicit_client_id.as_deref(), header_max_len)
    })
    .await
    .map_err(|error| {
        super::client_auth::client_assertion_internal_error_response(
            state.issuer.as_str(),
            "private_key_jwt",
            match error {
                LookupError::BackendPolicy => {
                    "client assertion lookup parser backend misconfigured"
                }
                LookupError::TaskFailed => "client assertion lookup parser task failed",
            },
        )
    })
}

#[derive(Debug, PartialEq)]
enum LookupError {
    BackendPolicy,
    TaskFailed,
}

async fn run_lookup_parser(
    parser: impl FnOnce() -> Result<Option<String>, LookupError> + Send + 'static,
) -> Result<Option<String>, LookupError> {
    tokio::task::spawn_blocking(parser)
        .await
        .map_err(|_| LookupError::TaskFailed)?
}

fn parse_client_id(
    assertion: &str,
    explicit_client_id: Option<&str>,
    header_max_len: usize,
) -> Result<Option<String>, LookupError> {
    match util::decode_compact_jwt_header_without_duplicate_keys_with_max_len(
        assertion,
        header_max_len,
    ) {
        Ok(_) => {}
        Err(JsonObjectParseError::BackendPolicy) => return Err(LookupError::BackendPolicy),
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
                SignedAssertionClaimsError::BackendPolicy => Err(LookupError::BackendPolicy),
                _ => Ok(None),
            };
        }
    };
    Ok(claims.sub.filter(|subject| {
        !subject.is_empty() && explicit_client_id.is_none_or(|explicit| explicit == subject)
    }))
}

#[cfg(test)]
#[path = "assertion_subject/tests.rs"]
mod tests;
