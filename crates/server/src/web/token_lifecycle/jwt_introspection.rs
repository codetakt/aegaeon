use super::super::metadata::jwt_introspection_key_manager;
use super::super::oauth_errors::{json_error_with_iss, no_cache_json_error_with_iss};
use super::super::{clock_error_response, AppState};
use axum::{
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

use crate::config::MAX_JWT_INTROSPECTION_EXP_SECS;
use crate::kms::KeyManager;
use crate::upstream::random_token;
use crate::util;

const JWT_INTROSPECTION_CONTENT_TYPE: &str = "application/token-introspection+jwt";
const JWT_INTROSPECTION_TYP: &str = "token-introspection+jwt";

pub(super) fn wants_jwt_introspection(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| {
            accept
                .split(',')
                .any(|part| part.trim().starts_with(JWT_INTROSPECTION_CONTENT_TYPE))
        })
}

pub(super) fn build_jwt_introspection_response(
    state: &AppState,
    introspection_claims: &Value,
    requesting_client: Option<&str>,
) -> Response {
    let Some(requesting_client) = requesting_client else {
        return util::invalid_client_response(
            "token_introspection",
            "Client authentication is required for JWT introspection responses",
        );
    };

    let key_manager = jwt_introspection_key_manager(state);
    if key_manager.jwt_signing_public_jwk().is_none() {
        let mut response = json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("JWT introspection signing requires public verification material"),
            state.issuer.as_str(),
        );
        util::apply_no_cache_headers(&mut response);
        return response;
    }

    let now = match util::now_unix_epoch_secs() {
        Ok(now) => now,
        Err(err) => {
            util::log_clock_error("jwt introspection clock", &err);
            return clock_error_response(state.issuer.as_str());
        }
    };
    let exp_secs = state
        .cfg
        .jwt_runtime()
        .introspection_exp_secs()
        .min(MAX_JWT_INTROSPECTION_EXP_SECS);
    let Some(exp) = now.checked_add(exp_secs) else {
        return no_cache_json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("failed to build introspection response expiry"),
            state.issuer.as_str(),
        );
    };

    let mut jwt_payload = json!({
        "iss": state.issuer.as_str(),
        "iat": now,
        "exp": exp,
        "token_introspection": introspection_claims,
    });
    jwt_payload["aud"] = json!(requesting_client);
    jwt_payload["jti"] = json!(format!("ji-{}-{}", now, random_token(8)));

    let Ok(jwt) = sign_jwt_introspection(&jwt_payload, key_manager) else {
        let mut response = json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("failed to sign introspection JWT"),
            state.issuer.as_str(),
        );
        util::apply_no_cache_headers(&mut response);
        return response;
    };

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, JWT_INTROSPECTION_CONTENT_TYPE)
        .body(axum::body::Body::from(jwt))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response());
    util::apply_no_cache_headers(&mut response);
    response
}

fn sign_jwt_introspection(
    payload: &Value,
    key_manager: &dyn KeyManager,
) -> Result<String, crate::kms::KeyManagerError> {
    let header = json!({
        "alg": key_manager.jwt_signing_alg(),
        "typ": JWT_INTROSPECTION_TYP,
        "kid": key_manager.key_id(),
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header).map_err(|_| crate::kms::KeyManagerError::OperationFailed)?,
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(payload).map_err(|_| crate::kms::KeyManagerError::OperationFailed)?,
    );
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = key_manager.sign(signing_input.as_bytes())?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
    Ok(format!("{signing_input}.{sig_b64}"))
}
