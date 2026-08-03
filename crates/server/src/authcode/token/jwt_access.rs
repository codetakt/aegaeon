use crate::kms::KeyManager;

mod decoder;
mod signer;
mod types;

use decoder::{deserialize_jwt_access_token_header, deserialize_jwt_access_token_payload};
pub(super) use signer::sign_jwt;
use types::{access_token_parse_result, JwtTokenParts};
pub(super) use types::{
    JwtAccessTokenAudience, JwtAccessTokenHeader, JwtAccessTokenPayload,
    JwtAccessTokenVerificationError,
};

pub(super) fn verify_jwt(
    token: &str,
    key_manager: &dyn KeyManager,
) -> Result<Option<JwtTokenParts>, JwtAccessTokenVerificationError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Ok(None);
    }

    let Ok(header_bytes) = URL_SAFE_NO_PAD.decode(parts[0]) else {
        return Ok(None);
    };
    let Some(header) =
        access_token_parse_result(deserialize_jwt_access_token_header(&header_bytes))?
    else {
        return Ok(None);
    };
    let Some(kid) = header.kid.as_deref() else {
        return Ok(None);
    };
    let Some(alg) = header.alg.as_deref() else {
        return Ok(None);
    };

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let Ok(sig) = URL_SAFE_NO_PAD.decode(parts[2]) else {
        return Ok(None);
    };
    if !key_manager.verify_jwt_signature(kid, alg, signing_input.as_bytes(), &sig)? {
        return Ok(None);
    }

    let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(parts[1]) else {
        return Ok(None);
    };
    let Some(payload) =
        access_token_parse_result(deserialize_jwt_access_token_payload(&payload_bytes))?
    else {
        return Ok(None);
    };
    Ok(Some(JwtTokenParts { header, payload }))
}
