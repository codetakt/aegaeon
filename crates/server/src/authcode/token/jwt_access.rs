use crate::kms::{AccessTokenVerifier, KeyManagerError};

mod decoder;
mod signer;
mod types;

use decoder::{deserialize_jwt_access_token_header, deserialize_jwt_access_token_payload};
pub(super) use signer::sign_jwt;
use types::access_token_parse_result;
pub(super) use types::JwtTokenParts;
pub(super) use types::{
    JwtAccessTokenAudience, JwtAccessTokenHeader, JwtAccessTokenPayload,
    JwtAccessTokenVerificationError,
};

pub(super) fn verify_jwt(
    token: &str,
    verifier: &dyn AccessTokenVerifier,
) -> Result<Option<JwtTokenParts>, JwtAccessTokenVerificationError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
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
    match verifier.verify_access_token_signature(kid, alg, signing_input.as_bytes(), &sig) {
        Ok(true) => {}
        Ok(false) | Err(KeyManagerError::KeyNotFound | KeyManagerError::KeyRevoked) => {
            return Ok(None)
        }
        Err(error) => return Err(error.into()),
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
