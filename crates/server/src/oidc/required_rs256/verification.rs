use super::super::id_token::IdTokenClaims;
use super::decode_id_token_payload_claims_without_duplicate_keys;
use super::RequiredRs256Error;
use aegaeon_jose::{verify_compact_with_context, JoseContext, JwsError, VerificationKey};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ffi::id_token::{self as ffi_id_token, IdTokenParserError};

pub fn verify_required_id_token_claims(
    token: &str,
    modulus_b64u: &str,
    exponent_b64u: &str,
) -> Result<IdTokenClaims, RequiredRs256Error> {
    precheck_id_token_structure(token)?;

    let modulus = URL_SAFE_NO_PAD
        .decode(modulus_b64u)
        .map_err(|_| RequiredRs256Error::InvalidKey)?;
    let exponent = URL_SAFE_NO_PAD
        .decode(exponent_b64u)
        .map_err(|_| RequiredRs256Error::InvalidKey)?;

    let payload = verify_compact_with_context(
        token,
        VerificationKey::RsaPkcs1Sha256 {
            modulus: &modulus,
            exponent: &exponent,
        },
        &JoseContext::default(),
    )
    .map_err(map_jws_error)?;

    decode_id_token_payload_claims_without_duplicate_keys(&payload)
}

fn precheck_id_token_structure(token: &str) -> Result<(), RequiredRs256Error> {
    finalize_structure_precheck(ffi_id_token::check_id_token_jwt(token.as_bytes()))
}

pub(super) fn finalize_structure_precheck(
    parse_result: Result<(), IdTokenParserError>,
) -> Result<(), RequiredRs256Error> {
    match parse_result {
        Ok(()) => Ok(()),
        Err(IdTokenParserError::ParserUnavailable) => Err(RequiredRs256Error::Internal(
            "OIDC ID Token structure parser unavailable in this build".to_string(),
        )),
        Err(IdTokenParserError::BufferTooLarge | IdTokenParserError::InvalidPayload) => {
            Err(RequiredRs256Error::InvalidStructure)
        }
    }
}

pub(super) fn map_jws_error(err: JwsError) -> RequiredRs256Error {
    match err {
        JwsError::InvalidKey(_) => RequiredRs256Error::InvalidKey,
        JwsError::JsonLowStar(aegaeon_jose::json_lowstar::JsonError::Internal(message)) => {
            RequiredRs256Error::Internal(message)
        }
        JwsError::JsonLowStar(aegaeon_jose::json_lowstar::JsonError::ParserUnavailable) => {
            RequiredRs256Error::Internal("JOSE header parser unavailable in this build".to_string())
        }
        JwsError::InvalidFormat
        | JwsError::Base64(_)
        | JwsError::Json(_)
        | JwsError::JsonLowStar(_)
        | JwsError::VerificationFailed
        | JwsError::UnsupportedAlgorithm(_)
        | JwsError::AlgorithmMismatch
        | JwsError::HeaderTooLong
        | JwsError::InvalidKid
        | JwsError::UnsupportedCriticalHeader(_)
        | JwsError::UnsupportedHeader(_)
        | JwsError::AlgorithmNotAllowed(_)
        | JwsError::Algorithm(_) => RequiredRs256Error::InvalidSignature,
    }
}
