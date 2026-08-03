use super::super::upstream_metadata::select_upstream_signing_key;
use super::algorithms::{jwt_alg_curve, jwt_alg_name, jwt_alg_requires_rsa};
use super::errors::UpstreamIdTokenSignatureError;
use aegaeon_jose::jwk::{JwkSet, KeyMaterial};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::oidc::{required_rs256, IdTokenClaims, OidcDiscovery};
use crate::util;

pub(in crate::web) fn verify_compact_jwt_payload_with_key(
    token: &str,
    decoding_key: &jsonwebtoken::DecodingKey,
    alg: jsonwebtoken::Algorithm,
) -> Result<Vec<u8>, UpstreamIdTokenSignatureError> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(UpstreamIdTokenSignatureError::SignatureInvalid);
    };
    let signing_input = format!("{header}.{payload}");
    match jsonwebtoken::crypto::verify(signature, signing_input.as_bytes(), decoding_key, alg) {
        Ok(true) => URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| UpstreamIdTokenSignatureError::PayloadInvalid),
        Ok(false) | Err(_) => Err(UpstreamIdTokenSignatureError::SignatureInvalid),
    }
}

fn decode_id_token_claims_from_admitted_payload(
    payload: &[u8],
) -> Result<IdTokenClaims, UpstreamIdTokenSignatureError> {
    required_rs256::decode_id_token_payload_claims_without_duplicate_keys(payload).map_err(|err| {
        match err {
            required_rs256::RequiredRs256Error::Internal(message) => {
                UpstreamIdTokenSignatureError::Internal(message)
            }
            required_rs256::RequiredRs256Error::InvalidStructure
            | required_rs256::RequiredRs256Error::InvalidPayload
            | required_rs256::RequiredRs256Error::InvalidKey
            | required_rs256::RequiredRs256Error::InvalidSignature
            | required_rs256::RequiredRs256Error::Signing(_) => {
                UpstreamIdTokenSignatureError::PayloadInvalid
            }
        }
    })
}

pub(in crate::web) fn verify_upstream_id_token_claims(
    token: &str,
    jwks: &JwkSet,
    discovery: &OidcDiscovery,
    jose_header_max_len: usize,
) -> Result<(IdTokenClaims, &'static str), UpstreamIdTokenSignatureError> {
    let header = util::decode_compact_jwt_header_without_duplicate_keys_with_max_len(
        token,
        jose_header_max_len,
    )
    .map_err(|err| match err {
        util::JsonObjectParseError::BackendPolicy => UpstreamIdTokenSignatureError::Internal(
            "unsupported raw JSON backend for jose-header".to_string(),
        ),
        util::JsonObjectParseError::DuplicateKey
        | util::JsonObjectParseError::InvalidJson
        | util::JsonObjectParseError::TrailingBytes
        | util::JsonObjectParseError::InvalidShape => UpstreamIdTokenSignatureError::HeaderInvalid,
    })?;
    let alg = header.alg;
    let alg_name = jwt_alg_name(alg).ok_or(UpstreamIdTokenSignatureError::AlgNotAllowed)?;
    if !discovery
        .id_token_signing_alg_values_supported
        .iter()
        .any(|value| value.eq_ignore_ascii_case(alg_name))
    {
        return Err(UpstreamIdTokenSignatureError::AlgNotSupported);
    }

    let jwk = select_upstream_signing_key(jwks, header.kid.as_deref())
        .map_err(UpstreamIdTokenSignatureError::KeySelection)?;
    if let Some(jwk_alg) = jwk.alg.as_deref() {
        if !jwk_alg.eq_ignore_ascii_case(alg_name) {
            return Err(UpstreamIdTokenSignatureError::JwkAlgMismatch);
        }
    }

    let claims = match (&jwk.material, alg, jwt_alg_curve(alg)) {
        (KeyMaterial::Rsa { n, e }, jsonwebtoken::Algorithm::RS256, _) => {
            required_rs256::verify_required_id_token_claims(token, n.as_str(), e.as_str()).map_err(
                |err| match err {
                    required_rs256::RequiredRs256Error::InvalidKey => {
                        UpstreamIdTokenSignatureError::RsaKeyInvalid
                    }
                    required_rs256::RequiredRs256Error::Internal(message) => {
                        UpstreamIdTokenSignatureError::Internal(message)
                    }
                    _ => UpstreamIdTokenSignatureError::SignatureInvalid,
                },
            )?
        }
        (KeyMaterial::Rsa { n, e }, rsa_alg, _) if jwt_alg_requires_rsa(rsa_alg) => {
            let decoding_key =
                jsonwebtoken::DecodingKey::from_rsa_components(n.as_str(), e.as_str())
                    .map_err(|_| UpstreamIdTokenSignatureError::RsaKeyInvalid)?;
            let payload = verify_compact_jwt_payload_with_key(token, &decoding_key, rsa_alg)?;
            decode_id_token_claims_from_admitted_payload(&payload)?
        }
        (KeyMaterial::Ec { crv, x, y }, ec_alg, Some(expected)) => {
            if !crv.eq_ignore_ascii_case(expected) {
                return Err(UpstreamIdTokenSignatureError::CurveMismatch);
            }
            let decoding_key =
                jsonwebtoken::DecodingKey::from_ec_components(x.as_str(), y.as_str())
                    .map_err(|_| UpstreamIdTokenSignatureError::EcKeyInvalid)?;
            let payload = verify_compact_jwt_payload_with_key(token, &decoding_key, ec_alg)?;
            decode_id_token_claims_from_admitted_payload(&payload)?
        }
        _ => return Err(UpstreamIdTokenSignatureError::KeyTypeMismatch),
    };

    Ok((claims, alg_name))
}
