use aegaeon_jose::{
    jwk::{Jwk, KeyMaterial},
    jwt::{JwtClaims, ValidationContext},
    raw_json::RawJsonSurface,
    verify_compact_with_context, JoseContext, VerificationKey,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use simple_asn1::ASN1Block;
use std::time::Duration;

use super::jwks_fetch::fetch_jwks_with_state;
use super::jwks_runtime_state::JwksRuntimeState;
use super::jwks_validation::{jwk_alg_allows, select_jwk};
use super::{unix_epoch_now_i64, JwksRuntimePolicy, RegisteredClient};
use crate::util::{
    signed_assertion_claims_error_from_jwt_claims_decode, SignedAssertionClaimsError,
};

fn decoding_key_from_inline_jwk(
    jwk: &Jwk,
    alg: jsonwebtoken::Algorithm,
) -> Option<jsonwebtoken::DecodingKey> {
    if !jwk_alg_allows(jwk.alg.as_deref(), alg) {
        return None;
    }
    match (&jwk.material, alg) {
        (
            KeyMaterial::Rsa { n, e },
            jsonwebtoken::Algorithm::RS256
            | jsonwebtoken::Algorithm::RS384
            | jsonwebtoken::Algorithm::RS512
            | jsonwebtoken::Algorithm::PS256
            | jsonwebtoken::Algorithm::PS384
            | jsonwebtoken::Algorithm::PS512,
        ) => jsonwebtoken::DecodingKey::from_rsa_components(n, e).ok(),
        (KeyMaterial::Ec { crv, x, y }, jsonwebtoken::Algorithm::ES256) if crv == "P-256" => {
            jsonwebtoken::DecodingKey::from_ec_components(x, y).ok()
        }
        (KeyMaterial::Ec { crv, x, y }, jsonwebtoken::Algorithm::ES384) if crv == "P-384" => {
            jsonwebtoken::DecodingKey::from_ec_components(x, y).ok()
        }
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PromotedRsaAlg {
    Rs256,
    Ps256,
}

impl PromotedRsaAlg {
    pub(super) fn from_jwt_algorithm(alg: jsonwebtoken::Algorithm) -> Option<Self> {
        match alg {
            jsonwebtoken::Algorithm::RS256 => Some(Self::Rs256),
            jsonwebtoken::Algorithm::PS256 => Some(Self::Ps256),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Ps256 => "PS256",
        }
    }

    fn verification_key<'a>(self, modulus: &'a [u8], exponent: &'a [u8]) -> VerificationKey<'a> {
        match self {
            Self::Rs256 => VerificationKey::RsaPkcs1Sha256 { modulus, exponent },
            Self::Ps256 => VerificationKey::RsaPssSha256 { modulus, exponent },
        }
    }
}

fn rsa_components_from_inline_jwk(
    jwk: &Jwk,
    expected_alg: PromotedRsaAlg,
) -> Option<(Vec<u8>, Vec<u8>)> {
    if jwk
        .alg
        .as_deref()
        .is_some_and(|alg| alg != expected_alg.name())
    {
        return None;
    }
    let KeyMaterial::Rsa { n, e } = &jwk.material else {
        return None;
    };
    let modulus = URL_SAFE_NO_PAD.decode(n).ok()?;
    let exponent = URL_SAFE_NO_PAD.decode(e).ok()?;
    Some((modulus, exponent))
}

pub(super) fn resolve_request_object_key_with_state(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    reg: &RegisteredClient,
    kid: Option<&str>,
    alg: jsonwebtoken::Algorithm,
) -> Option<jsonwebtoken::DecodingKey> {
    if let Some(pem) = &reg.jwks_pem {
        return match alg {
            jsonwebtoken::Algorithm::RS256
            | jsonwebtoken::Algorithm::RS384
            | jsonwebtoken::Algorithm::RS512
            | jsonwebtoken::Algorithm::PS256
            | jsonwebtoken::Algorithm::PS384
            | jsonwebtoken::Algorithm::PS512 => {
                jsonwebtoken::DecodingKey::from_rsa_pem(pem.as_bytes()).ok()
            }
            jsonwebtoken::Algorithm::ES256 | jsonwebtoken::Algorithm::ES384 => {
                jsonwebtoken::DecodingKey::from_ec_pem(pem.as_bytes()).ok()
            }
            _ => None,
        };
    }

    if let Some(inline_jwks) = &reg.inline_jwks {
        let jwk = inline_jwks.select(kid)?;
        return decoding_key_from_inline_jwk(jwk, alg);
    }

    let uri = reg.jwks_uri.as_ref()?;
    let jwks = fetch_jwks_with_state(state, policy, uri)?;
    let jwk = select_jwk(&jwks, kid)?;

    match alg {
        jsonwebtoken::Algorithm::RS256
        | jsonwebtoken::Algorithm::RS384
        | jsonwebtoken::Algorithm::RS512
        | jsonwebtoken::Algorithm::PS256
        | jsonwebtoken::Algorithm::PS384
        | jsonwebtoken::Algorithm::PS512
            if jwk.kty == "RSA" =>
        {
            if !jwk_alg_allows(jwk.alg.as_deref(), alg) {
                return None;
            }
            let n = jwk.n.as_ref()?;
            let e = jwk.e.as_ref()?;
            jsonwebtoken::DecodingKey::from_rsa_components(n, e).ok()
        }
        jsonwebtoken::Algorithm::ES256 | jsonwebtoken::Algorithm::ES384 if jwk.kty == "EC" => {
            if !jwk_alg_allows(jwk.alg.as_deref(), alg) {
                return None;
            }
            let x = jwk.x.as_ref()?;
            let y = jwk.y.as_ref()?;
            jsonwebtoken::DecodingKey::from_ec_components(x, y).ok()
        }
        _ => None,
    }
}

pub(super) fn resolve_promoted_rsa_verification_key_with_state(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    reg: &RegisteredClient,
    kid: Option<&str>,
    expected_alg: PromotedRsaAlg,
) -> Option<(Vec<u8>, Vec<u8>)> {
    if let Some(pem) = &reg.jwks_pem {
        return rsa_public_components_from_public_pem(pem);
    }

    if let Some(inline_jwks) = &reg.inline_jwks {
        let jwk = inline_jwks.select(kid)?;
        return rsa_components_from_inline_jwk(jwk, expected_alg);
    }

    let uri = reg.jwks_uri.as_ref()?;
    let jwks = fetch_jwks_with_state(state, policy, uri)?;
    let jwk = select_jwk(&jwks, kid)?;
    if jwk.kty != "RSA" {
        return None;
    }
    if jwk
        .alg
        .as_deref()
        .is_some_and(|alg| alg != expected_alg.name())
    {
        return None;
    }
    let modulus = URL_SAFE_NO_PAD.decode(jwk.n.as_deref()?).ok()?;
    let exponent = URL_SAFE_NO_PAD.decode(jwk.e.as_deref()?).ok()?;
    Some((modulus, exponent))
}

pub(super) fn verify_private_key_jwt_rsa_promoted(
    assertion: &str,
    modulus: &[u8],
    exponent: &[u8],
    algorithm: PromotedRsaAlg,
    client_id: &str,
    expected_aud: &str,
    leeway: u64,
) -> Result<JwtClaims, SignedAssertionClaimsError> {
    let payload = verify_compact_with_context(
        assertion,
        algorithm.verification_key(modulus, exponent),
        &JoseContext::default(),
    )
    .map_err(|_| SignedAssertionClaimsError::VerificationFailed)?;
    let claims = JwtClaims::decode_registered_claims_for_surface(
        RawJsonSurface::PrivateKeyJwtPayload,
        &payload,
    )
    .map_err(|err| signed_assertion_claims_error_from_jwt_claims_decode(&err))?;

    let Some(now) = unix_epoch_now_i64("private-key-jwt promoted RSA validation clock") else {
        return Err(SignedAssertionClaimsError::ClaimsInvalid);
    };
    let ctx = ValidationContext::builder()
        .now(now)
        .leeway(Duration::from_secs(leeway))
        .expected_issuer(client_id.to_string())
        .expected_subject(client_id.to_string())
        .allowed_audiences([expected_aud.to_string()])
        .require_issuer(true)
        .require_subject(true)
        .require_audience(true)
        .require_exp(true)
        .build();
    claims
        .validate(&ctx)
        .map_err(|_| SignedAssertionClaimsError::ClaimsInvalid)?;
    Ok(claims)
}

#[derive(Clone, Copy)]
pub(super) struct PromotedRsaVerificationKey<'a> {
    pub(super) modulus: &'a [u8],
    pub(super) exponent: &'a [u8],
}

#[derive(Clone, Copy)]
pub(super) struct JwtBearerPromotedRsaValidation<'a> {
    pub(super) client_id: &'a str,
    pub(super) expected_token_aud: &'a str,
    pub(super) expected_issuer_aud: &'a str,
    pub(super) allow_client_subject: bool,
    pub(super) leeway: u64,
}

pub(super) fn verify_jwt_bearer_rsa_promoted(
    assertion: &str,
    key: PromotedRsaVerificationKey<'_>,
    algorithm: PromotedRsaAlg,
    validation: JwtBearerPromotedRsaValidation<'_>,
) -> Result<JwtClaims, SignedAssertionClaimsError> {
    let payload = verify_compact_with_context(
        assertion,
        algorithm.verification_key(key.modulus, key.exponent),
        &JoseContext::default(),
    )
    .map_err(|_| SignedAssertionClaimsError::VerificationFailed)?;
    let claims = JwtClaims::decode_registered_claims_for_surface(
        RawJsonSurface::JwtBearerAssertionPayload,
        &payload,
    )
    .map_err(|err| signed_assertion_claims_error_from_jwt_claims_decode(&err))?;

    let Some(now) = unix_epoch_now_i64("jwt bearer RS256 validation clock") else {
        return Err(SignedAssertionClaimsError::ClaimsInvalid);
    };
    let allowed_audiences = if validation.allow_client_subject {
        vec![
            validation.expected_token_aud.to_string(),
            validation.expected_issuer_aud.to_string(),
        ]
    } else {
        vec![validation.expected_token_aud.to_string()]
    };
    let ctx = ValidationContext::builder()
        .now(now)
        .leeway(Duration::from_secs(validation.leeway))
        .expected_issuer(validation.client_id.to_string())
        .allowed_audiences(allowed_audiences)
        .require_issuer(true)
        .require_subject(true)
        .require_audience(true)
        .require_exp(true)
        .build();
    claims
        .validate(&ctx)
        .map_err(|_| SignedAssertionClaimsError::ClaimsInvalid)?;
    Ok(claims)
}

pub(super) fn rsa_public_components_from_public_pem(
    public_pem: &str,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let parsed = pem::parse(public_pem).ok()?;
    match parsed.tag() {
        "RSA PUBLIC KEY" => rsa_public_components_from_public_der(parsed.contents()),
        "PUBLIC KEY" => rsa_public_components_from_spki_public_der(parsed.contents()),
        _ => None,
    }
}

fn rsa_public_components_from_public_der(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let blocks = simple_asn1::from_der(der).ok()?;
    let ASN1Block::Sequence(_, seq) = blocks.first()? else {
        return None;
    };
    if seq.len() < 2 {
        return None;
    }
    let modulus = match &seq[0] {
        ASN1Block::Integer(_, n) => n.to_biguint()?.to_bytes_be(),
        _ => return None,
    };
    let exponent = match &seq[1] {
        ASN1Block::Integer(_, e) => e.to_biguint()?.to_bytes_be(),
        _ => return None,
    };
    Some((modulus, exponent))
}

fn rsa_public_components_from_spki_public_der(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let blocks = simple_asn1::from_der(der).ok()?;
    let ASN1Block::Sequence(_, seq) = blocks.first()? else {
        return None;
    };
    if seq.len() < 2 {
        return None;
    }
    let ASN1Block::BitString(_, _bit_len, public_key) = &seq[1] else {
        return None;
    };
    rsa_public_components_from_public_der(public_key).or_else(|| {
        public_key
            .strip_prefix(&[0x00])
            .and_then(rsa_public_components_from_public_der)
    })
}
