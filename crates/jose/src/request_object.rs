use crate::jws::{verify_compact_with_context, JwsError, VerificationKey};
use crate::jwt::{JwtClaims, JwtValidationError, ValidationContext};
use crate::policy::JoseContext;
use crate::raw_json::{self, RawJsonObjectError, RawJsonSurface};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use serde_json::{Map, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// JOSE signing algorithm supported by Request Object verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestObjectSigningAlgorithm {
    name: &'static str,
    jwt_algorithm: jsonwebtoken::Algorithm,
}

impl RequestObjectSigningAlgorithm {
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    #[must_use]
    pub const fn jwt_algorithm(self) -> jsonwebtoken::Algorithm {
        self.jwt_algorithm
    }
}

/// Canonical Request Object signing algorithm inventory.
pub const REQUEST_OBJECT_SIGNING_ALGORITHMS: &[RequestObjectSigningAlgorithm] = &[
    RequestObjectSigningAlgorithm {
        name: "RS256",
        jwt_algorithm: jsonwebtoken::Algorithm::RS256,
    },
    RequestObjectSigningAlgorithm {
        name: "RS384",
        jwt_algorithm: jsonwebtoken::Algorithm::RS384,
    },
    RequestObjectSigningAlgorithm {
        name: "RS512",
        jwt_algorithm: jsonwebtoken::Algorithm::RS512,
    },
    RequestObjectSigningAlgorithm {
        name: "PS256",
        jwt_algorithm: jsonwebtoken::Algorithm::PS256,
    },
    RequestObjectSigningAlgorithm {
        name: "PS384",
        jwt_algorithm: jsonwebtoken::Algorithm::PS384,
    },
    RequestObjectSigningAlgorithm {
        name: "PS512",
        jwt_algorithm: jsonwebtoken::Algorithm::PS512,
    },
    RequestObjectSigningAlgorithm {
        name: "ES256",
        jwt_algorithm: jsonwebtoken::Algorithm::ES256,
    },
    RequestObjectSigningAlgorithm {
        name: "ES384",
        jwt_algorithm: jsonwebtoken::Algorithm::ES384,
    },
];

#[must_use]
pub fn request_object_signing_algorithm_supported(alg: jsonwebtoken::Algorithm) -> bool {
    REQUEST_OBJECT_SIGNING_ALGORITHMS
        .iter()
        .any(|supported| supported.jwt_algorithm() == alg)
}

#[derive(Debug, Error)]
pub enum RequestObjectError {
    #[error("Invalid request object format")]
    InvalidFormat,

    #[error("JWT decode error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("JWS verification error: {0}")]
    Jws(#[from] JwsError),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("JWT validation error: {0}")]
    JwtValidation(#[from] JwtValidationError),

    #[error("Unsupported request object algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Request Object policy violation: {0}")]
    PolicyViolation(String),

    #[error("Request Object internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct RequestObjectClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct RequestObjectVerification {
    pub claims: RequestObjectClaims,
    pub kid: Option<String>,
    pub algorithm: jsonwebtoken::Algorithm,
}

fn map_raw_json_object_error(err: RawJsonObjectError) -> RequestObjectError {
    match err {
        RawJsonObjectError::InvalidBackendPolicy(err) => {
            RequestObjectError::Internal(err.to_string())
        }
        RawJsonObjectError::DuplicateKey => {
            RequestObjectError::PolicyViolation("duplicate-key".to_string())
        }
        RawJsonObjectError::InvalidJson(err)
        | RawJsonObjectError::TrailingBytes(err)
        | RawJsonObjectError::InvalidShape(err) => RequestObjectError::Json(err),
    }
}

fn invalid_request_object_claim_type(key: &str, expected: &str) -> RequestObjectError {
    RequestObjectError::Json(serde_json::Error::io(std::io::Error::other(format!(
        "request object claim `{key}` must be {expected}"
    ))))
}

fn parse_request_object_members_raw(
    payload: &[u8],
) -> Result<Vec<raw_json::RawJsonObjectMember>, RequestObjectError> {
    let report = raw_json::parse_json_object_members_with_report_for_surface(
        RawJsonSurface::RequestObject,
        payload,
    )
    .map_err(map_raw_json_object_error)?;
    raw_json::ensure_unique_object_keys(&report.value).map_err(map_raw_json_object_error)?;
    Ok(report.value)
}

fn parse_optional_string_claim(
    key: &str,
    value: &Value,
) -> Result<Option<String>, RequestObjectError> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value.clone())),
        _ => Err(invalid_request_object_claim_type(key, "a string or null")),
    }
}

fn parse_optional_u64_claim(key: &str, value: &Value) -> Result<Option<u64>, RequestObjectError> {
    match value {
        Value::Null => Ok(None),
        Value::Number(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| invalid_request_object_claim_type(key, "a non-negative integer")),
        _ => Err(invalid_request_object_claim_type(
            key,
            "a non-negative integer or null",
        )),
    }
}

fn parse_optional_i64_claim(key: &str, value: &Value) -> Result<Option<i64>, RequestObjectError> {
    match value {
        Value::Null => Ok(None),
        Value::Number(value) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| invalid_request_object_claim_type(key, "an integer")),
        _ => Err(invalid_request_object_claim_type(key, "an integer or null")),
    }
}

fn parse_optional_audience_claim(
    key: &str,
    value: &Value,
) -> Result<(Option<Vec<String>>, Option<Value>), RequestObjectError> {
    match value {
        Value::Null => Ok((None, None)),
        Value::String(value) => Ok((
            Some(vec![value.clone()]),
            Some(Value::String(value.clone())),
        )),
        Value::Array(values) => {
            let mut audience = Vec::with_capacity(values.len());
            for value in values {
                let Value::String(value) = value else {
                    return Err(invalid_request_object_claim_type(
                        key,
                        "a string or an array of strings",
                    ));
                };
                audience.push(value.clone());
            }
            Ok((Some(audience), Some(Value::Array(values.clone()))))
        }
        _ => Err(invalid_request_object_claim_type(
            key,
            "a string, an array of strings, or null",
        )),
    }
}

fn parse_optional_open_json_claim(value: &Value) -> Option<Value> {
    if value.is_null() {
        None
    } else {
        Some(value.clone())
    }
}

fn parse_request_object_claim_sets_raw(
    payload: &[u8],
) -> Result<(RequestObjectClaims, JwtClaims), RequestObjectError> {
    let members = parse_request_object_members_raw(payload)?;
    decode_request_object_claim_sets_from_members(&members)
}

fn insert_member_clone(map: &mut Map<String, Value>, member: &raw_json::RawJsonObjectMember) {
    map.insert(member.key.clone(), member.value.clone());
}

fn decode_registered_jwt_member(
    member: &raw_json::RawJsonObjectMember,
    request_object_claims: &mut RequestObjectClaims,
    request_extra: &mut Map<String, Value>,
    jwt_claims: &mut JwtClaims,
) -> Result<bool, RequestObjectError> {
    match member.key.as_str() {
        "iss" => {
            let value = parse_optional_string_claim(&member.key, &member.value)?;
            request_object_claims.iss.clone_from(&value);
            jwt_claims.iss = value;
            Ok(true)
        }
        "sub" => {
            jwt_claims.sub = parse_optional_string_claim(&member.key, &member.value)?;
            insert_member_clone(request_extra, member);
            Ok(true)
        }
        "aud" => {
            let (request_aud, jwt_aud) = parse_optional_audience_claim(&member.key, &member.value)?;
            request_object_claims.aud = request_aud;
            jwt_claims.aud = jwt_aud;
            Ok(true)
        }
        "exp" => {
            request_object_claims.exp = parse_optional_u64_claim(&member.key, &member.value)?;
            jwt_claims.exp = parse_optional_i64_claim(&member.key, &member.value)?;
            Ok(true)
        }
        "nbf" => {
            request_object_claims.nbf = parse_optional_u64_claim(&member.key, &member.value)?;
            jwt_claims.nbf = parse_optional_i64_claim(&member.key, &member.value)?;
            Ok(true)
        }
        "iat" => {
            jwt_claims.iat = parse_optional_i64_claim(&member.key, &member.value)?;
            insert_member_clone(request_extra, member);
            Ok(true)
        }
        "jti" => {
            let value = parse_optional_string_claim(&member.key, &member.value)?;
            request_object_claims.jti.clone_from(&value);
            jwt_claims.jti = value;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn decode_authorization_request_member(
    member: &raw_json::RawJsonObjectMember,
    request_object_claims: &mut RequestObjectClaims,
    jwt_custom: &mut Map<String, Value>,
) -> Result<bool, RequestObjectError> {
    match member.key.as_str() {
        "client_id" => {
            request_object_claims.client_id =
                parse_optional_string_claim(&member.key, &member.value)?;
        }
        "redirect_uri" => {
            request_object_claims.redirect_uri =
                parse_optional_string_claim(&member.key, &member.value)?;
        }
        "response_type" => {
            request_object_claims.response_type =
                parse_optional_string_claim(&member.key, &member.value)?;
        }
        "scope" => {
            request_object_claims.scope = parse_optional_string_claim(&member.key, &member.value)?;
        }
        "state" => {
            request_object_claims.state = parse_optional_string_claim(&member.key, &member.value)?;
        }
        "nonce" => {
            request_object_claims.nonce = parse_optional_string_claim(&member.key, &member.value)?;
        }
        "code_challenge" => {
            request_object_claims.code_challenge =
                parse_optional_string_claim(&member.key, &member.value)?;
        }
        "code_challenge_method" => {
            request_object_claims.code_challenge_method =
                parse_optional_string_claim(&member.key, &member.value)?;
        }
        "response_mode" => {
            request_object_claims.response_mode =
                parse_optional_string_claim(&member.key, &member.value)?;
        }
        "acr_values" => {
            request_object_claims.acr_values =
                parse_optional_string_claim(&member.key, &member.value)?;
        }
        "max_age" => {
            request_object_claims.max_age = parse_optional_u64_claim(&member.key, &member.value)?;
        }
        "authorization_details" => {
            request_object_claims.authorization_details =
                parse_optional_open_json_claim(&member.value);
        }
        _ => return Ok(false),
    }
    insert_member_clone(jwt_custom, member);
    Ok(true)
}

fn decode_request_object_claim_sets_from_members(
    members: &[raw_json::RawJsonObjectMember],
) -> Result<(RequestObjectClaims, JwtClaims), RequestObjectError> {
    let mut request_object_claims = RequestObjectClaims::default();
    let mut request_extra = Map::new();
    let mut jwt_custom = Map::new();
    let mut jwt_claims = JwtClaims {
        iss: None,
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
        jti: None,
        custom: Value::Object(Map::new()),
    };

    for member in members {
        if decode_registered_jwt_member(
            member,
            &mut request_object_claims,
            &mut request_extra,
            &mut jwt_claims,
        )? || decode_authorization_request_member(
            member,
            &mut request_object_claims,
            &mut jwt_custom,
        )? {
            continue;
        }
        insert_member_clone(&mut request_extra, member);
        insert_member_clone(&mut jwt_custom, member);
    }

    if !request_extra.is_empty() {
        request_object_claims.extra = Some(Value::Object(request_extra));
    }
    jwt_claims.custom = Value::Object(jwt_custom);

    Ok((request_object_claims, jwt_claims))
}

fn validate_request_object_jwt_claims(
    claims: &JwtClaims,
    expected_aud: &[String],
    leeway: u64,
) -> Result<(), RequestObjectError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
        .cast_signed();

    let mut ctx_builder = ValidationContext::builder()
        .now(now)
        .leeway(Duration::from_secs(leeway))
        .require_exp(true);
    if expected_aud.is_empty() {
        ctx_builder = ctx_builder.require_audience(false);
    } else {
        ctx_builder = ctx_builder
            .allowed_audiences(expected_aud.iter().cloned())
            .require_audience(true);
    }
    claims.validate(&ctx_builder.build())?;
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_request_object_claims_raw(
    payload: &[u8],
) -> Result<RequestObjectClaims, RequestObjectError> {
    parse_request_object_claim_sets_raw(payload).map(|(claims, _)| claims)
}

fn decode_request_object_payload(token: &str) -> Result<Vec<u8>, RequestObjectError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(RequestObjectError::InvalidFormat);
    }
    Ok(URL_SAFE_NO_PAD.decode(parts[1])?)
}

/// Verify a Request Object using a `jsonwebtoken` decoding key.
///
/// # Errors
///
/// Returns [`RequestObjectError`] when the JWT header/claims are malformed, the
/// algorithm is unsupported, signature validation fails, or duplicate-key JSON
/// admission rejects the payload.
pub fn verify_request_object(
    token: &str,
    decoding_key: &jsonwebtoken::DecodingKey,
    expected_aud: &[String],
    leeway: u64,
) -> Result<RequestObjectVerification, RequestObjectError> {
    let header = jsonwebtoken::decode_header(token)?;
    let alg = header.alg;

    if !request_object_signing_algorithm_supported(alg) {
        return Err(RequestObjectError::UnsupportedAlgorithm(format!("{alg:?}")));
    }

    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();

    jsonwebtoken::decode::<Value>(token, decoding_key, &validation)?;
    let payload = decode_request_object_payload(token)?;
    let (claims, jwt_claims) = parse_request_object_claim_sets_raw(&payload)?;
    validate_request_object_jwt_claims(&jwt_claims, expected_aud, leeway)?;

    Ok(RequestObjectVerification {
        claims,
        kid: header.kid,
        algorithm: alg,
    })
}

/// Verify an `RS256` Request Object through the promoted verified path.
///
/// # Errors
///
/// Returns [`RequestObjectError`] when the header algorithm is not `RS256`,
/// signature verification fails, temporal/audience validation fails, or the
/// payload violates duplicate-key JSON policy.
pub fn verify_request_object_rs256_promoted(
    token: &str,
    modulus: &[u8],
    exponent: &[u8],
    expected_aud: &[String],
    leeway: u64,
) -> Result<RequestObjectVerification, RequestObjectError> {
    verify_request_object_rsa_promoted(
        token,
        expected_aud,
        leeway,
        jsonwebtoken::Algorithm::RS256,
        VerificationKey::RsaPkcs1Sha256 { modulus, exponent },
    )
}

/// Verify a `PS256` Request Object through the promoted verified path.
///
/// # Errors
///
/// Returns [`RequestObjectError`] when the header algorithm is not `PS256`,
/// signature verification fails, temporal/audience validation fails, or the
/// payload violates duplicate-key JSON policy.
pub fn verify_request_object_ps256_promoted(
    token: &str,
    modulus: &[u8],
    exponent: &[u8],
    expected_aud: &[String],
    leeway: u64,
) -> Result<RequestObjectVerification, RequestObjectError> {
    verify_request_object_rsa_promoted(
        token,
        expected_aud,
        leeway,
        jsonwebtoken::Algorithm::PS256,
        VerificationKey::RsaPssSha256 { modulus, exponent },
    )
}

fn verify_request_object_rsa_promoted(
    token: &str,
    expected_aud: &[String],
    leeway: u64,
    expected_alg: jsonwebtoken::Algorithm,
    verification_key: VerificationKey<'_>,
) -> Result<RequestObjectVerification, RequestObjectError> {
    let header = jsonwebtoken::decode_header(token)?;
    let alg = header.alg;
    if alg != expected_alg {
        return Err(RequestObjectError::UnsupportedAlgorithm(format!("{alg:?}")));
    }

    let payload = verify_compact_with_context(token, verification_key, &JoseContext::default())?;
    let (request_object_claims, claims) = parse_request_object_claim_sets_raw(&payload)?;
    validate_request_object_jwt_claims(&claims, expected_aud, leeway)?;

    Ok(RequestObjectVerification {
        claims: request_object_claims,
        kid: header.kid,
        algorithm: alg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegaeon_crypto::signing::RsaPssSigner;
    use base64::engine::general_purpose::STANDARD;
    use jsonwebtoken::{crypto, Algorithm, DecodingKey, EncodingKey, Header};
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::DecodePrivateKey;
    use simple_asn1::ASN1Block;
    use std::error::Error;
    use std::io::Error as IoError;
    use std::sync::MutexGuard;

    const TEST_EC_PRIVATE_KEY_PEM: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../server/tests/fixtures/p256-private.pk8.pem"
    ));
    const TEST_EC_PUBLIC_KEY_PEM: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../server/tests/fixtures/p256-public.pem"
    ));
    const TEST_RSA_PRIVATE_KEY_PEM: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../server/tests/fixtures/rsa2048-private.pk8.pem"
    ));
    const TEST_RSA_PUBLIC_KEY_PEM: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../server/tests/fixtures/rsa2048-public.pem"
    ));

    type TestResult = Result<(), Box<dyn Error>>;

    fn lock_raw_json_env_guard() -> Result<MutexGuard<'static, ()>, IoError> {
        crate::raw_json::RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))
    }

    struct RawJsonBackendOverrideGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl Drop for RawJsonBackendOverrideGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn use_compat_request_object_backend() -> RawJsonBackendOverrideGuard {
        let key = raw_json::raw_json_backend_env_var_for_surface(RawJsonSurface::RequestObject);
        let previous = std::env::var(key).ok();
        std::env::set_var(key, "serde-compat");
        RawJsonBackendOverrideGuard { key, previous }
    }

    fn build_compact_jwt_none_alg(
        payload_json: &serde_json::Value,
    ) -> Result<String, Box<dyn Error>> {
        let header = serde_json::json!({ "alg": "none", "typ": "JWT" });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload_json)?);
        // Signature is ignored for alg=none in this test; include a dummy segment so decode_header succeeds.
        Ok(format!("{header_b64}.{payload_b64}.c2ln"))
    }

    fn sign_compact_es256_payload(payload_json: &str) -> Result<String, Box<dyn Error>> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("request-object-test-key".to_string());
        let header_json = serde_json::to_vec(&header)?;
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");

        let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(TEST_EC_PRIVATE_KEY_PEM)?;
        let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("{header_b64}.{payload_b64}.{signature_b64}"))
    }

    fn sign_compact_rs256_payload(payload_json: &str) -> Result<String, Box<dyn Error>> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("request-object-rs256-test-key".to_string());
        let header_json = serde_json::to_vec(&header)?;
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let encoding_key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())?;
        let signature = crypto::sign(signing_input.as_bytes(), &encoding_key, Algorithm::RS256)?;

        Ok(format!("{signing_input}.{signature}"))
    }

    fn sign_compact_pss_payload(
        payload_json: &str,
        algorithm: Algorithm,
    ) -> Result<String, Box<dyn Error>> {
        let mut header = Header::new(algorithm);
        header.kid = Some("request-object-pss-test-key".to_string());
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let private_key = decode_pem_body(TEST_RSA_PRIVATE_KEY_PEM)?;
        let signer = RsaPssSigner::from_pkcs8(&private_key)?;
        let signature = match algorithm {
            Algorithm::PS256 => signer.sign_pss256(signing_input.as_bytes())?,
            Algorithm::PS384 => signer.sign_pss384(signing_input.as_bytes())?,
            _ => return Err(IoError::other("unsupported PSS test algorithm").into()),
        };

        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn decode_pem_body(pem_text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let body = pem_text
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        Ok(STANDARD.decode(body.as_bytes())?)
    }

    fn rsa_public_components_from_der(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
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

    fn rsa_public_components_from_spki_der(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
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
        rsa_public_components_from_der(public_key).or_else(|| {
            public_key
                .strip_prefix(&[0x00])
                .and_then(rsa_public_components_from_der)
        })
    }

    fn sample_rsa_public_components() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        let der = decode_pem_body(TEST_RSA_PUBLIC_KEY_PEM)?;
        rsa_public_components_from_spki_der(&der)
            .ok_or_else(|| IoError::other("rsa public components missing").into())
    }

    fn sample_time_window() -> (u64, u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs();
        (now + 300, now.saturating_sub(5))
    }

    fn valid_promoted_request_object_payload() -> String {
        let (exp, nbf) = sample_time_window();
        format!(
            r#"{{"iss":"client-123","aud":["https://issuer.example"],"exp":{exp},"nbf":{nbf},"client_id":"client-123","jti":"jti-123"}}"#
        )
    }

    #[test]
    fn request_object_ps256_promoted_accepts_valid_signature() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let _backend = use_compat_request_object_backend();
        let token =
            sign_compact_pss_payload(&valid_promoted_request_object_payload(), Algorithm::PS256)?;
        let (modulus, exponent) = sample_rsa_public_components()?;

        let verified = verify_request_object_ps256_promoted(
            &token,
            &modulus,
            &exponent,
            &["https://issuer.example".to_string()],
            60,
        )?;

        assert_eq!(verified.algorithm, Algorithm::PS256);
        Ok(())
    }

    #[test]
    fn request_object_ps256_promoted_rejects_rs256_header() -> TestResult {
        let token = sign_compact_rs256_payload(&valid_promoted_request_object_payload())?;
        let (modulus, exponent) = sample_rsa_public_components()?;

        assert!(matches!(
            verify_request_object_ps256_promoted(
                &token,
                &modulus,
                &exponent,
                &["https://issuer.example".to_string()],
                60,
            ),
            Err(RequestObjectError::UnsupportedAlgorithm(_))
        ));
        Ok(())
    }

    #[test]
    fn request_object_ps256_promoted_rejects_modified_signature() -> TestResult {
        let token =
            sign_compact_pss_payload(&valid_promoted_request_object_payload(), Algorithm::PS256)?;
        let mut segments = token.split('.').map(str::to_string).collect::<Vec<_>>();
        let mut signature = URL_SAFE_NO_PAD.decode(&segments[2])?;
        signature[0] ^= 0x01;
        segments[2] = URL_SAFE_NO_PAD.encode(signature);
        let modified = segments.join(".");
        let (modulus, exponent) = sample_rsa_public_components()?;

        assert!(matches!(
            verify_request_object_ps256_promoted(
                &modified,
                &modulus,
                &exponent,
                &["https://issuer.example".to_string()],
                60,
            ),
            Err(RequestObjectError::Jws(_))
        ));
        Ok(())
    }

    #[test]
    fn request_object_rejects_none_algorithm() -> TestResult {
        let token =
            build_compact_jwt_none_alg(&serde_json::json!({"aud":["https://example.com"]}))?;
        let dummy_key = jsonwebtoken::DecodingKey::from_secret(b"unused");
        let err = verify_request_object(&token, &dummy_key, &[], 0)
            .err()
            .ok_or_else(|| IoError::other("request object should be rejected"))?;
        let message = err.to_string();
        assert!(
            message.to_lowercase().contains("none"),
            "error should mention none algorithm: {message}"
        );
        // `jsonwebtoken::decode_header` currently rejects `{"alg":"none"}` at parse-time
        // (its `Algorithm` enum does not include `none`). If that changes upstream, we still
        // must reject `none` by allowlist.
        assert!(matches!(
            err,
            RequestObjectError::Jwt(_) | RequestObjectError::UnsupportedAlgorithm(_)
        ));
        Ok(())
    }

    #[test]
    fn request_object_raw_parser_preserves_authorization_details() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let _backend = use_compat_request_object_backend();
        let (exp, nbf) = sample_time_window();
        let payload = format!(
            r#"{{
            "iss":"client-123",
            "aud":["https://issuer.example"],
            "exp":{exp},
            "nbf":{nbf},
            "client_id":"client-123",
            "redirect_uri":"https://client.example/cb",
            "response_type":"code",
            "scope":"openid",
            "code_challenge":"abc123def456ghi789jkl012mno345pq",
            "code_challenge_method":"S256",
            "authorization_details":[{{"type":"payment","locations":["https://api.example"]}}],
            "jti":"jti-123"
        }}"#
        );

        let claims = parse_request_object_claims_raw(payload.as_bytes())?;
        let details = claims
            .authorization_details
            .ok_or_else(|| IoError::other("authorization_details should be preserved"))?;
        assert_eq!(details[0]["type"], Value::String("payment".to_string()));
        Ok(())
    }

    #[test]
    fn request_object_claim_set_parser_preserves_jwt_custom_and_additional_claims() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let _backend = use_compat_request_object_backend();
        let (exp, nbf) = sample_time_window();
        let payload = format!(
            r#"{{
            "iss":"client-123",
            "sub":"subject-123",
            "aud":["https://issuer.example","https://issuer-backup.example"],
            "exp":{exp},
            "nbf":{nbf},
            "iat":{nbf},
            "client_id":"client-123",
            "redirect_uri":"https://client.example/cb",
            "response_type":"code",
            "scope":"openid",
            "resource":"https://api.example",
            "authorization_details":[{{"type":"payment"}}],
            "jti":"jti-123"
        }}"#
        );

        let (request_claims, jwt_claims) = parse_request_object_claim_sets_raw(payload.as_bytes())?;
        assert_eq!(
            jwt_claims.aud,
            Some(serde_json::json!([
                "https://issuer.example",
                "https://issuer-backup.example"
            ]))
        );
        assert_eq!(
            jwt_claims.custom["client_id"],
            Value::String("client-123".to_string())
        );
        assert_eq!(
            jwt_claims.custom["resource"],
            Value::String("https://api.example".to_string())
        );

        let extra = request_claims
            .extra
            .ok_or_else(|| IoError::other("extra claims should preserve non-surface members"))?;
        assert_eq!(extra["sub"], Value::String("subject-123".to_string()));
        assert_eq!(extra["iat"], Value::Number(serde_json::Number::from(nbf)));
        assert_eq!(
            extra["resource"],
            Value::String("https://api.example".to_string())
        );
        assert!(extra.get("client_id").is_none());
        Ok(())
    }

    #[test]
    fn request_object_raw_parser_rejects_duplicate_keys() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let _backend = use_compat_request_object_backend();
        let (exp, nbf) = sample_time_window();
        let payload = format!(
            r#"{{
            "iss":"client-123",
            "aud":["https://issuer.example"],
            "exp":{exp},
            "nbf":{nbf},
            "client_id":"client-123",
            "client_id":"evil-client",
            "redirect_uri":"https://client.example/cb",
            "response_type":"code",
            "scope":"openid",
            "code_challenge":"abc123def456ghi789jkl012mno345pq",
            "code_challenge_method":"S256",
            "jti":"jti-123"
        }}"#
        );

        let err = parse_request_object_claims_raw(payload.as_bytes()).err();
        assert!(matches!(
            err,
            Some(RequestObjectError::PolicyViolation(ref msg)) if msg == "duplicate-key"
        ));
        Ok(())
    }

    #[test]
    fn request_object_raw_parser_rejects_invalid_numeric_claim_types() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let _backend = use_compat_request_object_backend();
        let payload = br#"{
            "iss":"client-123",
            "aud":["https://issuer.example"],
            "exp":"1735689600",
            "nbf":1735689300,
            "client_id":"client-123",
            "redirect_uri":"https://client.example/cb",
            "response_type":"code",
            "scope":"openid",
            "code_challenge":"abc123def456ghi789jkl012mno345pq",
            "code_challenge_method":"S256",
            "jti":"jti-123"
        }"#;

        assert!(matches!(
            parse_request_object_claims_raw(payload).err(),
            Some(RequestObjectError::Json(_))
        ));
        Ok(())
    }

    #[test]
    fn request_object_raw_parser_rejects_invalid_audience_entries() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let _backend = use_compat_request_object_backend();
        let payload = br#"{
            "iss":"client-123",
            "aud":["https://issuer.example", 7],
            "exp":1735689600,
            "nbf":1735689300,
            "client_id":"client-123",
            "redirect_uri":"https://client.example/cb",
            "response_type":"code",
            "scope":"openid",
            "code_challenge":"abc123def456ghi789jkl012mno345pq",
            "code_challenge_method":"S256",
            "jti":"jti-123"
        }"#;

        assert!(matches!(
            parse_request_object_claims_raw(payload).err(),
            Some(RequestObjectError::Json(_))
        ));
        Ok(())
    }

    #[test]
    fn request_object_raw_parser_rejects_trailing_bytes() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let _backend = use_compat_request_object_backend();
        let (exp, nbf) = sample_time_window();
        let payload = format!(
            r#"{{
            "iss":"client-123",
            "aud":["https://issuer.example"],
            "exp":{exp},
            "nbf":{nbf},
            "client_id":"client-123",
            "redirect_uri":"https://client.example/cb",
            "response_type":"code",
            "scope":"openid",
            "code_challenge":"abc123def456ghi789jkl012mno345pq",
            "code_challenge_method":"S256",
            "jti":"jti-123"
        }}x"#
        );

        assert!(matches!(
            parse_request_object_claims_raw(payload.as_bytes()).err(),
            Some(RequestObjectError::Json(_))
        ));
        Ok(())
    }

    #[test]
    fn request_object_raw_parser_rejects_unknown_backend_override() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let previous = std::env::var("AEGAEON_RAW_JSON_BACKEND_REQUEST_OBJECT").ok();
        std::env::set_var("AEGAEON_RAW_JSON_BACKEND_REQUEST_OBJECT", "future");

        let result = parse_request_object_claims_raw(
            br#"{
                "iss":"client-123",
                "aud":["https://issuer.example"],
                "exp":1735689600,
                "nbf":1735689300,
                "client_id":"client-123",
                "redirect_uri":"https://client.example/cb",
                "response_type":"code",
                "scope":"openid",
                "code_challenge":"abc123def456ghi789jkl012mno345pq",
                "code_challenge_method":"S256",
                "jti":"jti-123"
            }"#,
        );

        if let Some(prev) = previous {
            std::env::set_var("AEGAEON_RAW_JSON_BACKEND_REQUEST_OBJECT", prev);
        } else {
            std::env::remove_var("AEGAEON_RAW_JSON_BACKEND_REQUEST_OBJECT");
        }

        let err = result
            .err()
            .ok_or_else(|| IoError::other("unknown backend override must fail closed"))?;
        assert!(matches!(
            err,
            RequestObjectError::Internal(ref msg)
                if msg.contains("unsupported raw JSON backend `future`")
        ));
        Ok(())
    }

    #[test]
    fn request_object_verification_rejects_duplicate_claim_keys() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let _backend = use_compat_request_object_backend();
        let (exp, nbf) = sample_time_window();
        let payload = format!(
            r#"{{
            "iss":"client-123",
            "aud":["https://issuer.example"],
            "exp":{exp},
            "nbf":{nbf},
            "client_id":"client-123",
            "client_id":"evil-client",
            "redirect_uri":"https://client.example/cb",
            "response_type":"code",
            "scope":"openid",
            "state":"state-123",
            "nonce":"nonce-123",
            "code_challenge":"abc123def456ghi789jkl012mno345pq",
            "code_challenge_method":"S256",
            "jti":"jti-123"
        }}"#
        );
        let token = sign_compact_es256_payload(&payload)?;
        let decoding_key = DecodingKey::from_ec_pem(TEST_EC_PUBLIC_KEY_PEM.as_bytes())?;

        let err = verify_request_object(
            &token,
            &decoding_key,
            &[String::from("https://issuer.example")],
            60,
        )
        .err()
        .ok_or_else(|| IoError::other("duplicate request object claims must fail closed"))?;

        assert!(matches!(
            err,
            RequestObjectError::PolicyViolation(ref msg) if msg == "duplicate-key"
        ));
        Ok(())
    }

    #[test]
    fn request_object_rs256_promoted_rejects_duplicate_claim_keys() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let _backend = use_compat_request_object_backend();
        let (exp, nbf) = sample_time_window();
        let payload = format!(
            r#"{{
            "iss":"client-123",
            "aud":["https://issuer.example"],
            "exp":{exp},
            "nbf":{nbf},
            "client_id":"client-123",
            "client_id":"evil-client",
            "redirect_uri":"https://client.example/cb",
            "response_type":"code",
            "scope":"openid",
            "state":"state-123",
            "nonce":"nonce-123",
            "code_challenge":"abc123def456ghi789jkl012mno345pq",
            "code_challenge_method":"S256",
            "jti":"jti-123"
        }}"#
        );
        let token = sign_compact_rs256_payload(&payload)?;
        let (modulus, exponent) = sample_rsa_public_components()?;

        let err = verify_request_object_rs256_promoted(
            &token,
            &modulus,
            &exponent,
            &[String::from("https://issuer.example")],
            60,
        )
        .err()
        .ok_or_else(|| IoError::other("duplicate RS256 request object claims must fail closed"))?;

        assert!(matches!(
            err,
            RequestObjectError::PolicyViolation(ref msg) if msg == "duplicate-key"
        ));
        Ok(())
    }

    #[test]
    fn request_object_rs256_promoted_rejects_temporal_overflow() -> TestResult {
        let _guard = lock_raw_json_env_guard()?;
        let _backend = use_compat_request_object_backend();
        let payload = r#"{
            "iss":"client-123",
            "aud":["https://issuer.example"],
            "exp":9223372036854775807,
            "client_id":"client-123",
            "redirect_uri":"https://client.example/cb",
            "response_type":"code",
            "scope":"openid",
            "state":"state-123",
            "nonce":"nonce-123",
            "code_challenge":"abc123def456ghi789jkl012mno345pq",
            "code_challenge_method":"S256",
            "jti":"jti-overflow"
        }"#;
        let token = sign_compact_rs256_payload(payload)?;
        let (modulus, exponent) = sample_rsa_public_components()?;

        let err = verify_request_object_rs256_promoted(
            &token,
            &modulus,
            &exponent,
            &[String::from("https://issuer.example")],
            60,
        )
        .err()
        .ok_or_else(|| IoError::other("temporal overflow must fail closed"))?;

        assert!(matches!(
            err,
            RequestObjectError::JwtValidation(JwtValidationError::TemporalOverflow)
        ));
        Ok(())
    }
}
