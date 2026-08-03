use super::super::{Audience, IdTokenBuilder, OidcSigningKey};
use super::verification::{finalize_structure_precheck, map_jws_error};
use super::*;
use aegaeon_jose::raw_json::RawJsonSurface;
use aegaeon_jose::JwsError;
#[cfg(not(feature = "verified-claim"))]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ffi::id_token::IdTokenParserError;
#[cfg(not(feature = "verified-claim"))]
use jsonwebtoken::{crypto, Algorithm, EncodingKey, Header};
use serde_json::Value;
use std::error::Error as StdError;
use std::io;

type TestResult<T = ()> = std::result::Result<T, Box<dyn StdError>>;

const TEST_RSA_PRIVATE_KEY_PEM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/rsa2048-private.pk8.pem"
));

fn require_err<T, E>(
    result: std::result::Result<T, E>,
    message: &str,
) -> std::result::Result<E, io::Error> {
    match result {
        Ok(_) => Err(io::Error::other(message)),
        Err(err) => Ok(err),
    }
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

fn use_oidc_id_token_payload_backend(value: &str) -> RawJsonBackendOverrideGuard {
    let key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        RawJsonSurface::OidcIdTokenPayload,
    );
    let previous = std::env::var(key).ok();
    std::env::set_var(key, value);
    RawJsonBackendOverrideGuard { key, previous }
}

fn use_oidc_id_token_payload_verified_structural_backend() -> RawJsonBackendOverrideGuard {
    use_oidc_id_token_payload_backend("verified-structural-v1")
}

fn raw_json_structural_parser_unavailable(payload: &[u8]) -> bool {
    matches!(
        ffi::raw_json_structural::parse_raw_json_structural(payload),
        Err(ffi::raw_json_structural::RawJsonStructuralParseError::ParserUnavailable)
    )
}

fn id_token_structure_parser_unavailable(token: &str) -> bool {
    matches!(
        ffi::id_token::check_id_token_jwt(token.as_bytes()),
        Err(IdTokenParserError::ParserUnavailable)
    )
}

fn raw_json_env_lock() -> TestResult<std::sync::MutexGuard<'static, ()>> {
    crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|err| io::Error::other(format!("raw json env guard: {err}")).into())
}

fn sample_jwk_components(signing_key: &OidcSigningKey) -> TestResult<(String, String)> {
    let jwks = signing_key.jwks();
    let jwk = jwks
        .keys
        .first()
        .ok_or_else(|| io::Error::other("public jwk"))?;
    let modulus = jwk
        .n
        .as_deref()
        .ok_or_else(|| io::Error::other("rsa modulus"))?
        .to_string();
    let exponent = jwk
        .e
        .as_deref()
        .ok_or_else(|| io::Error::other("rsa exponent"))?
        .to_string();
    Ok((modulus, exponent))
}

#[cfg(not(feature = "verified-claim"))]
fn sign_raw_rs256_payload(payload_json: &str) -> TestResult<String> {
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_string());
    header.kid = Some("test-kid".to_string());

    let header_json = serde_json::to_vec(&header)?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let encoding_key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())?;
    let signature = crypto::sign(signing_input.as_bytes(), &encoding_key, Algorithm::RS256)?;

    Ok(format!("{signing_input}.{signature}"))
}

#[cfg(not(feature = "verified-claim"))]
#[test]
fn required_rs256_round_trip_signs_and_verifies() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let _payload_backend = use_oidc_id_token_payload_verified_structural_backend();
    let signing_key =
        OidcSigningKey::from_rsa_pem("test-kid".to_string(), TEST_RSA_PRIVATE_KEY_PEM)?;
    let claims = IdTokenBuilder::try_new(
        "https://issuer.example".to_string(),
        "subject-123".to_string(),
        "client-123".to_string(),
    )
    .map_err(io::Error::other)?
    .nonce("nonce-123".to_string())
    .build()
    .claims;

    let token = sign_required_id_token(&claims, &signing_key)?;
    if id_token_structure_parser_unavailable(&token) {
        return Ok(());
    }
    let (modulus, exponent) = sample_jwk_components(&signing_key)?;
    let verified = verify_required_id_token_claims(&token, &modulus, &exponent)?;

    assert_eq!(verified.iss, claims.iss);
    assert_eq!(verified.sub, claims.sub);
    assert_eq!(verified.nonce, claims.nonce);
    Ok(())
}

#[test]
fn required_rs256_rejects_tampered_signature() -> TestResult {
    let signing_key =
        OidcSigningKey::from_rsa_pem("test-kid".to_string(), TEST_RSA_PRIVATE_KEY_PEM)?;
    let claims = IdTokenBuilder::try_new(
        "https://issuer.example".to_string(),
        "subject-123".to_string(),
        "client-123".to_string(),
    )
    .map_err(io::Error::other)?
    .build()
    .claims;

    let token = sign_required_id_token(&claims, &signing_key)?;
    if id_token_structure_parser_unavailable(&token) {
        return Ok(());
    }
    let mut parts: Vec<String> = token.split('.').map(ToString::to_string).collect();
    assert_eq!(parts.len(), 3);
    let replacement = if parts[2].starts_with('A') { "B" } else { "A" };
    parts[2].replace_range(0..1, replacement);
    let tampered = parts.join(".");

    let (modulus, exponent) = sample_jwk_components(&signing_key)?;
    let err = require_err(
        verify_required_id_token_claims(&tampered, &modulus, &exponent),
        "tampered token must fail",
    )?;

    assert!(matches!(
        err,
        RequiredRs256Error::InvalidSignature | RequiredRs256Error::InvalidStructure
    ));
    Ok(())
}

#[test]
fn raw_id_token_payload_parser_rejects_duplicate_claim_keys() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let _payload_backend = use_oidc_id_token_payload_verified_structural_backend();
    let payload = br#"{
            "iss":"https://issuer.example",
            "sub":"subject-123",
            "sub":"evil-subject",
            "aud":"client-123",
            "exp":4102444800,
            "iat":1700000000
        }"#;

    let err = require_err(
        decode_id_token_payload_claims_without_duplicate_keys(payload),
        "duplicate ID Token claims must fail before deserialization",
    )?;

    assert!(matches!(err, RequiredRs256Error::InvalidPayload));
    Ok(())
}

#[test]
fn raw_id_token_payload_parser_rejects_trailing_bytes() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let _payload_backend = use_oidc_id_token_payload_verified_structural_backend();
    let payload = br#"{
            "iss":"https://issuer.example",
            "sub":"subject-123",
            "aud":"client-123",
            "exp":4102444800,
            "iat":1700000000
        } trailing"#;

    let err = require_err(
        decode_id_token_payload_claims_without_duplicate_keys(payload),
        "trailing bytes must fail before ID Token deserialization",
    )?;

    assert!(matches!(err, RequiredRs256Error::InvalidPayload));
    Ok(())
}

#[test]
fn raw_id_token_payload_parser_rejects_non_object_shape() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let _payload_backend = use_oidc_id_token_payload_verified_structural_backend();
    let err = require_err(
        decode_id_token_payload_claims_without_duplicate_keys(br#"[]"#),
        "non-object payloads must fail before ID Token deserialization",
    )?;

    assert!(matches!(err, RequiredRs256Error::InvalidPayload));
    Ok(())
}

#[test]
fn raw_id_token_payload_parser_rejects_unknown_surface_backend_override() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        RawJsonSurface::OidcIdTokenPayload,
    );
    let previous = std::env::var(key).ok();
    std::env::set_var(key, "future");

    let result = decode_id_token_payload_claims_without_duplicate_keys(
        br#"{
                "iss":"https://issuer.example",
                "sub":"subject-123",
                "aud":"client-123",
                "exp":4102444800,
                "iat":1700000000
            }"#,
    );

    if let Some(prev) = previous {
        std::env::set_var(key, prev);
    } else {
        std::env::remove_var(key);
    }

    let err = require_err(
        result,
        "unknown OIDC ID Token payload backend override must fail closed",
    )?;

    assert!(matches!(
        err,
        RequiredRs256Error::Internal(ref msg)
            if msg.contains("unsupported raw JSON backend")
                && msg.contains("oidc-id-token-payload")
    ));
    Ok(())
}

#[cfg(not(feature = "verified-claim"))]
#[test]
fn required_rs256_rejects_duplicate_claim_keys() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let _payload_backend = use_oidc_id_token_payload_verified_structural_backend();
    let signing_key =
        OidcSigningKey::from_rsa_pem("test-kid".to_string(), TEST_RSA_PRIVATE_KEY_PEM)?;
    let (modulus, exponent) = sample_jwk_components(&signing_key)?;
    let payload = r#"{
            "iss":"https://issuer.example",
            "sub":"subject-123",
            "sub":"evil-subject",
            "aud":"client-123",
            "exp":4102444800,
            "iat":1700000000,
            "nonce":"nonce-123"
        }"#;
    let token = sign_raw_rs256_payload(payload)?;
    if id_token_structure_parser_unavailable(&token) {
        return Ok(());
    }

    let err = require_err(
        verify_required_id_token_claims(&token, &modulus, &exponent),
        "duplicate ID Token claims must fail closed",
    )?;

    assert!(matches!(err, RequiredRs256Error::InvalidPayload));
    Ok(())
}

#[cfg(not(feature = "verified-claim"))]
#[test]
fn id_token_structure_precheck_rejects_unavailable_parser() -> TestResult {
    let err = require_err(
        finalize_structure_precheck(Err(IdTokenParserError::ParserUnavailable)),
        "ID Token structure parser unavailability must fail closed",
    )?;

    assert!(matches!(
        err,
        RequiredRs256Error::Internal(ref msg)
            if msg.contains("structure parser unavailable")
    ));
    Ok(())
}

#[cfg(feature = "verified-claim")]
#[test]
fn verified_claim_profile_rejects_unavailable_id_token_structure_parser() -> TestResult {
    let err = require_err(
        finalize_structure_precheck(Err(IdTokenParserError::ParserUnavailable)),
        "strict profile must fail closed when the ID Token structure parser is unavailable",
    )?;

    assert!(matches!(
        err,
        RequiredRs256Error::Internal(ref msg)
            if msg.contains("structure parser unavailable")
    ));
    Ok(())
}

#[test]
fn required_rs256_maps_json_lowstar_internal_errors_to_internal() -> TestResult {
    let err = map_jws_error(JwsError::JsonLowStar(
        aegaeon_jose::json_lowstar::JsonError::Internal("unsupported raw JSON backend".to_string()),
    ));

    let RequiredRs256Error::Internal(message) = err else {
        return Err(io::Error::other("unexpected error kind").into());
    };
    assert_eq!(message, "unsupported raw JSON backend");
    Ok(())
}

#[test]
fn required_rs256_maps_json_lowstar_parser_unavailable_to_internal() -> TestResult {
    let err = map_jws_error(JwsError::JsonLowStar(
        aegaeon_jose::json_lowstar::JsonError::ParserUnavailable,
    ));

    let RequiredRs256Error::Internal(message) = err else {
        return Err(io::Error::other("unexpected error kind").into());
    };
    assert_eq!(message, "JOSE header parser unavailable in this build");
    Ok(())
}

#[test]
fn raw_id_token_payload_parser_accepts_valid_payload_with_additional_claims() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let payload = br#"{
            "iss":"https://issuer.example",
            "sub":"subject-123",
            "aud":["client-123","client-456"],
            "exp":4102444800,
            "iat":1700000000,
            "nonce":"nonce-123",
            "amr":["pwd","mfa"],
            "email":"user@example.com",
            "email_verified":true,
            "profile":{"department":"Platform"}
        }"#;
    if raw_json_structural_parser_unavailable(payload) {
        return Ok(());
    }
    let _payload_backend = use_oidc_id_token_payload_backend("verified-structural-v1");

    let result = decode_id_token_payload_claims_without_duplicate_keys(payload);

    let claims = result?;
    assert_eq!(claims.iss, "https://issuer.example");
    assert_eq!(claims.sub, "subject-123");
    assert!(matches!(claims.aud, Audience::Multiple(ref aud) if aud.len() == 2));
    assert_eq!(claims.nonce.as_deref(), Some("nonce-123"));
    assert_eq!(claims.amr.as_ref().map(Vec::len), Some(2));
    assert_eq!(
        claims.additional_claims.get("email"),
        Some(&Value::String("user@example.com".to_string()))
    );
    assert_eq!(
        claims.additional_claims.get("email_verified"),
        Some(&Value::Bool(true))
    );
    assert!(matches!(
        claims.additional_claims.get("profile"),
        Some(Value::Object(_))
    ));
    Ok(())
}

#[test]
fn raw_id_token_payload_parser_rejects_invalid_exp_type_under_verified_backend() -> TestResult {
    let _guard = raw_json_env_lock()?;
    let payload = br#"{
            "iss":"https://issuer.example",
            "sub":"subject-123",
            "aud":"client-123",
            "exp":"4102444800",
            "iat":1700000000
        }"#;
    if raw_json_structural_parser_unavailable(payload) {
        return Ok(());
    }
    let _payload_backend = use_oidc_id_token_payload_backend("verified-structural-v1");

    let result = decode_id_token_payload_claims_without_duplicate_keys(payload);

    let err = require_err(result, "string exp must fail under typed verified decode")?;
    assert!(matches!(err, RequiredRs256Error::InvalidPayload));
    Ok(())
}
