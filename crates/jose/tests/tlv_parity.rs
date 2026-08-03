//! TLV Parser Parity Tests
//!
//! These tests verify that the EverParse/F* verified TLV parser correctly
//! handles JOSE headers according to RFC 7515/7516 specifications.

use aegaeon_jose::jws::{verify_compact, JwsError, VerificationKey};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{digest::KeyInit, Hmac, Mac};
use sha2::Sha256;
use std::error::Error;

#[cfg(feature = "everparse_jose_header_entry")]
use aegaeon_jose::{parse_jose_header_tlv, JoseHeaderParseError};

/// Helper macro to skip test when Low* FFI is unavailable
macro_rules! skip_if_lowstar_unavailable {
    () => {
        if ffi::is_lowstar_unavailable() {
            eprintln!("Skipping: Low* FFI unavailable in this build");
            return Ok(());
        }
    };
}

type TestResult = Result<(), Box<dyn Error>>;

fn sign_hs256_jws(
    header: &str,
    payload: &[u8],
    secret: &[u8],
) -> Result<String, hmac::digest::InvalidLength> {
    let header_b64 = URL_SAFE_NO_PAD.encode(header);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret)?;
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

    Ok(format!("{signing_input}.{signature_b64}"))
}

fn verify_hs256_header(
    header: &str,
) -> Result<Result<Vec<u8>, JwsError>, hmac::digest::InvalidLength> {
    let payload = b"test payload";
    let secret = b"secret-key-for-test";
    let jws = sign_hs256_jws(header, payload, secret)?;
    Ok(verify_compact(&jws, VerificationKey::HmacSha256(secret)))
}

#[cfg(feature = "everparse_jose_header_entry")]
fn sample_raw_tlv_header() -> Vec<u8> {
    vec![
        3, b'a', b'l', b'g', 5, b'H', b'S', b'2', b'5', b'6', 3, b'k', b'i', b'd', 4, b't', b'e',
        b's', b't',
    ]
}

#[cfg(feature = "everparse_jose_header_entry")]
#[test]
fn test_tlv_entry_validator_accepts_valid_raw_header() -> TestResult {
    skip_if_lowstar_unavailable!();
    assert_eq!(
        parse_jose_header_tlv(&sample_raw_tlv_header()),
        Ok(vec![
            ("alg".to_string(), "HS256".to_string()),
            ("kid".to_string(), "test".to_string()),
        ])
    );
    Ok(())
}

#[cfg(feature = "everparse_jose_header_entry")]
#[test]
fn test_tlv_entry_validator_preserves_truncated_error_for_raw_header() -> TestResult {
    skip_if_lowstar_unavailable!();
    assert_eq!(
        parse_jose_header_tlv(&[3, b'a', b'l']),
        Err(JoseHeaderParseError::Truncated)
    );
    Ok(())
}

/// Test that a minimal valid JWS header is parsed correctly
#[test]
fn test_tlv_parser_minimal_header() -> TestResult {
    skip_if_lowstar_unavailable!();
    let payload = b"test payload";
    let secret = b"secret-key-for-test";
    let jws = sign_hs256_jws(r#"{"alg":"HS256"}"#, payload, secret)?;

    let result = verify_compact(&jws, VerificationKey::HmacSha256(secret));
    assert!(
        result.is_ok(),
        "TLV parser should accept minimal valid header"
    );
    assert!(matches!(result.as_deref(), Ok(bytes) if bytes == payload));
    Ok(())
}

/// Test that headers with typ field are parsed correctly
#[test]
fn test_tlv_parser_header_with_typ() -> TestResult {
    skip_if_lowstar_unavailable!();
    let payload = b"test payload";
    let secret = b"secret-key-for-test";
    let jws = sign_hs256_jws(r#"{"alg":"HS256","typ":"JWT"}"#, payload, secret)?;

    let result = verify_compact(&jws, VerificationKey::HmacSha256(secret));
    assert!(
        result.is_ok(),
        "TLV parser should accept header with typ field"
    );
    assert!(matches!(result.as_deref(), Ok(bytes) if bytes == payload));
    Ok(())
}

/// Test that headers with kid field are parsed correctly
#[test]
fn test_tlv_parser_header_with_kid() -> TestResult {
    skip_if_lowstar_unavailable!();
    let payload = b"test payload";
    let secret = b"secret-key-for-test";
    let jws = sign_hs256_jws(r#"{"alg":"HS256","kid":"key-2024"}"#, payload, secret)?;

    let result = verify_compact(&jws, VerificationKey::HmacSha256(secret));
    assert!(
        result.is_ok(),
        "TLV parser should accept header with kid field"
    );
    assert!(matches!(result.as_deref(), Ok(bytes) if bytes == payload));
    Ok(())
}

/// Test that headers with all common fields are parsed correctly
#[test]
fn test_tlv_parser_header_with_all_fields() -> TestResult {
    skip_if_lowstar_unavailable!();
    let payload = b"test payload";
    let secret = b"secret-key-for-test";
    let jws = sign_hs256_jws(
        r#"{"alg":"HS256","typ":"JWT","kid":"key-2024"}"#,
        payload,
        secret,
    )?;

    let result = verify_compact(&jws, VerificationKey::HmacSha256(secret));
    assert!(
        result.is_ok(),
        "TLV parser should accept header with all common fields"
    );
    assert!(matches!(result.as_deref(), Ok(bytes) if bytes == payload));
    Ok(())
}

/// Test that headers with crit field are rejected
#[test]
fn test_tlv_parser_rejects_critical_header() -> TestResult {
    let result = verify_hs256_header(r#"{"alg":"HS256","crit":["exp"]}"#)?;

    assert!(
        result.is_err(),
        "TLV parser should reject critical header extensions"
    );
    assert!(matches!(
        result,
        Err(JwsError::UnsupportedCriticalHeader(_) | JwsError::JsonLowStar(_))
    ));
    Ok(())
}

/// Test that malformed JSON headers are rejected
#[test]
fn test_tlv_parser_rejects_malformed_json() -> TestResult {
    let result = verify_hs256_header(r#"{"alg":"HS256""#)?;

    assert!(result.is_err(), "TLV parser should reject malformed JSON");
    Ok(())
}

/// Test that headers with null values are handled correctly
#[test]
fn test_tlv_parser_handles_null_values() -> TestResult {
    skip_if_lowstar_unavailable!();
    let result = verify_hs256_header(r#"{"alg":"HS256","kid":null}"#)?;

    assert!(
        result.is_ok(),
        "TLV parser should accept null values as missing fields"
    );
    Ok(())
}

/// Test that headers without alg field are rejected
#[test]
fn test_tlv_parser_rejects_missing_alg() -> TestResult {
    let result = verify_hs256_header(r#"{"typ":"JWT"}"#)?;

    assert!(
        result.is_err(),
        "TLV parser should reject headers without alg field"
    );
    Ok(())
}

/// Test that unsupported algorithms are rejected
#[test]
fn test_tlv_parser_rejects_unsupported_alg() -> TestResult {
    let result = verify_hs256_header(r#"{"alg":"none"}"#)?;

    assert!(
        result.is_err(),
        "TLV parser should reject unsupported algorithms"
    );
    Ok(())
}

/// Test that headers with non-string values for string fields are rejected
#[test]
fn test_tlv_parser_rejects_invalid_field_types() -> TestResult {
    let result = verify_hs256_header(r#"{"alg":"HS256","kid":12345}"#)?;

    assert!(
        result.is_err(),
        "TLV parser should reject non-string values for string fields"
    );
    Ok(())
}

/// Test that headers with extra whitespace are handled correctly
#[test]
fn test_tlv_parser_handles_whitespace() -> TestResult {
    skip_if_lowstar_unavailable!();
    let result = verify_hs256_header(r#"{ "alg" : "HS256" , "typ" : "JWT" }"#)?;

    assert!(
        result.is_ok(),
        "TLV parser should handle whitespace in JSON"
    );
    Ok(())
}
