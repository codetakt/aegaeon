use super::*;
use std::error::Error as StdError;
use std::io;

type TestResult = std::result::Result<(), Box<dyn StdError>>;

fn require_err<T, E>(
    result: std::result::Result<T, E>,
    message: &str,
) -> std::result::Result<E, io::Error> {
    match result {
        Ok(_) => Err(io::Error::other(message)),
        Err(err) => Ok(err),
    }
}

fn test_token_at(now: i64) -> IdToken {
    let mut token = IdTokenBuilder::try_new(
        "https://example.com".to_string(),
        "user123".to_string(),
        "client456".to_string(),
    )
    .expect("test issuer is valid")
    .nonce("test-nonce".to_string())
    .auth_time(now)
    .expiration(now + 3600)
    .build();
    token.claims.iat = now;
    token.claims.nbf = Some(now);
    token
}

#[test]
fn test_audience_contains() {
    let single = Audience::Single("client1".to_string());
    assert!(single.contains("client1"));
    assert!(!single.contains("client2"));

    let multiple = Audience::Multiple(vec!["client1".to_string(), "client2".to_string()]);
    assert!(multiple.contains("client1"));
    assert!(multiple.contains("client2"));
    assert!(!multiple.contains("client3"));
}

#[test]
fn test_id_token_validation() -> TestResult {
    let now = unix_time_now_i64().ok_or_else(|| io::Error::other("failed to compute unix time"))?;

    let token = IdTokenBuilder::try_new(
        "https://example.com".to_string(),
        "user123".to_string(),
        "client456".to_string(),
    )
    .map_err(io::Error::other)?
    .nonce("test-nonce".to_string())
    .expiration(now + 3600)
    .build();

    // Valid token
    assert!(token
        .validate("client456", "https://example.com", Some("test-nonce"))
        .is_ok());

    // Invalid issuer
    assert!(token
        .validate("client456", "https://other.com", Some("test-nonce"))
        .is_err());

    // Invalid audience
    assert!(token
        .validate("other-client", "https://example.com", Some("test-nonce"))
        .is_err());

    // Invalid nonce
    assert!(token
        .validate("client456", "https://example.com", Some("wrong-nonce"))
        .is_err());
    Ok(())
}

#[test]
fn max_age_rejects_future_auth_time() -> TestResult {
    let now = 1_700_000_000_i64;
    let mut token = test_token_at(now);
    token.claims.auth_time = Some(now + 120);
    let mut ctx = IdTokenValidationContext::new("client456", "https://example.com");
    ctx.expected_nonce = Some("test-nonce");
    ctx.max_age = Some(60);
    ctx.current_time = Some(now);
    ctx.clock_skew = 60;

    let err = require_err(
        token.validate_with_context(&ctx),
        "future auth_time must be rejected",
    )?;

    assert!(matches!(
        err,
        Error::InvalidRequest(ref msg) if msg.contains("future")
    ));
    Ok(())
}

#[test]
fn max_age_rejects_unrepresentable_authentication_age() -> TestResult {
    let now = 1_700_000_000_i64;
    let mut token = test_token_at(now);
    token.claims.auth_time = Some(i64::MIN);
    let mut ctx = IdTokenValidationContext::new("client456", "https://example.com");
    ctx.expected_nonce = Some("test-nonce");
    ctx.max_age = Some(60);
    ctx.current_time = Some(now);

    let err = require_err(
        token.validate_with_context(&ctx),
        "unrepresentable auth_time age must be rejected",
    )?;

    assert!(matches!(
        err,
        Error::InvalidRequest(ref msg) if msg.contains("Authentication time")
    ));
    Ok(())
}

#[test]
fn validation_rejects_non_structural_https_issuer() -> TestResult {
    let now = 1_700_000_000_i64;
    let mut token = test_token_at(now);
    token.claims.iss = "https://example.com?tenant=one".to_string();
    let mut ctx = IdTokenValidationContext::new("client456", "https://example.com?tenant=one");
    ctx.expected_nonce = Some("test-nonce");
    ctx.current_time = Some(now + 10);

    let err = require_err(
        token.validate_with_context(&ctx),
        "issuer with query must be rejected",
    )?;

    assert!(matches!(
        err,
        Error::InvalidRequest(ref msg) if msg.contains("Issuer")
    ));
    Ok(())
}

#[test]
fn validation_rejects_exp_not_after_iat() -> TestResult {
    let now = 1_700_000_000_i64;
    let mut token = test_token_at(now);
    token.claims.iat = now + 600;
    token.claims.exp = now + 600;
    token.claims.nbf = Some(now);
    let mut ctx = IdTokenValidationContext::new("client456", "https://example.com");
    ctx.expected_nonce = Some("test-nonce");
    ctx.current_time = Some(now + 10);

    let err = require_err(
        token.validate_with_context(&ctx),
        "exp at iat must be rejected",
    )?;

    assert!(matches!(
        err,
        Error::InvalidRequest(ref msg) if msg.contains("exp must be after iat")
    ));
    Ok(())
}

#[test]
fn validation_rejects_exp_not_after_nbf() -> TestResult {
    let now = 1_700_000_000_i64;
    let mut token = test_token_at(now);
    token.claims.iat = now;
    token.claims.nbf = Some(now + 600);
    token.claims.exp = now + 600;
    let mut ctx = IdTokenValidationContext::new("client456", "https://example.com");
    ctx.expected_nonce = Some("test-nonce");
    ctx.current_time = Some(now + 10);

    let err = require_err(
        token.validate_with_context(&ctx),
        "exp at nbf must be rejected",
    )?;

    assert!(matches!(
        err,
        Error::InvalidRequest(ref msg) if msg.contains("exp must be after nbf")
    ));
    Ok(())
}

#[test]
fn test_compute_hash() -> TestResult {
    // Test vector from OIDC spec
    let access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
    let expected_rs256 = "77QmUPtjPfzWtF2AnpK9RQ";

    let result = compute_hash(access_token, "RS256")?;
    assert_eq!(result, expected_rs256);
    Ok(())
}

#[test]
fn ps_algorithms_remain_disabled_before_runtime_dispatch() -> TestResult {
    let err = require_err(
        compute_hash("sample-access-token", "PS256"),
        "PS256 should remain rejected by policy",
    )?;

    assert!(matches!(
        err,
        Error::InvalidRequest(ref msg) if msg.contains("temporarily disabled")
    ));
    Ok(())
}

#[test]
fn finalize_hash_result_maps_invalid_algorithm_to_invalid_request() -> TestResult {
    let err = require_err(
        finalize_hash_result(
            Err(OidcHashError::InvalidAlgorithm),
            "sample-access-token",
            "none",
        ),
        "invalid algorithm must map to invalid request",
    )?;

    assert!(matches!(
        err,
        Error::InvalidRequest(ref msg) if msg.contains("Unsupported algorithm: none")
    ));
    Ok(())
}

#[test]
fn finalize_hash_result_maps_input_too_large_to_invalid_request() -> TestResult {
    let err = require_err(
        finalize_hash_result(
            Err(OidcHashError::InputTooLarge),
            "sample-access-token",
            "RS256",
        ),
        "oversized hash input must map to invalid request",
    )?;

    assert!(matches!(
        err,
        Error::InvalidRequest(ref msg) if msg.contains("exceeds 4 GiB")
    ));
    Ok(())
}

#[cfg(not(feature = "verified-claim"))]
#[test]
fn compat_profile_falls_back_when_hash_runtime_is_unavailable() -> TestResult {
    let result = finalize_hash_result(
        Err(OidcHashError::Unavailable),
        "sample-access-token",
        "RS256",
    )?;

    assert_eq!(result, "EN9PvSfRnJ9qwbHAFRGqMw");
    Ok(())
}

#[cfg(not(feature = "verified-claim"))]
#[test]
fn compat_profile_falls_back_when_hash_runtime_fails() -> TestResult {
    let result = finalize_hash_result(
        Err(OidcHashError::ComputationFailed),
        "sample-access-token",
        "RS256",
    )?;

    assert_eq!(result, "EN9PvSfRnJ9qwbHAFRGqMw");
    Ok(())
}

#[cfg(not(feature = "verified-claim"))]
#[test]
fn compat_profile_falls_back_when_hash_runtime_returns_null_digest() -> TestResult {
    let result = finalize_hash_result(
        Err(OidcHashError::NullDigest),
        "sample-access-token",
        "RS256",
    )?;

    assert_eq!(result, "EN9PvSfRnJ9qwbHAFRGqMw");
    Ok(())
}

#[cfg(feature = "verified-claim")]
#[test]
fn verified_claim_profile_rejects_unavailable_hash_runtime() -> TestResult {
    let err = require_err(
        finalize_hash_result(
            Err(OidcHashError::Unavailable),
            "sample-access-token",
            "RS256",
        ),
        "strict profile must fail closed",
    )?;

    assert!(matches!(
        err,
        Error::ServerError(ref msg) if msg.contains("verified path unavailable")
    ));
    Ok(())
}

#[cfg(feature = "verified-claim")]
#[test]
fn verified_claim_profile_rejects_failed_hash_runtime() -> TestResult {
    let err = require_err(
        finalize_hash_result(
            Err(OidcHashError::ComputationFailed),
            "sample-access-token",
            "RS256",
        ),
        "strict profile must fail closed",
    )?;

    assert!(matches!(
        err,
        Error::ServerError(ref msg) if msg.contains("verified path failed")
    ));
    Ok(())
}

#[cfg(feature = "verified-claim")]
#[test]
fn verified_claim_profile_rejects_null_digest_hash_runtime() -> TestResult {
    let err = require_err(
        finalize_hash_result(
            Err(OidcHashError::NullDigest),
            "sample-access-token",
            "RS256",
        ),
        "strict profile must fail closed",
    )?;

    assert!(matches!(
        err,
        Error::ServerError(ref msg) if msg.contains("verified path failed")
    ));
    Ok(())
}
