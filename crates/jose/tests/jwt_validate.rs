use aegaeon_jose::jwt::{JwtClaims, JwtValidationError, ValidationContext};
use serde_json::json;
use std::error::Error;
use std::time::Duration;

const NOW: i64 = 1_700_000_000;

type TestResult = Result<(), Box<dyn Error>>;

fn build_claims(value: serde_json::Value) -> Result<JwtClaims, serde_json::Error> {
    serde_json::from_value(value)
}

#[test]
fn validate_happy_path() -> TestResult {
    let claims = build_claims(json!({
        "iss": "https://issuer.example.com",
        "sub": "user-123",
        "aud": ["client-123", "client-456"],
        "exp": NOW + 60,
        "nbf": NOW - 10,
        "iat": NOW - 30,
        "jti": "token-1",
        "scope": "openid"
    }))?;

    let ctx = ValidationContext::builder()
        .now(NOW)
        .leeway(Duration::from_secs(5))
        .expected_issuer("https://issuer.example.com")
        .allowed_audiences(["client-123"])
        .require_issuer(true)
        .require_subject(true)
        .require_audience(true)
        .require_exp(true)
        .require_jti(true)
        .build();

    assert!(claims.validate(&ctx).is_ok());
    Ok(())
}

#[test]
fn validate_expired_token() -> TestResult {
    let claims = build_claims(json!({
        "iss": "https://issuer.example.com",
        "sub": "user-123",
        "aud": ["client-123"],
        "exp": NOW - 1,
        "nbf": NOW - 100,
        "iat": NOW - 200,
        "jti": "token-1"
    }))?;

    let ctx = ValidationContext::builder()
        .now(NOW)
        .expected_issuer("https://issuer.example.com")
        .allowed_audiences(["client-123"])
        .require_issuer(true)
        .require_subject(true)
        .require_audience(true)
        .require_jti(true)
        .build();

    let err = claims
        .validate(&ctx)
        .err()
        .ok_or("token should be expired")?;
    assert_eq!(err, JwtValidationError::Expired);
    Ok(())
}

#[test]
fn validate_not_yet_valid_token() -> TestResult {
    let claims = build_claims(json!({
        "sub": "user-123",
        "aud": ["client-123"],
        "exp": NOW + 60,
        "nbf": NOW + 30,
        "iat": NOW - 10
    }))?;

    let ctx = ValidationContext::builder()
        .now(NOW)
        .require_subject(true)
        .require_audience(true)
        .require_exp(true)
        .build();

    let err = claims
        .validate(&ctx)
        .err()
        .ok_or("token should not be valid yet")?;
    assert_eq!(err, JwtValidationError::NotYetValid);
    Ok(())
}

#[test]
fn validate_audience_mismatch() -> TestResult {
    let claims = build_claims(json!({
        "iss": "https://issuer.example.com",
        "aud": ["unexpected"],
        "exp": NOW + 60
    }))?;

    let ctx = ValidationContext::builder()
        .now(NOW)
        .expected_issuer("https://issuer.example.com")
        .allowed_audiences(["client-123"])
        .require_issuer(true)
        .build();

    let err = claims
        .validate(&ctx)
        .err()
        .ok_or("audience should fail to match")?;
    assert_eq!(err, JwtValidationError::AudienceMismatch);
    Ok(())
}

#[test]
fn validate_requires_audience_claim_when_expected() -> TestResult {
    let claims = build_claims(json!({
        "iss": "https://issuer.example.com",
        "exp": NOW + 30
    }))?;

    let ctx = ValidationContext::builder()
        .now(NOW)
        .expected_issuer("https://issuer.example.com")
        .allowed_audiences(["client-123"])
        .require_issuer(true)
        .build();

    let err = claims
        .validate(&ctx)
        .err()
        .ok_or("missing audience should be reported")?;
    assert_eq!(err, JwtValidationError::MissingClaim("aud"));
    Ok(())
}

#[test]
fn validate_audience_handles_string_form() -> TestResult {
    let claims = build_claims(json!({
        "aud": "client-123",
        "exp": NOW + 30
    }))?;

    let ctx = ValidationContext::builder()
        .now(NOW)
        .allowed_audiences(["client-123"])
        .require_exp(true)
        .build();

    assert!(claims.validate(&ctx).is_ok());
    Ok(())
}

#[test]
fn validate_audience_invalid_format() -> TestResult {
    let claims = build_claims(json!({
        "aud": [42, "client-123"],
        "exp": NOW + 30
    }))?;

    let ctx = ValidationContext::builder()
        .now(NOW)
        .require_exp(true)
        .build();

    let err = claims
        .validate(&ctx)
        .err()
        .ok_or("non-string audience should be rejected")?;
    assert_eq!(err, JwtValidationError::InvalidAudienceFormat);
    Ok(())
}

#[test]
fn validate_issued_at_future() -> TestResult {
    let claims = build_claims(json!({
        "exp": NOW + 30,
        "iat": NOW + 120
    }))?;

    let ctx = ValidationContext::builder()
        .now(NOW)
        .require_exp(true)
        .require_iat(true)
        .build();

    let err = claims
        .validate(&ctx)
        .err()
        .ok_or("iat in the future should be rejected")?;
    assert_eq!(err, JwtValidationError::IssuedAtInFuture);
    Ok(())
}

#[test]
fn validate_time_claims_accept_leeway() -> TestResult {
    // Token is slightly expired / not-yet-valid, but within the configured leeway window.
    let claims = build_claims(json!({
        "exp": NOW - 2,
        "nbf": NOW + 2,
        "iat": NOW + 2
    }))?;

    let ctx = ValidationContext::builder()
        .now(NOW)
        .leeway(Duration::from_secs(5))
        .require_exp(true)
        .require_iat(true)
        .build();

    assert!(claims.validate(&ctx).is_ok());
    Ok(())
}

#[test]
fn validate_exp_leeway_overflow_fails_closed() -> TestResult {
    let claims = build_claims(json!({
        "exp": i64::MAX
    }))?;

    let ctx = ValidationContext::builder()
        .now(NOW)
        .leeway(Duration::from_secs(5))
        .require_exp(true)
        .build();

    let err = claims
        .validate(&ctx)
        .err()
        .ok_or("exp + leeway overflow must fail closed")?;
    assert_eq!(err, JwtValidationError::TemporalOverflow);
    Ok(())
}

#[test]
fn validate_nbf_leeway_overflow_fails_closed() -> TestResult {
    let claims = build_claims(json!({
        "nbf": i64::MAX
    }))?;

    let ctx = ValidationContext::builder()
        .now(i64::MAX - 1)
        .leeway(Duration::from_secs(5))
        .require_exp(false)
        .build();

    let err = claims
        .validate(&ctx)
        .err()
        .ok_or("now + leeway overflow must fail closed for nbf")?;
    assert_eq!(err, JwtValidationError::TemporalOverflow);
    Ok(())
}

#[test]
fn validate_iat_leeway_overflow_fails_closed() -> TestResult {
    let claims = build_claims(json!({
        "iat": i64::MAX
    }))?;

    let ctx = ValidationContext::builder()
        .now(i64::MAX - 1)
        .leeway(Duration::from_secs(5))
        .require_exp(false)
        .require_iat(true)
        .build();

    let err = claims
        .validate(&ctx)
        .err()
        .ok_or("now + leeway overflow must fail closed for iat")?;
    assert_eq!(err, JwtValidationError::TemporalOverflow);
    Ok(())
}

#[test]
fn validate_missing_required_subject() -> TestResult {
    let claims = build_claims(json!({
        "exp": NOW + 30
    }))?;

    let ctx = ValidationContext::builder()
        .now(NOW)
        .require_subject(true)
        .require_exp(true)
        .build();

    let err = claims
        .validate(&ctx)
        .err()
        .ok_or("subject is required but missing")?;
    assert_eq!(err, JwtValidationError::MissingClaim("sub"));
    Ok(())
}
