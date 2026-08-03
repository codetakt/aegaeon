use aegaeon_jose::jwk::{Jwk, JwkError, JwkSet};
use serde_json::json;
use std::error::Error;

fn parse_jwk(value: serde_json::Value) -> Result<Jwk, JwkError> {
    Jwk::from_value(value)
}

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn parse_rsa_jwk_success() -> TestResult {
    let jwk = parse_jwk(json!({
        "kty": "RSA",
        "kid": "rsa-1",
        "use": "sig",
        "n": "modulus",
        "e": "AQAB"
    }))?;

    assert_eq!(jwk.kid(), Some("rsa-1"));
    assert!(jwk.is_signature_capable());
    Ok(())
}

#[test]
fn parse_ec_jwk_success() -> TestResult {
    let jwk = parse_jwk(json!({
        "kty": "EC",
        "kid": "ec-1",
        "use": "sig",
        "crv": "P-256",
        "x": "abc",
        "y": "def"
    }))?;

    assert_eq!(jwk.kid(), Some("ec-1"));
    assert!(jwk.is_signature_capable());
    Ok(())
}

#[test]
fn missing_kty_is_rejected() -> TestResult {
    let err = parse_jwk(json!({ "n": "mod", "e": "AQAB" }))
        .err()
        .ok_or("missing kty should be rejected")?;
    assert_eq!(err, JwkError::MissingField("kty"));
    Ok(())
}

#[test]
fn duplicate_kid_detected() -> TestResult {
    let jwks = JwkSet::from_value(json!({
        "keys": [
            { "kty": "RSA", "kid": "dup", "n": "n1", "e": "AQAB" },
            { "kty": "RSA", "kid": "dup", "n": "n2", "e": "AQAB" }
        ]
    }))?;

    let err = jwks
        .ensure_unique_kid()
        .err()
        .ok_or("duplicate kid should be rejected")?;
    assert_eq!(err, JwkError::DuplicateKid("dup".into()));
    Ok(())
}

#[test]
fn signature_capability_requires_sig_use() -> TestResult {
    let jwk = parse_jwk(json!({
        "kty": "EC",
        "use": "enc",
        "crv": "P-256",
        "x": "abc",
        "y": "def"
    }))?;
    assert!(!jwk.is_signature_capable());
    Ok(())
}

#[test]
fn ensure_all_have_kid_enforces_presence() -> TestResult {
    let jwks = JwkSet::from_value(json!({
        "keys": [
            { "kty": "RSA", "kid": "present", "n": "n1", "e": "AQAB" },
            { "kty": "RSA", "n": "n2", "e": "AQAB" }
        ]
    }))?;

    let err = jwks
        .ensure_all_have_kid()
        .err()
        .ok_or("kid requirement should be enforced")?;
    assert_eq!(err, JwkError::KidRequired);
    Ok(())
}
