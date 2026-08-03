use super::super::keys::{merge_signing_public_jwks, validated_additional_signing_jwks};
use super::*;
use crate::jwk_types::Jwk;

#[test]
fn oidc_config_additional_jwks_accepts_unique_kids() -> TestResult {
    let additional = validated_additional_signing_jwks(
        vec![Jwk {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            kid: "old-1".to_string(),
            alg: Some("RS256".to_string()),
            n: Some("mock_modulus".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        }],
        Some("active-1"),
    )?;
    let signing = OidcSigningKey::from_rsa_pem("active-1".into(), TEST_RSA_PRIVATE_KEY_PEM)?;
    let signing = signing.with_additional_public_jwks(additional)?;
    let jwks = signing.jwks();
    assert_eq!(jwks.keys.len(), 2);
    assert_eq!(jwks.keys[0].kid, "active-1");
    assert_eq!(jwks.keys[1].kid, "old-1");
    Ok(())
}

#[test]
fn oidc_config_additional_jwks_rejects_duplicate_kid() -> TestResult {
    let err = require_err(
        validated_additional_signing_jwks(
            vec![
                Jwk {
                    kty: "RSA".to_string(),
                    use_: Some("sig".to_string()),
                    kid: "old-1".to_string(),
                    alg: Some("RS256".to_string()),
                    n: Some("n1".to_string()),
                    e: Some("AQAB".to_string()),
                    x: None,
                    y: None,
                    crv: None,
                },
                Jwk {
                    kty: "RSA".to_string(),
                    use_: Some("sig".to_string()),
                    kid: "old-1".to_string(),
                    alg: Some("RS256".to_string()),
                    n: Some("n2".to_string()),
                    e: Some("AQAB".to_string()),
                    x: None,
                    y: None,
                    crv: None,
                },
            ],
            Some("active-1"),
        ),
        "duplicate kid should error",
    )?;
    assert!(matches!(
        err,
        OidcConfigError::AdditionalJwksDuplicateKid(_)
    ));
    Ok(())
}

#[test]
fn oidc_config_additional_jwks_rejects_conflicting_active_kid() -> TestResult {
    let err = require_err(
        validated_additional_signing_jwks(
            vec![Jwk {
                kty: "RSA".to_string(),
                use_: Some("sig".to_string()),
                kid: "active-1".to_string(),
                alg: Some("RS256".to_string()),
                n: Some("mock_modulus".to_string()),
                e: Some("AQAB".to_string()),
                x: None,
                y: None,
                crv: None,
            }],
            Some("active-1"),
        ),
        "conflicting kid should error",
    )?;
    assert!(matches!(
        err,
        OidcConfigError::AdditionalJwksConflictingKid(_)
    ));
    Ok(())
}

#[test]
fn oidc_config_additional_jwks_rejects_invalid_key_type_in_helper() -> TestResult {
    let err = validated_additional_signing_jwks(
        vec![Jwk {
            kty: "oct".to_string(),
            use_: Some("sig".to_string()),
            kid: "old-1".to_string(),
            alg: Some("RS256".to_string()),
            n: Some("mock_modulus".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        }],
        Some("active-1"),
    );
    let err = require_err(err, "non-RSA additional key should fail")?;

    assert!(matches!(
        err,
        OidcConfigError::AdditionalJwksUnsupportedKey(_)
    ));
    Ok(())
}

#[test]
fn oidc_config_merge_signing_public_jwks_returns_active_plus_overlap_keys() -> TestResult {
    let signing = OidcSigningKey::from_rsa_pem("active-1".into(), TEST_RSA_PRIVATE_KEY_PEM)?;
    let keys = merge_signing_public_jwks(
        signing.public_jwk(),
        signing.kid(),
        vec![Jwk {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            kid: "old-1".to_string(),
            alg: Some("RS256".to_string()),
            n: Some("mock_modulus".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        }],
    )?;

    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].kid, "active-1");
    assert_eq!(keys[1].kid, "old-1");
    Ok(())
}
