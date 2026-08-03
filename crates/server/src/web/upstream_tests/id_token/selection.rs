use super::*;

#[test]
fn parse_acr_values_trims_and_selects_supported() {
    let requested = parse_acr_values(Some("  urn:mfa  urn:pwd "));
    assert_eq!(
        requested,
        vec!["urn:mfa".to_string(), "urn:pwd".to_string()]
    );
    let supported = vec!["urn:pwd".to_string()];
    assert_eq!(
        select_supported_acr(&requested, &supported),
        Some("urn:pwd".to_string())
    );
}

#[test]
fn select_upstream_signing_key_prefers_kid() -> TestResult {
    let jwks = jwks_from_keys(&[rsa_key("k1"), rsa_key("k2")])?;
    let key = select_upstream_signing_key(&jwks, Some("k2"))
        .map_err(|err| format!("expected key to be selected: {err}"))?;
    assert_eq!(key.kid(), Some("k2"));
    Ok(())
}

#[test]
fn select_upstream_signing_key_requires_kid_when_multiple() -> TestResult {
    let jwks = jwks_from_keys(&[rsa_key("k1"), rsa_key("k2")])?;
    let err = require_err(
        select_upstream_signing_key(&jwks, None),
        "expected missing kid error",
    )?;
    assert!(err.contains("requires kid"));
    Ok(())
}

#[test]
fn select_upstream_signing_key_accepts_single_key() -> TestResult {
    let jwks = jwks_from_keys(&[rsa_key("k1")])?;
    let key = select_upstream_signing_key(&jwks, None)
        .map_err(|err| format!("expected single key to be selected: {err}"))?;
    assert_eq!(key.kid(), Some("k1"));
    Ok(())
}

#[test]
fn select_upstream_signing_key_rejects_unknown_kid() -> TestResult {
    let jwks = jwks_from_keys(&[rsa_key("k1")])?;
    let err = require_err(
        select_upstream_signing_key(&jwks, Some("missing")),
        "expected missing kid error",
    )?;
    assert!(err.contains("missing expected kid"));
    Ok(())
}
