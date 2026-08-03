use super::*;
use aegaeon_jose::raw_json::RawJsonSurface;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{crypto, Algorithm, EncodingKey, Header};
use serde_json::Value;

fn build_raw_rs256_jwt(raw_claims_json: &str) -> Result<String, String> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("ssa-test-kid".to_string());
    let header_b64 = URL_SAFE_NO_PAD.encode(must_ok!(
        serde_json::to_vec(&header),
        "header serialization should succeed",
    ));
    let payload_b64 = URL_SAFE_NO_PAD.encode(raw_claims_json.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let encoding_key = must_ok!(
        EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes()),
        "RSA private key fixture should parse",
    );
    let signature = must_ok!(
        crypto::sign(signing_input.as_bytes(), &encoding_key, Algorithm::RS256),
        "RSA signing should succeed",
    );
    Ok(format!("{signing_input}.{signature}"))
}

fn test_software_statement_config() -> SoftwareStatementValidationConfig {
    SoftwareStatementValidationConfig {
        public_key_pem: Some(TEST_RSA_PUBLIC_KEY_PEM.to_string()),
        expected_issuer: None,
        expected_audience: None,
        leeway_secs: 120,
        jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
    }
}

#[test]
fn software_statement_rejects_duplicate_claim_keys() -> DcrTestResult {
    let _guard = env_lock()?;
    let _raw_json_guard = raw_json_env_lock()?;
    let _jose_header_backend = override_jose_header_verified_structural_backend();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::SoftwareStatement,
        ),
        Some("verified-structural-v1"),
    );
    let ssa = build_raw_rs256_jwt(
        r#"{
                "iss":"https://issuer.example",
                "sub":"ssa-client",
                "sub":"evil-client",
                "exp":4102444800
            }"#,
    )?;

    let err =
        verify_software_statement_profile_v1_with_config(&ssa, &test_software_statement_config());
    assert!(
        err.is_err(),
        "duplicate software statement claims must fail closed"
    );
    Ok(())
}

#[test]
fn software_statement_rejects_unknown_surface_raw_json_backend_override() -> DcrTestResult {
    let _ssa_guard = env_lock()?;
    let _raw_json_guard = raw_json_env_lock()?;
    let _jose_header_backend = override_jose_header_verified_structural_backend();
    let raw_json_key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        aegaeon_jose::raw_json::RawJsonSurface::SoftwareStatement,
    );
    let previous_backend = std::env::var(raw_json_key).ok();
    std::env::set_var(raw_json_key, "future");

    let ssa = build_raw_rs256_jwt(
        r#"{
                "iss":"https://issuer.example",
                "sub":"ssa-client",
                "exp":4102444800
            }"#,
    )?;

    let err = must_err!(
        verify_software_statement_profile_v1_with_config(&ssa, &test_software_statement_config(),),
        "unknown software-statement backend override must fail closed",
    );

    if let Some(prev) = previous_backend {
        std::env::set_var(raw_json_key, prev);
    } else {
        std::env::remove_var(raw_json_key);
    }

    assert_eq!(
        err,
        SoftwareStatementVerificationError::BackendPolicy("software-statement")
    );
    Ok(())
}

#[test]
fn software_statement_reports_unknown_jose_header_backend_override() -> DcrTestResult {
    let _ssa_guard = env_lock()?;
    let _raw_json_guard = raw_json_env_lock()?;
    let _jose_header_backend = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            aegaeon_jose::raw_json::RawJsonSurface::JoseHeader,
        ),
        Some("future"),
    );

    let ssa = build_raw_rs256_jwt(
        r#"{
                "iss":"https://issuer.example",
                "sub":"ssa-client",
                "exp":4102444800
            }"#,
    )?;

    let err = must_err!(
        verify_software_statement_profile_v1_with_config(&ssa, &test_software_statement_config(),),
        "unknown jose-header backend override must fail closed",
    );

    assert_eq!(
        err,
        SoftwareStatementVerificationError::BackendPolicy("jose-header")
    );
    Ok(())
}

#[test]
fn software_statement_accepts_structural_surface_raw_json_backend_override() -> DcrTestResult {
    let _ssa_guard = env_lock()?;
    let _raw_json_guard = raw_json_env_lock()?;
    if raw_json_structural_parser_unavailable(
        br#"{"iss":"https://issuer.example","sub":"ssa-client","exp":4102444800,"redirect_uris":["https://client.example/callback"]}"#,
    ) {
        return Ok(());
    }
    let _jose_header_backend = override_jose_header_verified_structural_backend();
    let raw_json_key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        aegaeon_jose::raw_json::RawJsonSurface::SoftwareStatement,
    );
    let previous_backend = std::env::var(raw_json_key).ok();
    std::env::set_var(raw_json_key, "verified-structural-v1");

    let ssa = build_raw_rs256_jwt(
        r#"{
                "iss":"https://issuer.example",
                "sub":"ssa-client",
                "exp":4102444800,
                "redirect_uris":["https://client.example/callback"]
            }"#,
    )?;

    let profile = must_ok!(
        verify_software_statement_profile_v1_with_config(&ssa, &test_software_statement_config(),),
        "software statement structural backend should verify",
    );

    if let Some(prev) = previous_backend {
        std::env::set_var(raw_json_key, prev);
    } else {
        std::env::remove_var(raw_json_key);
    }
    assert_eq!(profile.claims.sub.as_deref(), Some("ssa-client"));
    assert_eq!(
        software_statement_profile_redirect_uris(&profile),
        Some(vec!["https://client.example/callback".to_string()])
    );
    Ok(())
}

#[test]
fn software_statement_profile_uses_snapshot_config_without_env() -> DcrTestResult {
    let _ssa_guard = env_lock()?;
    let _raw_json_guard = raw_json_env_lock()?;
    let _jose_header_backend = override_jose_header_verified_structural_backend();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::SoftwareStatement,
        ),
        Some("verified-structural-v1"),
    );
    let _pem_env = override_env_var("AEGAEON_SSA_JWT_PEM", None);
    let config = SoftwareStatementValidationConfig {
        public_key_pem: Some(TEST_RSA_PUBLIC_KEY_PEM.to_string()),
        expected_issuer: Some("https://issuer.example".to_string()),
        expected_audience: None,
        leeway_secs: 120,
        jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
    };

    let ssa = build_raw_rs256_jwt(
        r#"{
                "iss":"https://issuer.example",
                "sub":"ssa-client",
                "exp":4102444800,
                "redirect_uris":["https://client.example/callback"]
            }"#,
    )?;

    let profile = must_ok!(
        verify_software_statement_profile_v1_with_config(&ssa, &config),
        "snapshot software statement config should verify without reading env",
    );

    assert_eq!(
        software_statement_profile_redirect_uris(&profile),
        Some(vec!["https://client.example/callback".to_string()])
    );
    Ok(())
}

#[test]
fn software_statement_preserves_extensions_separately_from_registered_claims() -> DcrTestResult {
    let _guard = env_lock()?;
    let _raw_json_guard = raw_json_env_lock()?;
    let _jose_header_backend = override_jose_header_verified_structural_backend();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::SoftwareStatement,
        ),
        Some("verified-structural-v1"),
    );
    let ssa = build_raw_rs256_jwt(
        r#"{
                "iss":"https://issuer.example",
                "sub":"ssa-client",
                "exp":4102444800,
                "redirect_uris":["https://client.example/callback"],
                "software_id":"acct-app"
            }"#,
    )?;

    let profile = must_ok!(
        verify_software_statement_profile_v1_with_config(&ssa, &test_software_statement_config(),),
        "valid software statement should verify",
    );
    let redirect_uris = software_statement_profile_redirect_uris(&profile);

    assert_eq!(
        profile.claims.iss.as_deref(),
        Some("https://issuer.example")
    );
    assert_eq!(profile.claims.sub.as_deref(), Some("ssa-client"));
    assert_eq!(
        redirect_uris,
        Some(vec!["https://client.example/callback".to_string()])
    );
    assert_eq!(
        profile.claims.custom.get("software_id"),
        Some(&Value::String("acct-app".to_string()))
    );
    Ok(())
}

#[test]
fn software_statement_profile_rejects_non_string_redirect_uri_entries() -> DcrTestResult {
    let _guard = env_lock()?;
    let _raw_json_guard = raw_json_env_lock()?;
    let _jose_header_backend = override_jose_header_verified_structural_backend();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::SoftwareStatement,
        ),
        Some("verified-structural-v1"),
    );
    let ssa = build_raw_rs256_jwt(
        r#"{
                "iss":"https://issuer.example",
                "sub":"ssa-client",
                "exp":4102444800,
                "redirect_uris":["https://client.example/callback", 7]
            }"#,
    )?;

    let err = must_err!(
        verify_software_statement_profile_v1_with_config(&ssa, &test_software_statement_config(),),
        "malformed redirect_uris extension must fail closed",
    );

    assert!(
        err.to_string().contains("ssa metadata invalid"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn software_statement_profile_rejects_metadata_alias_collision() -> DcrTestResult {
    let _guard = env_lock()?;
    let _raw_json_guard = raw_json_env_lock()?;
    let _jose_header_backend = override_jose_header_verified_structural_backend();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::SoftwareStatement,
        ),
        Some("verified-structural-v1"),
    );
    let ssa = build_raw_rs256_jwt(
        r#"{
                "iss":"https://issuer.example",
                "sub":"ssa-client",
                "exp":4102444800,
                "pkce_required":true,
                "require_pkce":false
            }"#,
    )?;

    let err = must_err!(
        verify_software_statement_profile_v1_with_config(&ssa, &test_software_statement_config(),),
        "metadata aliases must fail closed",
    );

    assert_eq!(err.to_string(), "ssa metadata alias collision");
    Ok(())
}

#[test]
fn software_statement_profile_rejects_nested_software_statement_metadata() -> DcrTestResult {
    let _guard = env_lock()?;
    let _raw_json_guard = raw_json_env_lock()?;
    let _jose_header_backend = override_jose_header_verified_structural_backend();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::SoftwareStatement,
        ),
        Some("verified-structural-v1"),
    );
    let ssa = build_raw_rs256_jwt(
        r#"{
                "iss":"https://issuer.example",
                "sub":"ssa-client",
                "exp":4102444800,
                "software_statement":"nested"
            }"#,
    )?;

    let err = must_err!(
        verify_software_statement_profile_v1_with_config(&ssa, &test_software_statement_config(),),
        "nested software_statement metadata must fail closed",
    );

    assert_eq!(
        err.to_string(),
        "ssa metadata invalid: nested software_statement is not allowed"
    );
    Ok(())
}
