use super::*;

#[test]
fn metadata_core_fields_are_non_empty() {
    let base = "https://as.example.com";
    let metadata = secure_metadata(base);
    assert!(!metadata.issuer.is_empty(), "issuer must be non-empty");
    assert!(metadata.issuer.starts_with(base));
    assert!(!metadata.authorization_endpoint.is_empty());
    assert!(metadata.authorization_endpoint.starts_with(base));
    assert!(!metadata.token_endpoint.is_empty());
    assert!(metadata.token_endpoint.starts_with(base));
    assert!(!metadata.response_types_supported.is_empty());
    assert!(metadata
        .response_types_supported
        .iter()
        .all(|entry| !entry.is_empty()));
    assert!(metadata
        .response_types_supported
        .iter()
        .any(|entry| entry == "code"));
}

#[test]
fn test_metadata_serialization() -> TestResult {
    let metadata = AuthorizationServerMetadata {
        issuer: "https://server.example.com".to_string(),
        authorization_endpoint: "https://server.example.com/authorize".to_string(),
        token_endpoint: "https://server.example.com/token".to_string(),
        ..Default::default()
    };

    let json = serde_json::to_string(&metadata)?;
    assert!(json.contains("\"issuer\":\"https://server.example.com\""));
    assert!(json.contains("\"authorization_endpoint\":\"https://server.example.com/authorize\""));
    Ok(())
}

#[test]
fn test_par_metadata() {
    let metadata = AuthorizationServerMetadata::default()
        .with_par_support("https://server.example.com/par".to_string(), true);

    assert_eq!(
        metadata.pushed_authorization_request_endpoint,
        Some("https://server.example.com/par".to_string())
    );
    assert_eq!(metadata.require_pushed_authorization_requests, Some(true));
}

#[test]
fn test_security_extensions() {
    let metadata = AuthorizationServerMetadata::default()
        .with_pkce_support()
        .with_dpop_support(vec!["EdDSA".to_string()])
        .with_issuer_identification();

    assert!(metadata.code_challenge_methods_supported.is_some());
    assert!(metadata.dpop_signing_alg_values_supported.is_some());
    assert_eq!(
        metadata.authorization_response_iss_parameter_supported,
        Some(true)
    );
}

#[test]
fn test_secure_metadata_creation() -> TestResult {
    let metadata = secure_metadata("https://auth.example.com");

    assert_eq!(metadata.issuer, "https://auth.example.com");
    assert_eq!(metadata.require_pushed_authorization_requests, Some(false));
    assert!(metadata.dpop_signing_alg_values_supported.is_some());
    let methods = metadata
        .code_challenge_methods_supported
        .as_ref()
        .ok_or_else(|| io::Error::other("missing PKCE methods"))?;
    assert!(methods.contains(&"S256".to_string()));
    assert!(!methods.contains(&"plain".to_string()));
    assert_eq!(
        metadata.authorization_response_iss_parameter_supported,
        Some(true)
    );

    assert!(!metadata
        .response_types_supported
        .contains(&"token".to_string()));
    assert!(!metadata
        .grant_types_supported
        .contains(&"password".to_string()));
    Ok(())
}

#[test]
fn secure_metadata_omits_registration_endpoint_when_dcr_disabled() {
    let metadata = secure_metadata("https://auth.example.com");

    assert!(
        metadata.registration_endpoint.is_none(),
        "DCR-disabled runtime must not advertise a registration endpoint"
    );
}

#[test]
fn secure_metadata_advertises_registration_endpoint_when_dcr_enabled() -> TestResult {
    let runtime = runtime_with_dcr_enabled();
    let metadata = secure_metadata_with_runtime("https://auth.example.com", &runtime)?;

    assert_eq!(
        metadata.registration_endpoint.as_deref(),
        Some("https://auth.example.com/register")
    );
    Ok(())
}

#[test]
fn secure_metadata_omits_authorization_details_types_when_empty() -> TestResult {
    let metadata = secure_metadata("https://auth.example.com");

    assert!(metadata.authorization_details_types_supported.is_none());
    let value = serde_json::to_value(&metadata)?;
    assert!(value.get("authorization_details_types_supported").is_none());
    Ok(())
}

#[test]
fn secure_metadata_advertises_configured_authorization_details_types() -> TestResult {
    let expected = vec![
        "payment_initiation".to_string(),
        "account_information".to_string(),
    ];
    let runtime = MetadataRuntimeConfig {
        authorization_details_types_supported: expected.clone(),
        ..Default::default()
    };
    let metadata = secure_metadata_with_runtime("https://auth.example.com", &runtime)?;

    assert_eq!(
        metadata.authorization_details_types_supported.as_ref(),
        Some(&expected)
    );
    let value = serde_json::to_value(&metadata)?;
    assert_eq!(
        value.get("authorization_details_types_supported"),
        Some(&serde_json::json!(expected))
    );
    Ok(())
}

#[test]
fn secure_metadata_grant_types_follow_runtime_allowlist() -> TestResult {
    let runtime = MetadataRuntimeConfig {
        grant_types_supported: vec!["authorization_code".to_string()],
        ..Default::default()
    };
    let metadata = secure_metadata_with_runtime("https://auth.example.com", &runtime)?;

    assert_eq!(metadata.grant_types_supported, vec!["authorization_code"]);
    Ok(())
}

#[test]
fn secure_metadata_rejects_invalid_runtime_grant_allowlist() {
    let runtime = MetadataRuntimeConfig {
        grant_types_supported: vec!["authorization_code".to_string(), "urn:custom".to_string()],
        ..Default::default()
    };
    let result = AuthorizationServerMetadata::try_new_secure_with_runtime_config(
        "https://auth.example.com",
        &runtime,
    );

    assert!(matches!(
        result,
        Err(ConfigError::InvalidValue { key, .. }) if key == "grant_types_supported"
    ));
}

#[test]
fn secure_metadata_rejects_http_non_loopback_base_url() {
    let runtime = MetadataRuntimeConfig::default();
    let result = AuthorizationServerMetadata::try_new_secure_with_runtime_config(
        "http://auth.example.com",
        &runtime,
    );

    assert!(matches!(
        result,
        Err(ConfigError::InvalidValue { key, .. }) if key == "issuer_url"
    ));
}

#[test]
fn secure_metadata_allows_loopback_http_base_url_for_local_development() -> TestResult {
    let runtime = MetadataRuntimeConfig::default();
    let metadata = AuthorizationServerMetadata::try_new_secure_with_runtime_config(
        "http://127.0.0.1:8080",
        &runtime,
    )?;

    assert_eq!(metadata.issuer, "http://127.0.0.1:8080");
    assert_eq!(
        metadata.authorization_endpoint,
        "http://127.0.0.1:8080/authorize"
    );
    Ok(())
}

#[test]
fn secure_metadata_rejects_non_routable_https_base_urls() {
    for base_url in [
        "https://localhost",
        "https://127.0.0.1",
        "https://[::1]",
        "https://[fc00::1]",
        "https://169.254.169.254",
    ] {
        let result = validate_public_base_url(base_url);
        assert!(
            matches!(result, Err(ConfigError::InvalidValue { key, .. }) if key == "issuer_url"),
            "non-routable base URL must be rejected: {base_url}"
        );
    }
}

#[test]
fn secure_metadata_rejects_structurally_unsafe_base_urls() {
    for base_url in [
        "https://user@auth.example.com",
        "https://user:password@auth.example.com",
        "https://auth.example.com?tenant=one",
        "https://auth.example.com#fragment",
    ] {
        let result = validate_public_base_url(base_url);
        assert!(
            matches!(result, Err(ConfigError::InvalidValue { key, .. }) if key == "issuer_url"),
            "unsafe base URL must be rejected: {base_url}"
        );
    }
}

#[test]
fn test_security_compliance_validation_pass() {
    let metadata = secure_metadata("https://auth.example.com");
    assert!(metadata.validate_security_compliance().is_ok());
}

#[test]
fn test_security_compliance_validation_failures() -> TestResult {
    let mut metadata = secure_metadata("https://auth.example.com");
    metadata.response_types_supported.push("token".to_string());
    let result = metadata.validate_security_compliance();
    assert!(result.is_err());
    let Err(errors) = result else {
        return Err(io::Error::other("expected implicit flow failure").into());
    };
    assert!(errors.iter().any(|e| e.contains("Implicit flow")));

    metadata = secure_metadata("https://auth.example.com");
    metadata.grant_types_supported.push("password".to_string());
    let result = metadata.validate_security_compliance();
    assert!(result.is_err());
    let Err(errors) = result else {
        return Err(io::Error::other("expected password grant failure").into());
    };
    assert!(errors.iter().any(|e| e.contains("Password grant")));

    metadata = secure_metadata("https://auth.example.com");
    if let Some(ref mut methods) = metadata.code_challenge_methods_supported {
        methods.push("plain".to_string());
    }
    let result = metadata.validate_security_compliance();
    assert!(result.is_err());
    let Err(errors) = result else {
        return Err(io::Error::other("expected plain PKCE failure").into());
    };
    assert!(errors.iter().any(|e| e.contains("Plain PKCE")));
    Ok(())
}

#[test]
fn test_pkce_s256_only() -> TestResult {
    let metadata = AuthorizationServerMetadata::default().with_pkce_support();
    let methods = metadata
        .code_challenge_methods_supported
        .ok_or_else(|| io::Error::other("missing PKCE methods"))?;
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0], "S256");
    Ok(())
}
