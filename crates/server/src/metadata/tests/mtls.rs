use super::*;

#[test]
fn secure_metadata_rejects_unsafe_mtls_alias_base_url() {
    for mtls_base_url in [
        "http://mtls.auth.example.com",
        "https://localhost",
        "https://127.0.0.1",
        "https://[fc00::1]",
    ] {
        let runtime = MetadataRuntimeConfig {
            mtls_enabled: true,
            mtls_base_url: Some(mtls_base_url.to_string()),
            ..Default::default()
        };

        let result = AuthorizationServerMetadata::try_new_secure_with_runtime_config(
            "https://auth.example.com",
            &runtime,
        );

        assert!(
            matches!(
                result,
                Err(ConfigError::InvalidValue { key, .. }) if key == "mtls_base_url"
            ),
            "unsafe mTLS alias base URL must be rejected: {mtls_base_url}"
        );
    }
}

#[test]
fn test_mtls_metadata_gating_disabled() -> TestResult {
    let metadata = secure_metadata_with_runtime(
        "https://auth.example.com",
        &MetadataRuntimeConfig::default(),
    )?;

    assert_eq!(
        metadata.tls_client_certificate_bound_access_tokens,
        Some(false),
        "mTLS tokens should be disabled when runtime mTLS is disabled"
    );
    assert!(
        metadata.mtls_endpoint_aliases.is_none(),
        "mTLS aliases should not be present when runtime mTLS policy is disabled"
    );
    Ok(())
}

#[test]
fn test_mtls_metadata_gating_enabled() -> TestResult {
    let runtime = MetadataRuntimeConfig {
        mtls_enabled: true,
        ..Default::default()
    };

    let metadata = secure_metadata_with_runtime("https://auth.example.com", &runtime)?;

    assert_eq!(
        metadata.tls_client_certificate_bound_access_tokens,
        Some(true),
        "mTLS tokens should be enabled when runtime mTLS is enabled"
    );
    assert!(
        metadata.mtls_endpoint_aliases.is_some(),
        "mTLS aliases should be present when runtime mTLS policy is enabled"
    );

    let aliases = metadata
        .mtls_endpoint_aliases
        .as_ref()
        .ok_or_else(|| io::Error::other("missing mTLS aliases"))?;

    assert!(
        aliases.token_endpoint.is_some(),
        "token_endpoint alias should be present"
    );
    assert!(
        aliases.revocation_endpoint.is_some(),
        "revocation_endpoint alias should be present"
    );
    assert!(
        aliases.introspection_endpoint.is_some(),
        "introspection_endpoint alias should be present"
    );
    assert!(
        aliases.pushed_authorization_request_endpoint.is_none(),
        "PAR alias should not be present when runtime PAR alias is disabled"
    );
    Ok(())
}

#[test]
fn test_mtls_par_alias_gating() -> TestResult {
    let runtime = MetadataRuntimeConfig {
        mtls_enabled: true,
        mtls_alias_par: true,
        ..Default::default()
    };

    let metadata = secure_metadata_with_runtime("https://auth.example.com", &runtime)?;

    let aliases = metadata
        .mtls_endpoint_aliases
        .as_ref()
        .ok_or_else(|| io::Error::other("mTLS aliases should be present"))?;

    assert!(
        aliases.pushed_authorization_request_endpoint.is_some(),
        "PAR alias should be present when runtime PAR alias is enabled"
    );
    Ok(())
}
