use super::*;

#[test]
fn runtime_metadata_constructor_uses_snapshot_instead_of_env() -> TestResult {
    let _guard = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|_| io::Error::other("mtls env guard poisoned"))?;
    std::env::set_var("AEGAEON_MTLS_ENABLED", "not-a-bool");
    std::env::set_var("AEGAEON_CLIENT_JWT_ALLOWED_ALGS", "HS256");

    let runtime = MetadataRuntimeConfig {
        mtls_enabled: true,
        mtls_base_url: Some("https://mtls.auth.example.com".to_string()),
        mtls_alias_par: true,
        enable_private_key_jwt: true,
        client_jwt_algs: vec!["RS256".to_string()],
        ..Default::default()
    };

    let metadata = AuthorizationServerMetadata::try_new_secure_with_runtime_config(
        "https://auth.example.com",
        &runtime,
    )?;
    let aliases = metadata
        .mtls_endpoint_aliases
        .ok_or_else(|| io::Error::other("mTLS aliases should use runtime snapshot"))?;

    assert_eq!(
        aliases.token_endpoint.as_deref(),
        Some("https://mtls.auth.example.com/token")
    );
    assert_eq!(
        aliases.pushed_authorization_request_endpoint.as_deref(),
        Some("https://mtls.auth.example.com/par")
    );
    assert_eq!(
        metadata.token_endpoint_auth_signing_alg_values_supported,
        Some(vec!["RS256".to_string()])
    );

    std::env::remove_var("AEGAEON_MTLS_ENABLED");
    std::env::remove_var("AEGAEON_CLIENT_JWT_ALLOWED_ALGS");
    Ok(())
}
