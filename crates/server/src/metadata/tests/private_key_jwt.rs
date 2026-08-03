use super::*;
use aegaeon_jose::algorithms::CryptoProfile;

#[test]
fn test_private_key_jwt_metadata_verified_profile_promotes_rs256_slice() -> TestResult {
    let runtime = MetadataRuntimeConfig {
        crypto_profile: CryptoProfile::Verified,
        enable_private_key_jwt: true,
        client_jwt_algs: vec!["RS256".to_string()],
        ..Default::default()
    };

    let metadata = secure_metadata_with_runtime("https://auth.example.com", &runtime)?;
    for methods in [
        metadata.token_endpoint_auth_methods_supported.as_ref(),
        metadata.revocation_endpoint_auth_methods_supported.as_ref(),
        metadata
            .introspection_endpoint_auth_methods_supported
            .as_ref(),
    ] {
        let methods = methods.ok_or_else(|| io::Error::other("methods should be present"))?;
        assert!(
            methods.contains(&"private_key_jwt".to_string()),
            "private_key_jwt should remain advertised for the promoted RS256 interop slice"
        );
    }
    let expected_algs = vec!["RS256".to_string()];
    for algs in [
        metadata
            .token_endpoint_auth_signing_alg_values_supported
            .as_ref(),
        metadata
            .revocation_endpoint_auth_signing_alg_values_supported
            .as_ref(),
        metadata
            .introspection_endpoint_auth_signing_alg_values_supported
            .as_ref(),
    ] {
        let algs = algs.ok_or_else(|| io::Error::other("signing algs should be present"))?;
        assert_eq!(algs, &expected_algs);
    }
    Ok(())
}

#[test]
fn test_client_jwt_allowed_alg_parser_rejects_unsupported_values() -> TestResult {
    let _guard = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|_| io::Error::other("mtls env guard poisoned"))?;

    let result = std::panic::catch_unwind(|| {
        crate::client_registry::ClientAssertionRuntimePolicy::try_new(
            ["EdDSA".to_string()],
            false,
            60,
            aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
            300,
            300,
        )
    });
    assert!(
        result.is_ok_and(|policy| policy.is_err()),
        "unsupported client JWT alg configuration must return an error"
    );
    Ok(())
}

#[test]
fn test_static_metadata_does_not_advertise_symmetric_jwt_access_token_alg() -> TestResult {
    let metadata = secure_metadata("https://auth.example.com");
    assert!(
        metadata.access_token_signing_alg_values_supported.is_none(),
        "static metadata must not advertise HS256 without public verification material"
    );
    Ok(())
}
