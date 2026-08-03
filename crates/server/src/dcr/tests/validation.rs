use super::*;
use crate::policy::DEVICE_CODE_GRANT_TYPE;
use serde_json::json;
use std::collections::HashSet;

fn base_client_registration() -> ClientRegistration {
    ClientRegistration {
        client_id: None,
        token_endpoint_auth_method: Some("client_secret_basic".into()),
        token_endpoint_auth_signing_alg: None,
        id_token_signed_response_alg: None,
        redirect_uris: Some(vec!["https://example.com/callback".into()]),
        post_logout_redirect_uris: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: None,
        jwks_uri: None,
        jwks: None,
        software_statement: None,
        grant_types: Some(vec!["authorization_code".into()]),
        response_types: Some(vec!["code".into()]),
        scope: None,
        pkce_required: None,
        require_sender_constrained_tokens: None,
        sender_constrained_methods: None,
        require_dpop: None,
        require_mtls: None,
    }
}

#[test]
fn software_statement_metadata_consistency_accepts_absent_or_equal_fields() -> DcrTestResult {
    let registration = base_client_registration();
    let statement = ClientRegistration {
        redirect_uris: registration.redirect_uris.clone(),
        grant_types: registration.grant_types.clone(),
        pkce_required: None,
        ..ClientRegistration::default()
    };

    assert!(validate_software_statement_metadata_consistency(&registration, &statement).is_ok());
    Ok(())
}

#[test]
fn software_statement_metadata_consistency_rejects_conflicting_fields() -> DcrTestResult {
    let registration = base_client_registration();
    let statement = ClientRegistration {
        redirect_uris: Some(vec!["https://ssa.example/callback".to_string()]),
        ..ClientRegistration::default()
    };

    let err = must_err!(
        validate_software_statement_metadata_consistency(&registration, &statement),
        "conflicting software statement metadata must fail closed",
    );

    assert_eq!(
        err,
        "software_statement metadata conflicts with redirect_uris"
    );
    Ok(())
}

fn allowed_algs(list: &[&str]) -> HashSet<String> {
    list.iter().map(std::string::ToString::to_string).collect()
}

#[test]
fn dcr_rejects_non_code_response_types() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.response_types = Some(vec!["token".into()]);
    let res = validate_registration(&meta, false, &allowed_algs(&["RS256"]));
    assert!(matches!(res, Err(ref err) if err.contains("response_types")));
    Ok(())
}

#[test]
fn dcr_rejects_password_grant_type() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.grant_types = Some(vec!["authorization_code".into(), "password".into()]);
    let res = validate_registration(&meta, false, &allowed_algs(&["RS256"]));
    assert!(matches!(res, Err(ref err) if err.contains("password")));
    Ok(())
}

#[test]
fn dcr_rejects_malformed_scope_string() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.scope = Some("openid\tprofile".to_string());

    let res = validate_registration(&meta, false, &allowed_algs(&["RS256"]));

    assert!(matches!(res, Err(ref err) if err.contains("scope is invalid")));
    Ok(())
}

#[test]
fn dcr_rejects_refresh_without_code_grant() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.grant_types = Some(vec!["refresh_token".into()]);
    let res = validate_registration(&meta, false, &allowed_algs(&["RS256"]));
    assert!(matches!(
        res,
        Err(ref err) if err.contains("refresh_token requires authorization_code")
    ));
    Ok(())
}

#[test]
fn dcr_rejects_unsupported_grant_type() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.grant_types = Some(vec!["authorization_code".into(), "urn:custom".into()]);
    let res = validate_registration(&meta, false, &allowed_algs(&["RS256"]));
    assert!(matches!(res, Err(ref err) if err.contains("unsupported grant_type")));
    Ok(())
}

#[test]
fn dcr_accepts_device_code_grant_when_policy_enables_it() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.grant_types = Some(vec![
        "authorization_code".to_string(),
        DEVICE_CODE_GRANT_TYPE.to_string(),
    ]);
    let policy = crate::management::types::PolicyDocument::default();
    let config = must_ok!(
        DcrValidationConfig::try_from_policy(
            &policy,
            false,
            false,
            true,
            false,
            aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
        ),
        "device_code-enabled DCR policy should build",
    );

    assert!(
        validate_registration_with_config(&meta, false, &allowed_algs(&["RS256"]), &config).is_ok()
    );
    Ok(())
}

#[test]
fn dcr_validation_config_rejects_invalid_ssa_public_key_pem() -> DcrTestResult {
    let policy = crate::management::types::PolicyDocument {
        ssa_jwt_pem: Some("not a PEM public key".to_string()),
        ..Default::default()
    };

    let err = must_err!(
        DcrValidationConfig::try_from_policy(
            &policy,
            false,
            false,
            false,
            false,
            aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
        ),
        "invalid software-statement public key PEM must fail closed",
    );

    assert!(matches!(
        err,
        crate::config::ConfigError::InvalidValue { key, .. } if key == "ssa_jwt_pem"
    ));
    Ok(())
}

#[test]
fn dcr_validation_config_accepts_valid_ssa_public_key_pem() -> DcrTestResult {
    let policy = crate::management::types::PolicyDocument {
        ssa_jwt_pem: Some(TEST_RSA_PUBLIC_KEY_PEM.to_string()),
        ..Default::default()
    };

    let config = must_ok!(
        DcrValidationConfig::try_from_policy(
            &policy,
            false,
            false,
            false,
            false,
            aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
        ),
        "valid software-statement public key PEM should build DCR validation config",
    );

    assert_eq!(
        config.software_statement().public_key_pem.as_deref(),
        Some(TEST_RSA_PUBLIC_KEY_PEM.trim())
    );
    Ok(())
}

#[test]
fn dcr_rejects_device_code_grant_when_policy_disables_it() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.grant_types = Some(vec![
        "authorization_code".to_string(),
        DEVICE_CODE_GRANT_TYPE.to_string(),
    ]);

    let err = must_err!(
        validate_registration(&meta, false, &allowed_algs(&["RS256"])),
        "device_code grant must fail closed when disabled",
    );

    assert!(err.contains("device_code grant is disabled by policy"));
    Ok(())
}

#[test]
fn dcr_rejects_unimplemented_mtls_client_auth_methods() -> DcrTestResult {
    for method in ["tls_client_auth", "self_signed_tls_client_auth"] {
        let mut meta = base_client_registration();
        meta.token_endpoint_auth_method = Some(method.to_string());

        let err = must_err!(
                validate_registration(&meta, false, &allowed_algs(&["RS256"])),
                "mTLS client authentication methods must fail closed until endpoint auth is implemented",
            );

        assert!(
            err.contains("not implemented"),
            "{method} should be rejected as unimplemented, got {err}"
        );
    }
    Ok(())
}

#[test]
fn dcr_rejects_unimplemented_mtls_sender_method() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.require_sender_constrained_tokens = Some(true);
    meta.sender_constrained_methods = Some(vec!["mtls".to_string()]);

    let err = must_err!(
        validate_registration(&meta, false, &allowed_algs(&["RS256"])),
        "mTLS sender-constrained DCR must fail closed until mTLS client auth is implemented",
    );

    assert!(
        err.contains("method 'mtls' is not implemented"),
        "mTLS sender method should be rejected as unimplemented, got {err}"
    );
    Ok(())
}

#[test]
fn private_key_jwt_rejects_disallowed_alg() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.token_endpoint_auth_method = Some("private_key_jwt".into());
    meta.token_endpoint_auth_signing_alg = Some("PS256".into());
    let res = validate_registration(&meta, true, &allowed_algs(&["RS256"]));
    assert!(matches!(res, Err(ref err) if err.contains("alg PS256 not allowed")));
    Ok(())
}

#[test]
fn private_key_jwt_rejects_policy_without_promoted_rs256_alg() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.token_endpoint_auth_method = Some("private_key_jwt".into());
    meta.token_endpoint_auth_signing_alg = Some("EdDSA".into());
    meta.jwks = Some(json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "kid": "client-key",
            "x": "test",
            "y": "value"
        }]
    }));
    let err = must_err!(
        validate_registration(&meta, true, &allowed_algs(&["EDDSA"])),
        "client JWT policy without promoted RS256 must be rejected",
    );
    assert!(err.contains("promoted RS256"));
    Ok(())
}

#[test]
fn private_key_jwt_accepts_allowed_alg_with_jwks_uri() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.token_endpoint_auth_method = Some("private_key_jwt".into());
    meta.token_endpoint_auth_signing_alg = Some("RS256".into());
    meta.jwks_uri = Some("https://example.com/jwks.json".into());
    assert!(validate_registration(&meta, true, &allowed_algs(&["RS256"])).is_ok());
    Ok(())
}

#[test]
fn private_key_jwt_rejects_missing_key_source_even_when_kid_optional() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.token_endpoint_auth_method = Some("private_key_jwt".into());
    meta.token_endpoint_auth_signing_alg = Some("RS256".into());

    let err = must_err!(
        validate_registration(&meta, false, &allowed_algs(&["RS256"])),
        "private_key_jwt without jwks_uri or jwks must be rejected",
    );

    assert!(err.contains("jwks_uri or jwks"));
    Ok(())
}

#[test]
fn private_key_jwt_jwks_uri_still_runs_common_dcr_policy_gates() -> DcrTestResult {
    let mut ropc = base_client_registration();
    ropc.token_endpoint_auth_method = Some("private_key_jwt".into());
    ropc.token_endpoint_auth_signing_alg = Some("RS256".into());
    ropc.jwks_uri = Some("https://example.com/jwks.json".into());
    ropc.grant_types = Some(vec!["password".into()]);
    let err = must_err!(
        validate_registration(&ropc, true, &allowed_algs(&["RS256"])),
        "private_key_jwt jwks_uri must not bypass ROPC rejection",
    );
    assert!(err.contains("ROPC"));

    let mut implicit = base_client_registration();
    implicit.token_endpoint_auth_method = Some("private_key_jwt".into());
    implicit.token_endpoint_auth_signing_alg = Some("RS256".into());
    implicit.jwks_uri = Some("https://example.com/jwks.json".into());
    implicit.response_types = Some(vec!["token".into()]);
    let err = must_err!(
        validate_registration(&implicit, true, &allowed_algs(&["RS256"])),
        "private_key_jwt jwks_uri must not bypass response type rejection",
    );
    assert!(err.contains("response_types"));
    Ok(())
}

#[test]
fn private_key_jwt_rejects_server_side_jwks_uri_ssrf_shapes() -> DcrTestResult {
    for uri in [
        "http://127.0.0.1/jwks.json",
        "https://127.0.0.1/jwks.json",
        "https://localhost/jwks.json",
        "https://[fc00::1]/jwks.json",
        "https://169.254.169.254/latest/meta-data",
        "https://user@example.com/jwks.json",
        "https://example.com/jwks.json#fragment",
    ] {
        let mut meta = base_client_registration();
        meta.token_endpoint_auth_method = Some("private_key_jwt".into());
        meta.token_endpoint_auth_signing_alg = Some("RS256".into());
        meta.jwks_uri = Some(uri.into());

        let err = must_err!(
            validate_registration(&meta, true, &allowed_algs(&["RS256"])),
            "unsafe jwks_uri must be rejected",
        );
        assert!(
            err.contains("jwks_uri"),
            "unexpected error for {uri}: {err}"
        );
    }
    Ok(())
}

#[test]
fn jwks_loopback_override_is_test_helper_only_for_dcr_validation() -> DcrTestResult {
    let _guard = env_lock()?;
    let _env = override_env_var("AEGAEON_JWKS_ALLOW_HTTP_LOOPBACK_FOR_TESTS", Some("1"));

    let mut meta = base_client_registration();
    meta.token_endpoint_auth_method = Some("private_key_jwt".into());
    meta.token_endpoint_auth_signing_alg = Some("RS256".into());
    meta.jwks_uri = Some("http://127.0.0.1/jwks.json".into());

    let result = validate_registration(&meta, true, &allowed_algs(&["RS256"]));
    assert_eq!(
        result.is_ok(),
        crate::config::test_runtime_helpers_allowed_by_build()
    );
    Ok(())
}

#[test]
fn backchannel_logout_uri_rejects_server_side_callback_ssrf_shapes() -> DcrTestResult {
    for uri in [
        "http://example.com/logout",
        "https://127.0.0.1/logout",
        "https://localhost/logout",
        "https://10.0.0.1/logout",
        "https://[fc00::1]/logout",
        "https://user@example.com/logout",
        "https://example.com/logout#fragment",
    ] {
        let mut meta = base_client_registration();
        meta.backchannel_logout_uri = Some(uri.into());

        let err = must_err!(
            validate_registration(&meta, true, &allowed_algs(&["RS256"])),
            "unsafe backchannel_logout_uri must be rejected",
        );
        assert!(
            err.contains("backchannel_logout_uri"),
            "unexpected error for {uri}: {err}"
        );
    }
    Ok(())
}

#[test]
fn dcr_rejects_server_side_jwks_uri_ssrf_shapes_for_secret_clients() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.jwks_uri = Some("https://127.0.0.1/jwks.json".into());

    let err = must_err!(
        validate_registration(&meta, true, &allowed_algs(&["RS256"])),
        "unsafe jwks_uri must be rejected for every registered key surface",
    );
    assert!(err.contains("jwks_uri"));
    Ok(())
}

#[test]
fn dcr_rejects_invalid_inline_jwks_for_secret_clients() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.jwks = Some(json!({
        "keys": [
            { "kty": "RSA", "kid": "dup", "n": "n1", "e": "AQAB" },
            { "kty": "RSA", "kid": "dup", "n": "n2", "e": "AQAB" }
        ]
    }));

    let err = must_err!(
        validate_registration(&meta, true, &allowed_algs(&["RS256"])),
        "invalid inline JWKS must be rejected for every registered key surface",
    );
    assert!(err.contains("duplicate"));
    Ok(())
}

#[test]
fn dcr_rejects_unsupported_id_token_signing_alg() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.id_token_signed_response_alg = Some("HS256".into());
    let res = validate_registration(&meta, false, &allowed_algs(&["RS256"]));
    assert!(matches!(
        res,
        Err(ref err) if err.contains("id_token_signed_response_alg HS256 is not supported")
    ));
    Ok(())
}

#[test]
fn private_key_jwt_accepts_inline_jwks_with_kid() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.token_endpoint_auth_method = Some("private_key_jwt".into());
    meta.token_endpoint_auth_signing_alg = Some("RS256".into());
    meta.jwks = Some(json!({
        "keys": [{
            "kty": "RSA",
            "kid": "client-key",
            "n": "test",
            "e": "AQAB"
        }]
    }));
    assert!(validate_registration(&meta, true, &allowed_algs(&["RS256"])).is_ok());
    Ok(())
}

#[test]
fn private_key_jwt_rejects_inline_jwks_missing_kid() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.token_endpoint_auth_method = Some("private_key_jwt".into());
    meta.token_endpoint_auth_signing_alg = Some("RS256".into());
    meta.jwks = Some(json!({
        "keys": [{ "kty": "RSA", "n": "mod", "e": "AQAB" }]
    }));
    let err = must_err!(
        validate_registration(&meta, true, &allowed_algs(&["RS256"])),
        "inline JWKS without kid must be rejected",
    );
    assert!(err.contains("kid"));
    Ok(())
}

#[test]
fn private_key_jwt_rejects_inline_jwks_duplicate_kid() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.token_endpoint_auth_method = Some("private_key_jwt".into());
    meta.token_endpoint_auth_signing_alg = Some("RS256".into());
    meta.jwks = Some(json!({
        "keys": [
            { "kty": "RSA", "kid": "dup", "n": "n1", "e": "AQAB" },
            { "kty": "RSA", "kid": "dup", "n": "n2", "e": "AQAB" }
        ]
    }));
    let err = must_err!(
        validate_registration(&meta, true, &allowed_algs(&["RS256"])),
        "duplicate kid entries must be rejected",
    );
    assert!(err.contains("duplicate"));
    Ok(())
}

#[test]
fn private_key_jwt_rejects_inline_jwks_without_signature_capability() -> DcrTestResult {
    let mut meta = base_client_registration();
    meta.token_endpoint_auth_method = Some("private_key_jwt".into());
    meta.token_endpoint_auth_signing_alg = Some("RS256".into());
    meta.jwks = Some(json!({
        "keys": [{
            "kty": "RSA",
            "kid": "enc-key",
            "use": "enc",
            "n": "abc",
            "e": "AQAB"
        }]
    }));
    let err = must_err!(
        validate_registration(&meta, true, &allowed_algs(&["RS256"])),
        "non-signature JWKS entries must be rejected",
    );
    assert!(err.contains("signature-capable"));
    Ok(())
}
