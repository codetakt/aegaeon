
#[test]
fn parse_introspect_form_rejects_duplicate_singleton_fields() -> TestResult {
    let fields = [
        ("token", "opaque-token"),
        ("token_type_hint", "access_token"),
        ("client_id", "client"),
        ("client_secret", "secret"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", "assertion"),
    ];

    for (field, duplicate_value) in [
        ("token", "other-token"),
        ("token_type_hint", "refresh_token"),
        ("client_id", "other-client"),
        ("client_secret", "other-secret"),
        ("client_assertion_type", "other-assertion-type"),
        ("client_assertion", "other-assertion"),
    ] {
        let err = require_err(
            parse_introspect_form(
                Ok(form_pairs_with_duplicate(&fields, field, duplicate_value)),
                TEST_ISSUER,
            ),
            "duplicate introspection form field must be rejected",
        )?;
        assert_eq!(err.status(), StatusCode::BAD_REQUEST, "{field}");
    }

    Ok(())
}

#[test]
fn parse_revoke_form_rejects_duplicate_singleton_fields() -> TestResult {
    let fields = [
        ("token", "opaque-token"),
        ("token_type_hint", "access_token"),
        ("client_id", "client"),
        ("client_secret", "secret"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", "assertion"),
    ];

    for (field, duplicate_value) in [
        ("token", "other-token"),
        ("token_type_hint", "refresh_token"),
        ("client_id", "other-client"),
        ("client_secret", "other-secret"),
        ("client_assertion_type", "other-assertion-type"),
        ("client_assertion", "other-assertion"),
    ] {
        let err = require_err(
            parse_revoke_form(
                Ok(form_pairs_with_duplicate(&fields, field, duplicate_value)),
                TEST_ISSUER,
            ),
            "duplicate revocation form field must be rejected",
        )?;
        assert_eq!(err.status(), StatusCode::BAD_REQUEST, "{field}");
    }

    Ok(())
}

#[test]
fn parse_par_form_rejects_duplicate_singleton_fields() -> TestResult {
    let fields = [
        ("client_id", "client"),
        ("response_type", "code"),
        ("redirect_uri", "https://client.example/callback"),
        ("authorization_details", r#"[{"type":"openid"}]"#),
        ("scope", "openid profile"),
        ("state", "state"),
        ("nonce", "nonce"),
        ("acr_values", "urn:pwd"),
        ("max_age", "60"),
        ("code_challenge", "challenge"),
        ("code_challenge_method", "S256"),
        ("client_secret", "secret"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", "assertion"),
        ("request", "request-object"),
    ];

    for (field, duplicate_value) in [
        ("client_id", "other-client"),
        ("response_type", "token"),
        ("redirect_uri", "https://client.example/other"),
        ("authorization_details", r#"[{"type":"payment"}]"#),
        ("scope", "openid email"),
        ("state", "other-state"),
        ("nonce", "other-nonce"),
        ("acr_values", "urn:mfa"),
        ("max_age", "120"),
        ("code_challenge", "other-challenge"),
        ("code_challenge_method", "plain"),
        ("client_secret", "other-secret"),
        ("client_assertion_type", "other-assertion-type"),
        ("client_assertion", "other-assertion"),
        ("request", "other-request-object"),
    ] {
        let err = require_err(
            parse_par_form(
                Ok(form_pairs_with_duplicate(&fields, field, duplicate_value)),
                TEST_ISSUER,
            ),
            "duplicate PAR singleton field must be rejected",
        )?;
        assert_eq!(err.status(), StatusCode::BAD_REQUEST, "{field}");
    }

    Ok(())
}

#[test]
fn parse_par_form_preserves_repeated_resource_values() -> TestResult {
    let form = parse_par_form(
        Ok(form_pairs(&[
            ("client_id", "client"),
            ("response_type", "code"),
            ("redirect_uri", "https://client.example/callback"),
            ("resource", "https://api.example/a"),
            ("resource", "https://api.example/b"),
        ])),
        TEST_ISSUER,
    )
    .map_err(|response| {
        format!(
            "resource repetition should be accepted: {}",
            response.status()
        )
    })?;

    assert_eq!(
        form.resource,
        vec![
            "https://api.example/a".to_string(),
            "https://api.example/b".to_string()
        ]
    );
    Ok(())
}

#[test]
fn parse_par_form_rejects_invalid_max_age() -> TestResult {
    let err = require_err(
        parse_par_form(
            Ok(form_pairs(&[
                ("client_id", "client"),
                ("response_type", "code"),
                ("redirect_uri", "https://client.example/callback"),
                ("max_age", "-1"),
            ])),
            TEST_ISSUER,
        ),
        "invalid max_age must be rejected",
    )?;

    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[test]
fn par_server_error_maps_to_internal_server_error_with_generic_description() {
    let (body, status) = par_error_response_body_and_status(&crate::par::ParError {
        error: "server_error".to_string(),
        error_description: Some("PAR request expiry overflow".to_string()),
    });

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"], "server_error");
    assert_eq!(
        body["error_description"],
        "PAR request processing failed internally"
    );
}

#[test]
fn parse_userinfo_form_rejects_duplicate_access_token() -> TestResult {
    let err = require_err(
        parse_userinfo_form(
            Ok(form_pairs(&[
                ("access_token", "token-a"),
                ("access_token", "token-b"),
            ])),
            TEST_ISSUER,
        ),
        "duplicate userinfo access_token must be rejected",
    )?;

    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[test]
fn backchannel_logout_dispatch_uri_rejects_ssrf_shapes() -> TestResult {
    for uri in [
        "http://example.com/logout",
        "https://127.0.0.1/logout",
        "https://[::1]/logout",
        "https://localhost/logout",
        "https://10.0.0.1/logout",
        "https://[fc00::1]/logout",
        "https://user@example.com/logout",
        "https://example.com/logout#fragment",
    ] {
        let err = require_err(
            validate_backchannel_logout_dispatch_uri(uri),
            "unsafe backchannel logout uri must be rejected",
        )?;
        assert!(
            err.contains("backchannel logout uri"),
            "unexpected error for {uri}: {err}"
        );
    }
    Ok(())
}

fn test_oidc_logout_config(signing_key: crate::oidc::OidcSigningKey) -> OidcConfig {
    OidcConfig {
        issuer: TEST_ISSUER.to_string(),
        id_token_ttl_secs: 3600,
        discovery_enabled: true,
        userinfo_enabled: true,
        logout_enabled: true,
        backchannel_logout_enabled: true,
        logout_session_ttl_secs: 600,
        backchannel_logout_timeout_secs: 2,
        require_nonce: false,
        signing_key,
        request_object_encryption_key: None,
    }
}

fn backchannel_test_client(
    client_id: &str,
    backchannel_logout_uri: Option<&str>,
    backchannel_logout_session_required: bool,
) -> crate::client_registry::RegisteredClient {
    crate::client_registry::RegisteredClient {
        client_id: client_id.to_string(),
        client_secret: None,
        redirect_uris: vec!["https://rp.example/callback".to_string()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: backchannel_logout_uri.map(str::to_string),
        backchannel_logout_session_required,
        token_endpoint_auth_method: "none".to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: vec!["openid".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        registration_access_token: None,
        client_id_issued_at: None,
    }
}

#[test]
fn backchannel_logout_dispatch_reports_skipped_clients() -> TestResult {
    let cfg = test_oidc_logout_config(upstream_signing_key()?);
    let clients = ClientRegistry::new_process_local_for_tests();
    clients.register(backchannel_test_client(
        "registered-without-uri",
        None,
        false,
    ));
    let event = OidcLogoutEvent {
        sid: "sid-123".to_string(),
        user_id: "user-123".to_string(),
        jti: "logout-jti".to_string(),
        client_ids: vec![
            "missing-client".to_string(),
            "registered-without-uri".to_string(),
        ],
    };

    let report = dispatch_backchannel_logout(&cfg, &clients, &event);

    assert_eq!(
        report,
        BackchannelLogoutDispatchReport {
            targeted_clients: 2,
            skipped_unregistered_clients: 1,
            skipped_without_logout_uri: 1,
            ..BackchannelLogoutDispatchReport::default()
        }
    );
    assert!(report.has_failures());
    Ok(())
}

#[test]
fn backchannel_logout_dispatch_reports_token_build_failure() -> TestResult {
    let cfg = test_oidc_logout_config(upstream_signing_key()?);
    let clients = ClientRegistry::new_process_local_for_tests();
    clients.register(backchannel_test_client(
        "backchannel-client",
        Some("https://93.184.216.34/logout"),
        false,
    ));
    let event = OidcLogoutEvent {
        sid: String::new(),
        user_id: "user-123".to_string(),
        jti: "logout-jti".to_string(),
        client_ids: vec!["backchannel-client".to_string()],
    };

    let report = dispatch_backchannel_logout(&cfg, &clients, &event);

    assert_eq!(
        report,
        BackchannelLogoutDispatchReport {
            targeted_clients: 1,
            token_build_failures: 1,
            ..BackchannelLogoutDispatchReport::default()
        }
    );
    assert!(report.has_failures());
    Ok(())
}
