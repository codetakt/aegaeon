#[test]
fn validate_connection_input_accepts_valid() {
    let mut input = valid_connection_input();
    assert!(validate_connection_input(&mut input, "req-1").is_ok());
}

#[test]
fn validate_connection_input_rejects_empty_identifier() {
    let mut input = valid_connection_input();
    input.connection_identifier = "  ".to_string();
    assert!(validate_connection_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_connection_input_rejects_empty_name() {
    let mut input = valid_connection_input();
    input.name = String::new();
    assert!(validate_connection_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_connection_input_rejects_non_oidc_type() {
    let mut input = valid_connection_input();
    input.connection_type = "SAML".to_string();
    assert!(validate_connection_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_connection_input_accepts_lowercase_oidc() {
    let mut input = valid_connection_input();
    input.connection_type = " oidc ".to_string();
    assert!(validate_connection_input(&mut input, "req-1").is_ok());
    assert_eq!(input.connection_type, "OIDC");
}

#[test]
fn validate_connection_input_rejects_empty_issuer_url() {
    let mut input = valid_connection_input();
    input.issuer_url = String::new();
    assert!(validate_connection_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_connection_input_rejects_http_issuer_url() {
    let mut input = valid_connection_input();
    input.issuer_url = "http://insecure.example.com".to_string();
    assert!(validate_connection_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_connection_input_rejects_issuer_url_with_query() {
    let mut input = valid_connection_input();
    input.issuer_url = "https://idp.example.com?param=val".to_string();
    assert!(validate_connection_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_connection_input_rejects_issuer_url_with_fragment() {
    let mut input = valid_connection_input();
    input.issuer_url = "https://idp.example.com#frag".to_string();
    assert!(validate_connection_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_connection_input_rejects_issuer_url_with_userinfo() {
    let mut input = valid_connection_input();
    input.issuer_url = "https://user:pass@idp.example.com".to_string();
    assert!(validate_connection_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_connection_input_rejects_loopback_issuer_url() {
    for issuer_url in [
        "https://localhost",
        "https://127.0.0.1",
        "https://[::1]",
        "https://[fc00::1]",
    ] {
        let mut input = valid_connection_input();
        input.issuer_url = issuer_url.to_string();
        assert!(
            validate_connection_input(&mut input, "req-1").is_err(),
            "{issuer_url} should be rejected"
        );
    }
}

#[test]
fn validate_connection_input_rejects_empty_client_id() {
    let mut input = valid_connection_input();
    input.client_id = "   ".to_string();
    assert!(validate_connection_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_connection_input_rejects_invalid_auth_method() {
    let mut input = valid_connection_input();
    input.client_auth_method = "bearer".to_string();
    assert!(validate_connection_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_connection_input_accepts_all_valid_auth_methods() {
    for method in &["client_secret_basic", "client_secret_post", "none"] {
        let mut input = valid_connection_input();
        input.client_auth_method = method.to_string();
        assert!(
            validate_connection_input(&mut input, "req-1").is_ok(),
            "should accept auth method: {method}"
        );
    }
}

#[test]
fn validate_connection_input_rejects_private_key_jwt_until_upstream_support_exists() {
    let mut input = valid_connection_input();
    input.client_auth_method = "private_key_jwt".to_string();
    assert!(validate_connection_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_connection_input_normalizes_auth_method_case() {
    let mut input = valid_connection_input();
    input.client_auth_method = " CLIENT_SECRET_BASIC ".to_string();
    assert!(validate_connection_input(&mut input, "req-1").is_ok());
    assert_eq!(input.client_auth_method, "client_secret_basic");
}

#[test]
fn connection_client_secret_required_for_secret_auth_methods() -> TestResult {
    let input = valid_connection_input();

    assert!(resolve_connection_client_secret_action(
        &input,
        ConnectionClientSecretAction::Clear,
        false,
        "req-1",
    )
    .is_err());
    assert_eq!(
        must_ok!(
            resolve_connection_client_secret_action(
                &input,
                ConnectionClientSecretAction::Preserve,
                true,
                "req-1",
            ),
            "existing secret may be preserved"
        ),
        ConnectionClientSecretAction::Preserve
    );
    assert_eq!(
        must_ok!(
            resolve_connection_client_secret_action(
                &input,
                ConnectionClientSecretAction::Set("secret".to_string()),
                false,
                "req-1",
            ),
            "new secret may be set"
        ),
        ConnectionClientSecretAction::Set("secret".to_string())
    );
    Ok(())
}

#[test]
fn preserved_connection_client_secret_is_revalidated_for_secret_auth_methods() {
    assert!(
        validate_preserved_connection_client_secret("client_secret_basic", true, "req-1").is_ok()
    );
    assert!(
        validate_preserved_connection_client_secret("client_secret_basic", false, "req-1").is_err()
    );
    assert!(validate_preserved_connection_client_secret("none", false, "req-1").is_ok());
}

#[test]
fn connection_client_secret_rejected_and_cleared_for_non_secret_auth_methods() -> TestResult {
    for method in ["none", "private_key_jwt"] {
        let mut input = valid_connection_input();
        input.client_auth_method = method.to_string();

        assert!(resolve_connection_client_secret_action(
            &input,
            ConnectionClientSecretAction::Set("secret".to_string()),
            false,
            "req-1",
        )
        .is_err());
        assert_eq!(
            must_ok!(
                resolve_connection_client_secret_action(
                    &input,
                    ConnectionClientSecretAction::Preserve,
                    true,
                    "req-1",
                ),
                "non-secret auth methods clear stored secrets"
            ),
            ConnectionClientSecretAction::Clear
        );
    }
    Ok(())
}

#[test]
fn connection_client_secret_actions_preserve_patch_semantics() {
    let create = CreateConnectionRequest {
        base_configuration_version_id: Uuid::nil().to_string(),
        connection_identifier: "conn".to_string(),
        name: "Connection".to_string(),
        connection_type: None,
        issuer_url: "https://idp.example.com".to_string(),
        client_id: "client".to_string(),
        client_auth_method: Some("client_secret_post".to_string()),
        client_secret: Some("  new-secret  ".to_string()),
        status: None,
        oauth_profile_id: None,
    };
    assert_eq!(
        connection_client_secret_action_from_create(&create),
        ConnectionClientSecretAction::Set("new-secret".to_string())
    );

    let omitted = UpdateConnectionRequest {
        base_configuration_version_id: Uuid::nil().to_string(),
        connection_identifier: None,
        name: None,
        connection_type: None,
        issuer_url: None,
        client_id: None,
        client_auth_method: None,
        client_secret: None,
        status: None,
        oauth_profile_id: None,
    };
    assert_eq!(
        connection_client_secret_action_from_update(&omitted),
        ConnectionClientSecretAction::Preserve
    );

    let cleared = UpdateConnectionRequest {
        client_secret: Some(None),
        ..omitted
    };
    assert_eq!(
        connection_client_secret_action_from_update(&cleared),
        ConnectionClientSecretAction::Clear
    );
}

#[test]
fn validate_connection_input_rejects_invalid_status() {
    let mut input = valid_connection_input();
    input.status = "DELETED".to_string();
    assert!(validate_connection_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_connection_input_accepts_disabled_status() {
    let mut input = valid_connection_input();
    input.status = "disabled".to_string();
    assert!(validate_connection_input(&mut input, "req-1").is_ok());
    assert_eq!(input.status, "DISABLED");
}

#[test]
fn validate_connection_input_normalizes_oauth_profile_id() {
    let mut input = valid_connection_input();
    input.oauth_profile_id = Some("  ".to_string());
    assert!(validate_connection_input(&mut input, "req-1").is_ok());
    assert_eq!(input.oauth_profile_id, None);
}
