
// ---------------------------------------------------------------
// P1: default_policy_document sanity checks
// ---------------------------------------------------------------

#[test]
fn default_policy_document_has_sane_defaults() {
    let policy = default_policy_document();
    assert!(policy.pkce_required);
    assert!(!policy.dcr_enabled);
    assert!(policy.dpop_strict);
    assert!(policy.require_state_parameter);
    assert!(policy.require_client_auth_token);
    assert_eq!(policy.dpop_iat_window_seconds, 300);
    assert_eq!(policy.par_expires_in_seconds, 90);
    assert_eq!(
        policy.jose_header_max_len,
        aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN as u32
    );
    assert_eq!(policy.access_token_time_to_live_seconds, 3600);
    assert_eq!(policy.id_token_time_to_live_seconds, 3600);
    assert_eq!(policy.refresh_token_time_to_live_seconds, 2_592_000);
    assert_eq!(policy.authorization_code_time_to_live_seconds, 300);
    assert_eq!(policy.auth_session_ttl_seconds, 28_800);
    assert_eq!(policy.auth_max_sessions, 10_000);
    assert_eq!(policy.jwks_local_cache_max_entries, 4096);
    assert_eq!(policy.upstream_discovery_cache_ttl_seconds, 300);
    assert_eq!(policy.upstream_discovery_cache_max_entries, 4096);
    assert_eq!(policy.upstream_jwks_cache_ttl_seconds, 300);
    assert_eq!(policy.upstream_jwks_cache_max_entries, 4096);
    assert!(!policy.oidc_enabled);
    assert!(policy.oidc_enable_discovery);
    assert!(!policy.mtls_enabled);
    assert!(policy.federation_outbound_allowed_domains.is_empty());
    assert!(policy.upstream_outbound_allowed_domains.is_empty());
    assert_eq!(policy.federation_entity_cache_ttl_seconds, 1_800);
    assert_eq!(policy.federation_trust_chain_cache_ttl_seconds, 3_600);
    assert_eq!(policy.federation_cache_max_entries, 1_000);
    assert!(policy.ssa_jwt_pem.is_none());
    assert!(policy.mtls_base_url.is_none());
}

#[test]
fn default_policy_grants_include_auth_code_and_refresh() {
    let policy = default_policy_document();
    assert!(policy
        .allowed_grant_types
        .contains(&"authorization_code".to_string()));
    assert!(policy
        .allowed_grant_types
        .contains(&"refresh_token".to_string()));
    assert!(policy
        .allowed_grant_types
        .contains(&"client_credentials".to_string()));
}

#[test]
fn parse_configuration_policy_document_rejects_malformed_policy() -> TestResult {
    let document = serde_json::json!({
        "policy": {
            "pkceRequired": true,
            "unexpectedPolicyFlag": true,
        },
    });

    let response = must_err!(
        parse_configuration_policy_document(&document, "req-1"),
        "unknown policy fields must fail closed"
    );

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[test]
fn parse_configuration_policy_document_distinguishes_missing_policy() -> TestResult {
    let document = serde_json::json!({});

    let response = must_err!(
        parse_configuration_policy_document(&document, "req-1"),
        "missing policy must fail closed"
    );

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[test]
fn load_policy_from_configuration_snapshot_rejects_corrupt_policy_as_internal() -> TestResult {
    let document = serde_json::json!({
        "policy": {
            "pkceRequired": true,
            "unexpectedPolicyFlag": true,
        },
    });

    let response = must_err!(
        load_policy_from_configuration_snapshot(&document, "req-1"),
        "corrupt stored policy must fail closed"
    );

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}

#[test]
fn parse_configuration_scope_allowlist_accepts_trimmed_unique_strings() -> TestResult {
    let document = serde_json::json!({
        "scopeAllowlist": ["openid", " profile ", "email"]
    });

    let scopes = must_ok!(
        parse_configuration_scope_allowlist(&document, "req-1"),
        "valid scope allowlist"
    );

    assert_eq!(scopes, vec!["openid", "profile", "email"]);
    Ok(())
}

#[test]
fn parse_configuration_scope_allowlist_rejects_malformed_entries() {
    let non_string = serde_json::json!({
        "scopeAllowlist": ["openid", 42]
    });
    assert!(parse_configuration_scope_allowlist(&non_string, "req-1").is_err());

    let blank = serde_json::json!({
        "scopeAllowlist": ["openid", "  "]
    });
    assert!(parse_configuration_scope_allowlist(&blank, "req-1").is_err());

    let duplicate = serde_json::json!({
        "scopeAllowlist": ["openid", " openid "]
    });
    assert!(parse_configuration_scope_allowlist(&duplicate, "req-1").is_err());

    let invalid_token = serde_json::json!({
        "scopeAllowlist": ["openid profile"]
    });
    assert!(parse_configuration_scope_allowlist(&invalid_token, "req-1").is_err());
}

fn activation_configuration_with_key_store(key_store: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 1,
        "issuerHost": "issuer.example.com",
        "issuerUrl": "https://issuer.example.com",
        "policy": default_policy_document(),
        "scopeAllowlist": ["openid", "profile"],
        "keyStore": key_store,
    })
}

fn minimal_activation_configuration() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 1,
        "issuerHost": "issuer.example.com",
        "issuerUrl": "https://issuer.example.com",
        "policy": default_policy_document(),
        "keyStore": {
            "type": "databaseEncrypted",
            "configuration": {},
        },
    })
}

#[test]
fn prepare_configuration_document_hashes_canonical_strict_shape() -> TestResult {
    let implicit_defaults = minimal_activation_configuration();
    let mut explicit_defaults = minimal_activation_configuration();
    explicit_defaults["scopeAllowlist"] = serde_json::json!([]);
    explicit_defaults["keyStore"]["redacted"] = serde_json::json!(true);

    let prepared_implicit = must_ok!(
        prepare_configuration_document(&implicit_defaults, "req-1"),
        "implicit defaults should prepare"
    );
    let prepared_explicit = must_ok!(
        prepare_configuration_document(&explicit_defaults, "req-1"),
        "explicit defaults should prepare"
    );

    assert_eq!(prepared_implicit.hash, prepared_explicit.hash);
    assert_eq!(prepared_implicit.document, prepared_explicit.document);
    assert!(!prepared_implicit.document.contains("scopeAllowlist"));
    assert!(prepared_implicit.document.contains("\"redacted\":true"));

    let stored_document: serde_json::Value = serde_json::from_str(&prepared_implicit.document)?;
    must_ok!(
        parse_activated_environment_configuration(
            stored_document,
            "issuer.example.com",
            "https://issuer.example.com",
            "req-1",
        ),
        "canonical stored document should activate"
    );
    Ok(())
}

#[test]
fn prepare_configuration_document_rejects_unknown_fields() {
    let mut document = minimal_activation_configuration();
    document["legacyDatabaseMode"] = serde_json::json!("optional");

    assert!(prepare_configuration_document(&document, "req-1").is_err());
}

#[test]
fn prepare_configuration_document_rejects_federation_op_policy_input() {
    let mut document = minimal_activation_configuration();
    document["policy"]["federationOpEnabled"] = serde_json::json!(false);

    assert!(prepare_configuration_document(&document, "req-1").is_err());
}

#[test]
fn parse_activated_environment_configuration_accepts_valid_key_store() -> TestResult {
    let document = activation_configuration_with_key_store(serde_json::json!({
        "type": "databaseEncrypted",
        "configuration": {},
        "redacted": true,
    }));

    let parsed = must_ok!(
        parse_activated_environment_configuration(
            document,
            "issuer.example.com",
            "https://issuer.example.com",
            "req-1",
        ),
        "valid activated environment configuration"
    );

    assert_eq!(parsed.state.key_store_type, "databaseEncrypted");
    assert_eq!(parsed.state.key_store_configuration, serde_json::json!({}));
    assert!(parsed.state.key_store_redacted);
    Ok(())
}

#[test]
fn parse_activated_environment_configuration_rejects_unknown_top_level_field() {
    let mut document = activation_configuration_with_key_store(serde_json::json!({
        "type": "databaseEncrypted",
        "configuration": {},
        "redacted": true,
    }));
    document["unexpected"] = serde_json::json!(true);

    assert!(parse_activated_environment_configuration(
        document,
        "issuer.example.com",
        "https://issuer.example.com",
        "req-1",
    )
    .is_err());
}

#[test]
fn parse_activated_environment_configuration_rejects_unknown_key_store_field() {
    let document = activation_configuration_with_key_store(serde_json::json!({
        "type": "databaseEncrypted",
        "configuration": {},
        "redacted": true,
        "typo": true,
    }));

    assert!(parse_activated_environment_configuration(
        document,
        "issuer.example.com",
        "https://issuer.example.com",
        "req-1",
    )
    .is_err());
}

#[test]
fn parse_activated_environment_configuration_rejects_unsupported_key_store_type() {
    let document = activation_configuration_with_key_store(serde_json::json!({
        "type": "rawFilesystem",
        "configuration": {},
        "redacted": true,
    }));

    assert!(parse_activated_environment_configuration(
        document,
        "issuer.example.com",
        "https://issuer.example.com",
        "req-1",
    )
    .is_err());
}

#[test]
fn parse_activated_environment_configuration_rejects_malformed_key_store_configuration() {
    for configuration in [
        serde_json::Value::Null,
        serde_json::json!("not-an-object"),
        serde_json::json!(["not", "an", "object"]),
    ] {
        let document = activation_configuration_with_key_store(serde_json::json!({
            "type": "databaseEncrypted",
            "configuration": configuration,
            "redacted": true,
        }));

        assert!(parse_activated_environment_configuration(
            document,
            "issuer.example.com",
            "https://issuer.example.com",
            "req-1",
        )
        .is_err());
    }
}

#[test]
fn parse_activated_environment_configuration_rejects_non_empty_database_encrypted_key_store_configuration() {
    let document = activation_configuration_with_key_store(serde_json::json!({
        "type": "databaseEncrypted",
        "configuration": {
            "rotationPolicy": "manual"
        },
        "redacted": true,
    }));

    assert!(parse_activated_environment_configuration(
        document,
        "issuer.example.com",
        "https://issuer.example.com",
        "req-1",
    )
    .is_err());
}

#[test]
fn parse_activated_environment_configuration_rejects_secret_key_store_configuration() {
    let document = activation_configuration_with_key_store(serde_json::json!({
        "type": "databaseEncrypted",
        "configuration": {
            "nested": {
                "privateKeyPem": "-----BEGIN PRIVATE KEY-----"
            }
        },
        "redacted": true,
    }));

    assert!(parse_activated_environment_configuration(
        document,
        "issuer.example.com",
        "https://issuer.example.com",
        "req-1",
    )
    .is_err());
}

#[test]
fn parse_activated_environment_configuration_requires_key_store_configuration() {
    let document = activation_configuration_with_key_store(serde_json::json!({
        "type": "databaseEncrypted",
        "redacted": true,
    }));

    assert!(parse_activated_environment_configuration(
        document,
        "issuer.example.com",
        "https://issuer.example.com",
        "req-1",
    )
    .is_err());
}
