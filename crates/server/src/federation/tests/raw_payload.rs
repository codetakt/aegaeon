// ── Parse Unverified ─────────────────────────────────────────────

#[test]
fn parse_entity_statement_unverified_valid() {
    let _guard = raw_json_env_guard();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::FederationEntityStatement,
        ),
        Some("verified-structural-v1"),
    );
    let now = 1_700_000_000_i64;
    let header = json!({"alg": "ES256"});
    let payload = json!({
        "iss": "https://rp.example.com",
        "sub": "https://rp.example.com",
        "iat": now,
        "exp": now + 3600,
        "jwks": sample_jwks_value()
    });

    let jws = make_test_jws(&header, &payload);
    match parse_entity_statement_unverified(&jws) {
        Ok(stmt) => {
            assert_eq!(stmt.iss, "https://rp.example.com");
            assert!(stmt.is_self_signed());
        }
        // Low* header parser unavailable in test builds (same as jose crate tests)
        Err(FederationError::Jws(JwsError::JsonLowStar(_))) => {}
        Err(err) => assert!(
            matches!(&err, FederationError::Jws(JwsError::JsonLowStar(_))),
            "unexpected error: {err}"
        ),
    }
}

#[test]
fn parse_entity_statement_unverified_invalid_jws() {
    let err = must_err(parse_entity_statement_unverified("not.a.valid.jws.token"));
    assert!(matches!(err, FederationError::Jws(JwsError::InvalidFormat)));
}

#[test]
fn parse_entity_statement_payload_rejects_duplicate_claim_keys() {
    let _guard = raw_json_env_guard();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::FederationEntityStatement,
        ),
        Some("verified-structural-v1"),
    );
    let err = must_err(parse_entity_statement_payload(
        br#"{
                "iss":"https://rp.example.com",
                "sub":"https://rp.example.com",
                "sub":"https://evil.example.com",
                "iat":1700000000,
                "exp":1700003600
            }"#,
    ));

    assert!(matches!(
        err,
        FederationError::Validation(ref msg) if msg == "duplicate-key"
    ));
}

#[test]
fn parse_entity_statement_payload_rejects_nested_duplicate_metadata_policy_keys() {
    let _guard = raw_json_env_guard();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::FederationEntityStatement,
        ),
        Some("verified-structural-v1"),
    );
    let err = must_err(parse_entity_statement_payload(
        br#"{
                "iss":"https://ta.example.com",
                "sub":"https://rp.example.com",
                "iat":1700000000,
                "exp":1700003600,
                "metadata_policy":{
                    "openid_provider":{
                        "jwks_uri":{
                            "value":"https://issuer.example/jwks-a",
                            "value":"https://issuer.example/jwks-b"
                        }
                    }
                }
            }"#,
    ));

    assert!(matches!(
        err,
        FederationError::Validation(ref msg) if msg == "duplicate-key"
    ));
}

#[test]
fn parse_entity_statement_payload_rejects_trailing_bytes_as_json_error() {
    let _guard = raw_json_env_guard();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::FederationEntityStatement,
        ),
        Some("verified-structural-v1"),
    );
    let err = must_err(parse_entity_statement_payload(
        br#"{
                "iss":"https://rp.example.com",
                "sub":"https://rp.example.com",
                "iat":1700000000,
                "exp":1700003600
            } trailing"#,
    ));

    assert!(matches!(err, FederationError::Json(_)));
}

#[test]
fn parse_entity_statement_payload_accepts_verified_structural_override() {
    let _guard = raw_json_env_guard();
    let _global_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var(),
        Some("future"),
    );
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::FederationEntityStatement,
        ),
        Some("verified-structural-v1"),
    );

    let payload = must_ok(serde_json::to_vec(&json!({
        "iss": "https://rp.example.com",
        "sub": "https://rp.example.com",
        "iat": 1_700_000_000_i64,
        "exp": 1_700_003_600_i64,
        "jwks": sample_jwks_value(),
        "metadata": {
            "openid_relying_party": {
                "redirect_uris": ["https://rp.example.com/callback"]
            }
        },
        "metadata_policy": {
            "openid_relying_party": {
                "contacts": {
                    "subset_of": ["ops@example.com"]
                }
            }
        },
        "constraints": {
            "max_path_length": 2,
            "allowed_leaf_entity_types": ["openid_relying_party"]
        },
        "trust_marks": [{
            "id": "https://trust.example/profile",
            "trust_mark": "header.payload.signature"
        }],
        "authority_hints": ["https://ta.example.com"],
        "source_endpoint": "https://ta.example.com/fetch"
    })));

    let stmt = must_ok(parse_entity_statement_payload(&payload));
    assert_eq!(stmt.iss, "https://rp.example.com");
    assert_eq!(stmt.sub, "https://rp.example.com");
    assert_eq!(stmt.jwks, Some(sample_jwks_value()));
    assert!(stmt
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.contains_key("openid_relying_party")));
    assert!(stmt
        .metadata_policy
        .as_ref()
        .is_some_and(|policy| policy.contains_key("openid_relying_party")));
    assert_eq!(
        stmt.constraints
            .as_ref()
            .and_then(|constraints| constraints.max_path_length),
        Some(2)
    );
    assert_eq!(
        stmt.constraints
            .as_ref()
            .and_then(|constraints| constraints.allowed_leaf_entity_types.clone()),
        Some(vec!["openid_relying_party".to_string()])
    );
    assert_eq!(
        stmt.authority_hints,
        Some(vec!["https://ta.example.com".to_string()])
    );
    assert_eq!(
        stmt.source_endpoint.as_deref(),
        Some("https://ta.example.com/fetch")
    );
    assert_eq!(stmt.trust_marks.as_ref().map(Vec::len), Some(1));
    assert_eq!(
        stmt.trust_marks
            .as_ref()
            .and_then(|trust_marks| trust_marks.first())
            .map(|trust_mark| trust_mark.id.as_str()),
        Some("https://trust.example/profile")
    );
}

#[test]
fn parse_entity_statement_payload_preserves_json_error_for_invalid_typed_claim_under_verified_structural_override(
) {
    let _guard = raw_json_env_guard();
    let _global_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var(),
        Some("future"),
    );
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::FederationEntityStatement,
        ),
        Some("verified-structural-v1"),
    );

    let payload = must_ok(serde_json::to_vec(&json!({
        "iss": "https://rp.example.com",
        "sub": "https://rp.example.com",
        "iat": "1700000000",
        "exp": 1_700_003_600_i64
    })));

    let err = must_err(parse_entity_statement_payload(&payload));
    assert!(matches!(err, FederationError::Json(_)));
}

#[cfg(feature = "verified-claim")]
#[test]
fn parse_entity_statement_payload_uses_structural_parser_or_fails_closed_when_unavailable() {
    let _guard = raw_json_env_guard();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::FederationEntityStatement,
        ),
        Some("verified-structural-v1"),
    );

    let payload = must_ok(serde_json::to_vec(&json!({
        "iss": "https://rp.example.com",
        "sub": "https://rp.example.com",
        "iat": 1_700_000_000_i64,
        "exp": 1_700_003_600_i64
    })));

    let result = parse_entity_statement_payload(&payload);
    if ffi_raw_json_structural::is_raw_json_structural_parser_available() {
        let stmt = must_ok(result);
        assert_eq!(stmt.iss, "https://rp.example.com");
        assert_eq!(stmt.sub, "https://rp.example.com");
    } else {
        let err = must_err(result);
        assert!(matches!(
            err,
            FederationError::Validation(ref msg) if msg == "raw-json-structural-unavailable"
        ));
    }
}

#[test]
fn parse_trust_mark_claims_payload_rejects_duplicate_claim_keys() {
    let _guard = raw_json_env_guard();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::FederationTrustMark,
        ),
        Some("verified-structural-v1"),
    );
    let err = must_err(parse_trust_mark_claims_payload(
        br#"{
                "iss":"https://trust-mark-issuer.example",
                "sub":"https://rp.example.com",
                "id":"https://trust.example/profile",
                "id":"https://trust.example/evil-profile",
                "iat":1700000000
            }"#,
    ));

    assert!(matches!(
        err,
        FederationError::TrustMark(ref msg) if msg == "duplicate-key"
    ));
}

#[test]
fn parse_trust_mark_claims_payload_rejects_non_object_shape_as_json_error() {
    let _guard = raw_json_env_guard();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::FederationTrustMark,
        ),
        Some("verified-structural-v1"),
    );
    let err = must_err(parse_trust_mark_claims_payload(br#"[]"#));

    assert!(matches!(err, FederationError::Json(_)));
}

#[test]
fn parse_trust_mark_claims_payload_accepts_verified_structural_override() {
    let _guard = raw_json_env_guard();
    let _global_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var(),
        Some("future"),
    );
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::FederationTrustMark,
        ),
        Some("verified-structural-v1"),
    );

    let payload = must_ok(serde_json::to_vec(&json!({
        "iss": "https://trust-mark-issuer.example",
        "sub": "https://rp.example.com",
        "trust_mark_type": "https://trust.example/profile",
        "iat": 1_700_000_000_i64,
        "exp": 1_700_003_600_i64,
        "ref": "https://trust-mark-issuer.example/.well-known/openid-federation"
    })));

    let claims = must_ok(parse_trust_mark_claims_payload(&payload));
    assert_eq!(claims.iss, "https://trust-mark-issuer.example");
    assert_eq!(claims.sub, "https://rp.example.com");
    assert_eq!(claims.id, "https://trust.example/profile");
    assert_eq!(claims.exp, Some(1_700_003_600_i64));
    assert_eq!(
        claims.ref_.as_deref(),
        Some("https://trust-mark-issuer.example/.well-known/openid-federation")
    );
}

#[test]
fn parse_trust_mark_claims_payload_rejects_alias_collisions() {
    let _guard = raw_json_env_guard();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::FederationTrustMark,
        ),
        Some("verified-structural-v1"),
    );
    let err = must_err(parse_trust_mark_claims_payload(
        br#"{
                "iss":"https://trust-mark-issuer.example",
                "sub":"https://rp.example.com",
                "trust_mark_type":"https://trust.example/profile",
                "id":"https://trust.example/legacy-profile",
                "iat":1700000000
            }"#,
    ));

    assert!(matches!(
        err,
        FederationError::TrustMark(ref msg) if msg == "duplicate-key"
    ));
}

#[cfg(feature = "verified-claim")]
#[test]
fn parse_trust_mark_claims_payload_uses_structural_parser_or_fails_closed_when_unavailable() {
    let _guard = raw_json_env_guard();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::FederationTrustMark,
        ),
        Some("verified-structural-v1"),
    );

    let payload = must_ok(serde_json::to_vec(&json!({
        "iss": "https://trust-mark-issuer.example",
        "sub": "https://rp.example.com",
        "id": "https://trust.example/profile",
        "iat": 1_700_000_000_i64
    })));

    let result = parse_trust_mark_claims_payload(&payload);
    if ffi_raw_json_structural::is_raw_json_structural_parser_available() {
        let claims = must_ok(result);
        assert_eq!(claims.iss, "https://trust-mark-issuer.example");
        assert_eq!(claims.sub, "https://rp.example.com");
        assert_eq!(claims.id, "https://trust.example/profile");
    } else {
        let err = must_err(result);
        assert!(matches!(
            err,
            FederationError::TrustMark(ref msg) if msg == "raw-json-structural-unavailable"
        ));
    }
}

#[test]
fn parse_entity_statement_payload_rejects_unknown_surface_backend_override() {
    let _guard = raw_json_env_guard();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::FederationEntityStatement,
        ),
        Some("future"),
    );

    let result = parse_entity_statement_payload(
        br#"{
                "iss":"https://rp.example.com",
                "sub":"https://rp.example.com",
                "iat":1700000000,
                "exp":1700003600
            }"#,
    );

    let err = must_err(result);
    assert!(matches!(
        err,
        FederationError::Internal(ref msg)
            if msg.contains("federation-entity-statement")
    ));
}

#[test]
fn parse_trust_mark_claims_payload_rejects_unknown_surface_backend_override() {
    let _guard = raw_json_env_guard();
    let _surface_override = override_env_var(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
            RawJsonSurface::FederationTrustMark,
        ),
        Some("future"),
    );

    let result = parse_trust_mark_claims_payload(
        br#"{
                "iss":"https://trust-mark-issuer.example",
                "sub":"https://rp.example.com",
                "id":"https://trust.example/profile",
                "iat":1700000000
            }"#,
    );

    let err = must_err(result);
    assert!(matches!(
        err,
        FederationError::Internal(ref msg) if msg.contains("federation-trust-mark")
    ));
}
