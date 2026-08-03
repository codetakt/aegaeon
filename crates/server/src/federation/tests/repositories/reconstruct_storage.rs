// ── reconstruct_chain_from_cache ────────────────────────────────

#[test]
fn reconstruct_chain_valid() {
    let _guard = raw_json_env_guard();
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";
    let signed_chain = signed_direct_chain(ta_id, leaf_id, now);

    let anchor = TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: must_ok(JwkSet::from_value(signed_chain.anchor_jwks.clone())),
        metadata_policy: None,
    };

    let cached = StoredTrustChain {
        id: Uuid::new_v4(),
        environment_id: Uuid::new_v4(),
        leaf_entity_id: leaf_id.to_string(),
        anchor_entity_id: ta_id.to_string(),
        chain_jwts: signed_chain_jwts(&signed_chain),
        resolved_at: now,
        expires_at: now + 3600,
    };

    let chain = must_ok(reconstruct_chain_from_cache(&cached, &anchor));
    assert_eq!(chain.chain.len(), 3);
    assert_eq!(must_ok(chain.leaf()).iss, leaf_id);
}

#[test]
fn reconstruct_chain_from_cache_rejects_malformed_statement_shape() {
    let _guard = raw_json_env_guard();
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";
    let malformed_jws = make_test_jws(&json!({"alg": "ES256"}), &json!({
        "iss": leaf_id,
        "sub": leaf_id,
        "iat": "not-an-integer",
        "exp": now + 3600
    }));
    let cached = StoredTrustChain {
        id: Uuid::new_v4(),
        environment_id: Uuid::new_v4(),
        leaf_entity_id: leaf_id.to_string(),
        anchor_entity_id: ta_id.to_string(),
        chain_jwts: json!([
            malformed_jws.clone(),
            malformed_jws.clone(),
            malformed_jws
        ]),
        resolved_at: now,
        expires_at: now + 3600,
    };
    let anchor = TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: None,
    };

    let err = must_err(reconstruct_chain_from_cache(&cached, &anchor));

    assert!(matches!(err, FederationError::Json(_)));
}

#[test]
fn reconstruct_chain_empty_array() {
    let cached = StoredTrustChain {
        id: Uuid::new_v4(),
        environment_id: Uuid::new_v4(),
        leaf_entity_id: "leaf".to_string(),
        anchor_entity_id: "anchor".to_string(),
        chain_jwts: json!([]),
        resolved_at: 0,
        expires_at: 0,
    };

    let anchor = TrustAnchor {
        entity_id: "anchor".to_string(),
        jwks: sample_jwks(),
        metadata_policy: None,
    };

    let err = must_err(reconstruct_chain_from_cache(&cached, &anchor));
    assert!(matches!(err, FederationError::Validation(_)));
}

#[test]
fn reconstruct_chain_not_array() {
    let cached = StoredTrustChain {
        id: Uuid::new_v4(),
        environment_id: Uuid::new_v4(),
        leaf_entity_id: "leaf".to_string(),
        anchor_entity_id: "anchor".to_string(),
        chain_jwts: json!({"not": "an array"}),
        resolved_at: 0,
        expires_at: 0,
    };

    let anchor = TrustAnchor {
        entity_id: "anchor".to_string(),
        jwks: sample_jwks(),
        metadata_policy: None,
    };

    let err = must_err(reconstruct_chain_from_cache(&cached, &anchor));
    assert!(matches!(err, FederationError::Validation(_)));
}

// ── FederationError::Storage ─────────────────────────────────────

#[test]
fn storage_error_variant_display() {
    let err = FederationError::Storage("connection refused".into());
    assert!(err.to_string().contains("connection refused"));
    assert!(matches!(err, FederationError::Storage(_)));
}

#[test]
fn storage_err_helper_converts_sqlx_error() {
    // RowNotFound is a simple sqlx::Error variant we can construct.
    let sqlx_err = sqlx::Error::RowNotFound;
    let fed_err = storage_err(&sqlx_err);
    assert!(matches!(fed_err, FederationError::Storage(_)));
    // Sanitized: must NOT expose raw sqlx error details.
    assert!(fed_err.to_string().contains("database operation failed"));
}
