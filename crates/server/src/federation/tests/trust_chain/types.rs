// ── Constraints ──────────────────────────────────────────────────

#[test]
fn constraints_deserialization() {
    let json = json!({
        "max_path_length": 2,
        "allowed_leaf_entity_types": ["openid_relying_party"]
    });
    let constraints: Constraints = must_ok(serde_json::from_value(json));
    assert_eq!(constraints.max_path_length, Some(2));
    assert_eq!(
        constraints.allowed_leaf_entity_types,
        Some(vec!["openid_relying_party".to_string()])
    );
}

#[test]
fn trust_mark_deserialization() {
    let json = json!({
        "id": "https://trust-mark.example.com/mark1",
        "trust_mark": "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoxfQ.test"
    });
    let tm: TrustMark = must_ok(serde_json::from_value(json));
    assert_eq!(tm.id, "https://trust-mark.example.com/mark1");
}

// ── Parse JWKS from Entity Statement ─────────────────────────────

#[test]
fn entity_statement_parse_jwks() {
    let now = 1_700_000_000_i64;
    let stmt = sample_entity_config("https://rp.example.com", now);
    let jwks = must_ok(stmt.parse_jwks());
    assert_eq!(jwks.keys().len(), 1);
    assert_eq!(jwks.keys()[0].kid(), Some("test-key-1"));
}

#[test]
fn entity_statement_parse_jwks_missing() {
    let now = 1_700_000_000_i64;
    let mut stmt = sample_entity_config("https://rp.example.com", now);
    stmt.jwks = None;
    let err = must_err(stmt.parse_jwks());
    assert!(matches!(err, FederationError::MissingField("jwks")));
}
