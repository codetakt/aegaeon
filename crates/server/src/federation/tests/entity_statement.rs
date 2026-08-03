// ── Entity Statement Serde ───────────────────────────────────────

#[test]
fn entity_statement_deserialization() {
    let now = 1_700_000_000_i64;
    let json = json!({
        "iss": "https://rp.example.com",
        "sub": "https://rp.example.com",
        "iat": now,
        "exp": now + 3600,
        "jwks": sample_jwks_value(),
        "authority_hints": ["https://ta.example.com"],
        "metadata": {
            "openid_relying_party": {
                "redirect_uris": ["https://rp.example.com/callback"]
            }
        }
    });

    let stmt: EntityStatement = must_ok(serde_json::from_value(json));
    assert_eq!(stmt.iss, "https://rp.example.com");
    assert_eq!(stmt.sub, "https://rp.example.com");
    assert_eq!(stmt.iat, now);
    assert_eq!(stmt.exp, now + 3600);
    assert!(stmt.jwks.is_some());
    assert!(stmt.authority_hints.is_some());
    assert_eq!(must_some(stmt.authority_hints.as_ref()).len(), 1);
    assert!(stmt.metadata.is_some());
    assert!(stmt.metadata_policy.is_none());
    assert!(stmt.constraints.is_none());
    assert!(stmt.trust_marks.is_none());
}

#[test]
fn entity_statement_round_trip() {
    let now = 1_700_000_000_i64;
    let stmt = sample_entity_config("https://rp.example.com", now);
    let json = must_ok(serde_json::to_value(&stmt));
    let deserialized: EntityStatement = must_ok(serde_json::from_value(json));
    assert_eq!(deserialized.iss, stmt.iss);
    assert_eq!(deserialized.sub, stmt.sub);
    assert_eq!(deserialized.iat, stmt.iat);
    assert_eq!(deserialized.exp, stmt.exp);
}

#[test]
fn entity_statement_minimal() {
    let json = json!({
        "iss": "https://example.com",
        "sub": "https://example.com",
        "iat": 1_700_000_000_i64,
        "exp": 1_700_003_600_i64
    });
    let stmt: EntityStatement = must_ok(serde_json::from_value(json));
    assert!(stmt.jwks.is_none());
    assert!(stmt.metadata.is_none());
    assert!(stmt.authority_hints.is_none());
}

// ── Self-Signed Check ────────────────────────────────────────────

#[test]
fn is_self_signed_true() {
    let stmt = sample_entity_config("https://rp.example.com", 1_700_000_000);
    assert!(stmt.is_self_signed());
}

#[test]
fn is_self_signed_false() {
    let stmt = sample_subordinate_statement(
        "https://ta.example.com",
        "https://rp.example.com",
        1_700_000_000,
    );
    assert!(!stmt.is_self_signed());
}

// ── Temporal Validation ──────────────────────────────────────────

#[test]
fn validate_temporal_valid() {
    let now = 1_700_000_000_i64;
    let stmt = sample_entity_config("https://rp.example.com", now);
    assert!(validate_temporal(&stmt, now, 60).is_ok());
}

#[test]
fn validate_temporal_expired() {
    let now = 1_700_000_000_i64;
    let mut stmt = sample_entity_config("https://rp.example.com", now);
    stmt.exp = now - 200; // expired well past leeway
    stmt.iat = now - 500;
    let err = must_err(validate_temporal(&stmt, now, 60));
    assert!(matches!(err, FederationError::Expired));
}

#[test]
fn validate_temporal_not_yet_valid() {
    let now = 1_700_000_000_i64;
    let mut stmt = sample_entity_config("https://rp.example.com", now);
    stmt.iat = now + 200; // issued in the far future
    stmt.exp = now + 3800;
    let err = must_err(validate_temporal(&stmt, now, 60));
    assert!(matches!(err, FederationError::NotYetValid));
}

#[test]
fn validate_temporal_exp_before_iat() {
    let now = 1_700_000_000_i64;
    let mut stmt = sample_entity_config("https://rp.example.com", now);
    stmt.iat = now;
    stmt.exp = now - 100; // exp before iat
    let err = must_err(validate_temporal(&stmt, now, 60));
    assert!(matches!(err, FederationError::Validation(_)));
}

#[test]
fn validate_temporal_at_boundary_with_leeway() {
    let now = 1_700_000_000_i64;
    let mut stmt = sample_entity_config("https://rp.example.com", now);
    stmt.iat = now - 100;
    stmt.exp = now - 50; // expired 50s ago, within 60s leeway
    assert!(validate_temporal(&stmt, now, 60).is_ok());
}

#[test]
fn validate_temporal_rejects_leeway_overflow_near_i64_max() {
    let now = i64::MAX;
    let mut stmt = sample_entity_config("https://rp.example.com", 1_700_000_000);
    stmt.iat = i64::MAX - 1;
    stmt.exp = i64::MAX;

    let err = must_err(validate_temporal(&stmt, now, 60));
    assert!(matches!(err, FederationError::Validation(message) if message.contains("leeway")));
}

#[test]
fn validate_temporal_rejects_negative_leeway() {
    let now = 1_700_000_000_i64;
    let stmt = sample_entity_config("https://rp.example.com", now);

    let err = must_err(validate_temporal(&stmt, now, -1));
    assert!(
        matches!(err, FederationError::Validation(message) if message.contains("non-negative"))
    );
}

// ── Entity Statement Validation ──────────────────────────────────

#[test]
fn validate_entity_statement_valid() {
    let now = 1_700_000_000_i64;
    let stmt = sample_entity_config("https://rp.example.com", now);
    assert!(validate_entity_statement(&stmt, now).is_ok());
}

#[test]
fn validate_entity_statement_empty_iss() {
    let now = 1_700_000_000_i64;
    let mut stmt = sample_entity_config("", now);
    stmt.sub = String::new();
    let err = must_err(validate_entity_statement(&stmt, now));
    assert!(matches!(err, FederationError::MissingField("iss")));
}

#[test]
fn validate_entity_statement_empty_sub() {
    let now = 1_700_000_000_i64;
    let mut stmt = sample_entity_config("https://rp.example.com", now);
    stmt.sub = String::new();
    let err = must_err(validate_entity_statement(&stmt, now));
    assert!(matches!(err, FederationError::MissingField("sub")));
}

#[test]
fn validate_entity_statement_self_signed_missing_jwks() {
    let now = 1_700_000_000_i64;
    let mut stmt = sample_entity_config("https://rp.example.com", now);
    stmt.jwks = None;
    let err = must_err(validate_entity_statement(&stmt, now));
    assert!(matches!(err, FederationError::MissingField("jwks")));
}

#[test]
fn validate_entity_statement_subordinate_no_jwks_ok() {
    let now = 1_700_000_000_i64;
    let mut stmt =
        sample_subordinate_statement("https://ta.example.com", "https://rp.example.com", now);
    stmt.jwks = None; // subordinate statements don't require JWKS
    assert!(validate_entity_statement(&stmt, now).is_ok());
}
