// ── Trust Mark Claims Validation ─────────────────────────────────

#[test]
fn trust_mark_claims_valid() {
    let now = 1_700_000_000_i64;
    let claims = TrustMarkClaims {
        iss: "https://tm-issuer.example.com".to_string(),
        sub: "https://rp.example.com".to_string(),
        id: "https://tm.example.com/profile1".to_string(),
        iat: now - 100,
        exp: Some(now + 3600),
        ref_: None,
    };
    assert!(validate_trust_mark_claims(
        &claims,
        "https://rp.example.com",
        "https://tm.example.com/profile1",
        now,
    )
    .is_ok());
}

#[test]
fn trust_mark_claims_iss_not_https() {
    let now = 1_700_000_000_i64;
    let claims = TrustMarkClaims {
        iss: "http://tm-issuer.example.com".to_string(),
        sub: "https://rp.example.com".to_string(),
        id: "https://tm.example.com/profile1".to_string(),
        iat: now - 100,
        exp: Some(now + 3600),
        ref_: None,
    };
    let err = must_err(validate_trust_mark_claims(
        &claims,
        "https://rp.example.com",
        "https://tm.example.com/profile1",
        now,
    ));
    assert!(matches!(err, FederationError::TrustMark(_)));
}

#[test]
fn trust_mark_claims_iss_rejects_non_entity_url_components() {
    let now = 1_700_000_000_i64;
    let base_claims = TrustMarkClaims {
        iss: "https://tm-issuer.example.com".to_string(),
        sub: "https://rp.example.com".to_string(),
        id: "https://tm.example.com/profile1".to_string(),
        iat: now - 100,
        exp: Some(now + 3600),
        ref_: None,
    };
    let invalid_issuers = [
        "https://tm-issuer.example.com?policy=loose",
        "https://tm-issuer.example.com#fragment",
        "https://user@tm-issuer.example.com",
        "https://",
    ];

    for iss in invalid_issuers {
        let claims = TrustMarkClaims {
            iss: iss.to_string(),
            ..base_claims.clone()
        };
        let err = must_err(validate_trust_mark_claims(
            &claims,
            "https://rp.example.com",
            "https://tm.example.com/profile1",
            now,
        ));
        assert!(matches!(err, FederationError::TrustMark(_)));
    }
}

#[test]
fn trust_mark_claims_sub_mismatch() {
    let now = 1_700_000_000_i64;
    let claims = TrustMarkClaims {
        iss: "https://tm-issuer.example.com".to_string(),
        sub: "https://evil.example.com".to_string(),
        id: "https://tm.example.com/profile1".to_string(),
        iat: now - 100,
        exp: Some(now + 3600),
        ref_: None,
    };
    let err = must_err(validate_trust_mark_claims(
        &claims,
        "https://rp.example.com",
        "https://tm.example.com/profile1",
        now,
    ));
    assert!(matches!(err, FederationError::TrustMark(_)));
}

#[test]
fn trust_mark_claims_id_mismatch() {
    let now = 1_700_000_000_i64;
    let claims = TrustMarkClaims {
        iss: "https://tm-issuer.example.com".to_string(),
        sub: "https://rp.example.com".to_string(),
        id: "https://tm.example.com/wrong-profile".to_string(),
        iat: now - 100,
        exp: Some(now + 3600),
        ref_: None,
    };
    let err = must_err(validate_trust_mark_claims(
        &claims,
        "https://rp.example.com",
        "https://tm.example.com/profile1",
        now,
    ));
    assert!(matches!(err, FederationError::TrustMark(_)));
}

#[test]
fn trust_mark_claims_expired() {
    let now = 1_700_000_000_i64;
    let claims = TrustMarkClaims {
        iss: "https://tm-issuer.example.com".to_string(),
        sub: "https://rp.example.com".to_string(),
        id: "https://tm.example.com/profile1".to_string(),
        iat: now - 7200,
        exp: Some(now - 3600),
        ref_: None,
    };
    let err = must_err(validate_trust_mark_claims(
        &claims,
        "https://rp.example.com",
        "https://tm.example.com/profile1",
        now,
    ));
    assert!(matches!(err, FederationError::TrustMark(_)));
}

#[test]
fn trust_mark_claims_exp_skew_overflow_rejected() {
    let claims = TrustMarkClaims {
        iss: "https://tm-issuer.example.com".to_string(),
        sub: "https://rp.example.com".to_string(),
        id: "https://tm.example.com/profile1".to_string(),
        iat: i64::MAX - 1,
        exp: Some(i64::MAX),
        ref_: None,
    };

    let err = must_err(validate_trust_mark_claims(
        &claims,
        "https://rp.example.com",
        "https://tm.example.com/profile1",
        i64::MAX,
    ));

    assert!(matches!(err, FederationError::TrustMark(message) if message.contains("clock skew")));
}

#[test]
fn trust_mark_claims_exp_before_iat() {
    let now = 1_700_000_000_i64;
    let claims = TrustMarkClaims {
        iss: "https://tm-issuer.example.com".to_string(),
        sub: "https://rp.example.com".to_string(),
        id: "https://tm.example.com/profile1".to_string(),
        iat: now - 100,
        exp: Some(now - 200),
        ref_: None,
    };
    let err = must_err(validate_trust_mark_claims(
        &claims,
        "https://rp.example.com",
        "https://tm.example.com/profile1",
        now,
    ));
    assert!(matches!(err, FederationError::TrustMark(_)));
}

#[test]
fn trust_mark_claims_no_exp_valid() {
    let now = 1_700_000_000_i64;
    let claims = TrustMarkClaims {
        iss: "https://tm-issuer.example.com".to_string(),
        sub: "https://rp.example.com".to_string(),
        id: "https://tm.example.com/profile1".to_string(),
        iat: now - 100,
        exp: None,
        ref_: None,
    };
    assert!(validate_trust_mark_claims(
        &claims,
        "https://rp.example.com",
        "https://tm.example.com/profile1",
        now,
    )
    .is_ok());
}

#[test]
fn trust_mark_claims_future_iat() {
    let now = 1_700_000_000_i64;
    let claims = TrustMarkClaims {
        iss: "https://tm-issuer.example.com".to_string(),
        sub: "https://rp.example.com".to_string(),
        id: "https://tm.example.com/profile1".to_string(),
        iat: now + 3600,
        exp: Some(now + 7200),
        ref_: None,
    };
    let err = must_err(validate_trust_mark_claims(
        &claims,
        "https://rp.example.com",
        "https://tm.example.com/profile1",
        now,
    ));
    assert!(matches!(err, FederationError::TrustMark(_)));
}

#[test]
fn trust_mark_claims_round_trip() {
    let now = 1_700_000_000_i64;
    let claims = TrustMarkClaims {
        iss: "https://tm-issuer.example.com".to_string(),
        sub: "https://rp.example.com".to_string(),
        id: "https://tm.example.com/profile1".to_string(),
        iat: now,
        exp: Some(now + 3600),
        ref_: Some("https://tm-issuer.example.com/.well-known/openid-federation".to_string()),
    };
    let json = must_ok(serde_json::to_value(&claims));
    let parsed: TrustMarkClaims = must_ok(serde_json::from_value(json.clone()));
    assert_eq!(parsed.iss, claims.iss);
    assert_eq!(parsed.sub, claims.sub);
    assert_eq!(parsed.id, claims.id);
    assert_eq!(parsed.exp, claims.exp);
    assert_eq!(parsed.ref_, claims.ref_);
    assert_eq!(json["trust_mark_type"], claims.id);
    assert_eq!(json["ref"], claims.ref_.as_deref().unwrap_or(""));
}
