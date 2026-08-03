use super::*;

#[test]
fn rsa_public_components_parse_spki_public_pem() -> TestResult {
    let (modulus, exponent) = test_some(
        rsa_public_components_from_public_pem(TEST_RSA_PUBLIC_KEY_PEM),
        "rsa public key",
    )?;
    assert!(!modulus.is_empty());
    assert!(!exponent.is_empty());
    Ok(())
}

#[test]
fn test_parse_cache_control_max_age() {
    let mut h = HeaderMap::new();
    h.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=120, must-revalidate"),
    );
    assert_eq!(parse_cache_control(&h), Some(120));
    let mut h2 = HeaderMap::new();
    h2.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    assert_eq!(parse_cache_control(&h2), None);

    let mut h3 = HeaderMap::new();
    h3.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=18446744073709551615"),
    );
    assert_eq!(
        parse_cache_control(&h3),
        Some(MAX_JWKS_CACHE_CONTROL_MAX_AGE_SECS)
    );

    let mut h4 = HeaderMap::new();
    h4.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=184467440737095516150"),
    );
    assert_eq!(parse_cache_control(&h4), None);
}

#[test]
fn test_sha256_hex() {
    let d = sha256_hex(b"abc");
    assert_eq!(
        d,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn test_duplicate_kid_detected() {
    let jwks = FetchedJwks {
        keys: vec![
            FetchedJwk {
                kty: "EC".into(),
                key_use: None,
                key_ops: None,
                kid: Some("k1".into()),
                alg: None,
                n: None,
                e: None,
                x: Some("x".into()),
                y: Some("y".into()),
                crv: Some("P-256".into()),
            },
            FetchedJwk {
                kty: "EC".into(),
                key_use: None,
                key_ops: None,
                kid: Some("k1".into()),
                alg: None,
                n: None,
                e: None,
                x: Some("x2".into()),
                y: Some("y2".into()),
                crv: Some("P-256".into()),
            },
        ],
    };
    assert!(has_duplicate_kid(&jwks));
}

#[test]
fn decode_fetched_jwks_body_rejects_duplicate_nested_object_key() {
    let body = br#"{
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "first",
                    "kid": "second",
                    "alg": "RS256",
                    "n": "00",
                    "e": "AQAB"
                }
            ]
        }"#;

    let decoded = decode_fetched_jwks_body(
        &JwksRuntimePolicy::default(),
        "https://jwks.example/keys.json",
        "testhash",
        body,
        std::time::Instant::now(),
    );
    assert!(decoded.is_none());
}

#[test]
fn test_kid_reuse_changed_detected() {
    let prev = CacheEntry {
        etag: None,
        expires_at: None,
        fetched_at: std::time::Instant::now(),
        jwks: FetchedJwks { keys: vec![] },
        kid_fps: {
            let mut m = HashMap::new();
            m.insert("k1".into(), "fp1".into());
            m
        },
        last_modified: None,
    };
    let mut new_map = HashMap::new();
    new_map.insert("k1".into(), "fp2".into());
    assert!(kid_reuse_changed(&prev, &new_map));
}

#[test]
fn test_select_jwk_prefers_requested_kid_and_rejects_ambiguous_default() -> TestResult {
    let jwks = FetchedJwks {
        keys: vec![
            FetchedJwk {
                kty: "EC".into(),
                key_use: None,
                key_ops: None,
                kid: Some("k1".into()),
                alg: None,
                n: None,
                e: None,
                x: Some("x1".into()),
                y: Some("y1".into()),
                crv: Some("P-256".into()),
            },
            FetchedJwk {
                kty: "RSA".into(),
                key_use: None,
                key_ops: None,
                kid: Some("k2".into()),
                alg: None,
                n: Some("n2".into()),
                e: Some("e2".into()),
                x: None,
                y: None,
                crv: None,
            },
        ],
    };

    let selected = select_jwk(&jwks, Some("k2"));
    assert!(selected.is_some());
    let s = test_some(selected, "selected JWK")?;
    assert_eq!(s.kty, "RSA");
    assert_eq!(s.kid.as_deref(), Some("k2"));

    let default = select_jwk(&jwks, None);
    assert!(
        default.is_none(),
        "missing kid must fail closed when multiple signature-capable keys exist"
    );
    Ok(())
}

#[test]
fn select_jwk_without_kid_accepts_single_signature_key() -> TestResult {
    let jwks = FetchedJwks {
        keys: vec![FetchedJwk {
            kty: "EC".into(),
            key_use: None,
            key_ops: None,
            kid: Some("k1".into()),
            alg: None,
            n: None,
            e: None,
            x: Some("x1".into()),
            y: Some("y1".into()),
            crv: Some("P-256".into()),
        }],
    };

    let default = select_jwk(&jwks, None);
    assert!(default.is_some());
    let d = test_some(default, "default JWK")?;
    assert_eq!(d.kty, "EC");
    assert_eq!(d.kid.as_deref(), Some("k1"));
    Ok(())
}

#[test]
fn inline_jwks_without_kid_rejects_ambiguous_signature_keys() -> TestResult {
    let jwks = test_context(
        RegisteredClientJwks::from_value(
            serde_json::json!({
                "keys": [
                    {"kty":"RSA","kid":"k1","n":"n1","e":"e1"},
                    {"kty":"RSA","kid":"k2","n":"n2","e":"e2"}
                ]
            }),
            false,
        ),
        "valid inline JWKS",
    )?;

    assert!(
        jwks.select(None).is_none(),
        "missing kid must fail closed for ambiguous inline JWKS"
    );
    assert!(jwks.select(Some("k2")).is_some());
    Ok(())
}
