const NOW: i64 = 1_700_000_000;
const SUBJECT: &str = "https://entity.example.com";
const MARK_ID: &str = "https://trust-mark.example.com/profile";

fn header_for(key: &InMemoryKeyManager, typ: &str) -> Value {
    let jwk = must_some(FederationKeyManager::federation_public_jwk(key));
    json!({"alg": FederationKeyManager::federation_alg(key), "typ": typ, "kid": jwk["kid"]})
}

pub(super) fn sign_with_header(
    key: &InMemoryKeyManager,
    header: &Value,
    payload: &Value,
) -> String {
    sign_with_raw_header(key, &must_ok(serde_json::to_string(header)), payload)
}

fn sign_with_raw_header(key: &InMemoryKeyManager, header: &str, payload: &Value) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.as_bytes()),
        encode_json_value(payload)
    );
    let signature = must_ok(FederationKeyManager::sign_federation(key, input.as_bytes()));
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn entity_payload(key: &InMemoryKeyManager) -> Value {
    let mut statement = sample_entity_config(SUBJECT, NOW);
    statement.jwks = Some(federation_jwks_value(key));
    must_ok(serde_json::to_value(statement))
}

fn mark_payload() -> Value {
    json!({"iss": "https://issuer.example.com", "sub": SUBJECT,
        "trust_mark_type": MARK_ID, "iat": NOW - 100, "exp": NOW + 3600})
}

fn check_mark(jwt: String, jwks: &JwkSet) -> Result<TrustMarkClaims, FederationError> {
    verify_trust_mark(
        &TrustMark {
            id: MARK_ID.into(),
            trust_mark: jwt,
        },
        SUBJECT,
        jwks,
        NOW,
    )
}

fn set_header_member(header: &mut Value, member: &str, value: Option<Value>) {
    if let Some(value) = value {
        header[member] = value;
    } else {
        must_some(header.as_object_mut()).remove(member);
    }
}

fn invalid_types(other_purpose: &str) -> Vec<Option<Value>> {
    vec![
        None,
        Some(Value::Null),
        Some(json!("")),
        Some(json!("JWT")),
        Some(json!(other_purpose)),
        Some(json!("ENTITY-STATEMENT+JWT")),
        Some(json!("TRUST-MARK+JWT")),
        Some(json!(" entity-statement+jwt")),
        Some(json!("trust-mark+jwt ")),
        Some(json!(123)),
        Some(json!(true)),
        Some(json!([])),
        Some(json!({})),
    ]
}

#[test]
fn entity_configuration_and_subordinate_require_exact_purpose() {
    let _guard = raw_json_env_guard();
    let key = InMemoryKeyManager::new();
    let jwks = must_ok(JwkSet::from_value(federation_jwks_value(&key)));
    let config = entity_payload(&key);
    let mut subordinate = config.clone();
    subordinate["iss"] = json!("https://superior.example.com");
    must_some(subordinate.as_object_mut()).remove("authority_hints");
    must_some(subordinate.as_object_mut()).remove("metadata");
    let valid = header_for(&key, "entity-statement+jwt");
    must_ok(verify_entity_configuration(&sign_with_header(
        &key, &valid, &config,
    )));
    must_ok(verify_entity_statement(
        &sign_with_header(&key, &valid, &subordinate),
        &jwks,
    ));
    for typ in invalid_types("trust-mark+jwt") {
        let mut header = valid.clone();
        set_header_member(&mut header, "typ", typ);
        assert!(verify_entity_configuration(&sign_with_header(&key, &header, &config)).is_err());
        assert!(
            verify_entity_statement(&sign_with_header(&key, &header, &subordinate), &jwks).is_err()
        );
    }
    let wrong_purpose = sign_with_header(&key, &header_for(&key, "trust-mark+jwt"), &config);
    // Parsing for discovery remains explicitly unverified. Actual verification
    // rejects the purpose before a valid Entity Statement payload can be accepted.
    must_ok(parse_entity_statement_unverified(&wrong_purpose));
    assert!(must_err(verify_entity_statement(&wrong_purpose, &jwks))
        .to_string()
        .contains("typ must be entity-statement+jwt"));
}

#[test]
fn trust_mark_requires_exact_purpose() {
    let _guard = raw_json_env_guard();
    let key = InMemoryKeyManager::new();
    let jwks = must_ok(JwkSet::from_value(federation_jwks_value(&key)));
    let payload = mark_payload();
    let valid = header_for(&key, "trust-mark+jwt");
    must_ok(check_mark(sign_with_header(&key, &valid, &payload), &jwks));
    for typ in invalid_types("entity-statement+jwt") {
        let mut header = valid.clone();
        set_header_member(&mut header, "typ", typ);
        assert!(check_mark(sign_with_header(&key, &header, &payload), &jwks).is_err());
    }
    let jwt = sign_with_header(&key, &header_for(&key, "entity-statement+jwt"), &payload);
    assert!(must_err(check_mark(jwt, &jwks))
        .to_string()
        .contains("typ must be trust-mark+jwt"));
}

#[test]
fn federation_tokens_require_nonempty_exact_kid_even_with_one_key() {
    let _guard = raw_json_env_guard();
    let key = InMemoryKeyManager::new();
    let jwks = must_ok(JwkSet::from_value(federation_jwks_value(&key)));
    assert_eq!(jwks.keys().len(), 1);
    for kid in [
        None,
        Some(Value::Null),
        Some(json!("")),
        Some(json!("wrong-key")),
        Some(json!(17)),
        Some(json!(true)),
        Some(json!([])),
        Some(json!({})),
    ] {
        let mut entity_header = header_for(&key, "entity-statement+jwt");
        let mut mark_header = header_for(&key, "trust-mark+jwt");
        set_header_member(&mut entity_header, "kid", kid.clone());
        set_header_member(&mut mark_header, "kid", kid);
        let entity = sign_with_header(&key, &entity_header, &entity_payload(&key));
        assert!(verify_entity_statement(&entity, &jwks).is_err());
        assert!(verify_entity_configuration(&entity).is_err());
        assert!(check_mark(sign_with_header(&key, &mark_header, &mark_payload()), &jwks).is_err());
    }
}

#[test]
fn federation_key_ids_preserve_opaque_whitespace_and_case() {
    let _guard = raw_json_env_guard();
    let key = InMemoryKeyManager::new();
    for kid in [" ", " opaque key ", "KeyID"] {
        let mut keys = federation_jwks_value(&key);
        keys["keys"][0]["kid"] = json!(kid);
        let jwks = must_ok(JwkSet::from_value(keys.clone()));
        let mut entity = entity_payload(&key);
        entity["jwks"] = keys;
        let mut entity_header = header_for(&key, "entity-statement+jwt");
        let mut mark_header = header_for(&key, "trust-mark+jwt");
        entity_header["kid"] = json!(kid);
        mark_header["kid"] = json!(kid);
        must_ok(verify_entity_configuration(&sign_with_header(
            &key,
            &entity_header,
            &entity,
        )));
        must_ok(verify_entity_statement(
            &sign_with_header(&key, &entity_header, &entity),
            &jwks,
        ));
        must_ok(check_mark(
            sign_with_header(&key, &mark_header, &mark_payload()),
            &jwks,
        ));
        let changed = if kid == "KeyID" { "keyid" } else { kid.trim() };
        entity_header["kid"] = json!(changed);
        mark_header["kid"] = json!(changed);
        assert!(
            verify_entity_statement(&sign_with_header(&key, &entity_header, &entity), &jwks)
                .is_err()
        );
        assert!(check_mark(sign_with_header(&key, &mark_header, &mark_payload()), &jwks).is_err());
    }
}

#[test]
fn duplicate_federation_protected_headers_remain_rejected() {
    let _guard = raw_json_env_guard();
    let key = InMemoryKeyManager::new();
    let jwks = must_ok(JwkSet::from_value(federation_jwks_value(&key)));
    for purpose in ["entity-statement+jwt", "trust-mark+jwt"] {
        let header = header_for(&key, purpose);
        for member in ["typ", "kid"] {
            let base = must_ok(serde_json::to_string(&header));
            let raw = format!(
                "{},\"{member}\":{}}}",
                &base[..base.len() - 1],
                header[member]
            );
            let payload = if purpose == "entity-statement+jwt" {
                entity_payload(&key)
            } else {
                mark_payload()
            };
            let jwt = sign_with_raw_header(&key, &raw, &payload);
            if purpose == "entity-statement+jwt" {
                assert!(verify_entity_statement(&jwt, &jwks).is_err());
                assert!(verify_entity_configuration(&jwt).is_err());
            } else {
                assert!(check_mark(jwt, &jwks).is_err());
            }
        }
    }
}

#[test]
fn every_chain_artifact_requires_federation_headers_on_fresh_and_cached_paths() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let leaf_id = "https://rp.example.com";
        let anchor_id = "https://ta.example.com";
        let anchor = sample_trust_anchor(anchor_id);
        let statements = vec![
            sample_entity_config(leaf_id, NOW),
            sample_subordinate_statement(anchor_id, leaf_id, NOW),
            sample_entity_config(anchor_id, NOW),
        ];
        for index in 0..3 {
            for missing_kid in [false, true] {
                let mut jwts: Vec<_> = statements
                    .iter()
                    .map(|stmt| sign_entity_statement_for_test(sample_signing_key(), stmt))
                    .collect();
                let mut header = header_for(sample_signing_key(), "entity-statement+jwt");
                if missing_kid {
                    must_some(header.as_object_mut()).remove("kid");
                } else {
                    header["typ"] = json!("trust-mark+jwt");
                }
                jwts[index] = sign_with_header(
                    sample_signing_key(),
                    &header,
                    &must_ok(serde_json::to_value(&statements[index])),
                );
                let mut fetcher = MockFetcher::new();
                fetcher.add_entity_config_with_jws(leaf_id, statements[0].clone(), jwts[0].clone());
                fetcher.add_subordinate_stmt_with_jws(
                    anchor_id,
                    leaf_id,
                    statements[1].clone(),
                    jwts[1].clone(),
                );
                fetcher.add_entity_config_with_jws(
                    anchor_id,
                    statements[2].clone(),
                    jwts[2].clone(),
                );
                assert!(
                    resolve_trust_chain(leaf_id, std::slice::from_ref(&anchor), &fetcher, NOW)
                        .await
                        .is_err()
                );
                assert!(resolve_trust_chain_with_jwts(
                    leaf_id,
                    std::slice::from_ref(&anchor),
                    &fetcher,
                    NOW
                )
                .await
                .is_err());
                let cache = InMemoryTrustChainCacheRepo::new();
                let env_id = Uuid::new_v4();
                must_ok(cache.upsert(env_id, leaf_id, anchor_id, &json!(jwts), NOW + 3600));
                let calls = std::sync::atomic::AtomicUsize::new(0);
                let result = resolve_trust_chain_jwts_cached_with(
                    leaf_id,
                    env_id,
                    vec![anchor.clone()],
                    &cache,
                    &FederationCacheConfig::default(),
                    NOW,
                    |_| {
                        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        async { Err(FederationError::Fetch("fresh unavailable".into())) }
                    },
                )
                .await;
                assert!(result.is_err());
                assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
                let fresh_cache = InMemoryTrustChainCacheRepo::new();
                let result = resolve_trust_chain_jwts_cached_with(
                    leaf_id,
                    env_id,
                    vec![anchor.clone()],
                    &fresh_cache,
                    &FederationCacheConfig::default(),
                    NOW,
                    |_| {
                        let resolved = ResolvedTrustChain::new(
                            TrustChain {
                                chain: statements.clone(),
                                anchor: anchor.clone(),
                            },
                            jwts.clone(),
                        );
                        async move { Ok(resolved) }
                    },
                )
                .await;
                assert!(result.is_err());
                assert!(must_ok(fresh_cache.get(env_id, leaf_id, anchor_id, NOW)).is_none());
            }
        }
    });
}
