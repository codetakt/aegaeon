const NOW: i64 = 1_700_000_000;
const LEAF: &str = "https://rp.example.com";
const ANCHOR: &str = "https://ta.example.com";
const MARK_ID: &str = "https://trust-mark.example.com/profile";

fn stored_anchor(jwks: Value) -> StoredTrustAnchor {
    StoredTrustAnchor {
        id: Uuid::new_v4(),
        environment_id: Uuid::new_v4(),
        entity_id: ANCHOR.into(),
        jwks,
        metadata_policy: None,
        created_at: NOW,
        updated_at: NOW,
    }
}

fn verify_consumers(
    key: &InMemoryKeyManager,
    keys: Value,
    kid: &str,
) -> [Result<(), FederationError>; 3] {
    let jwks = must_ok(JwkSet::from_value(keys.clone()));
    let mut entity = sample_entity_config(LEAF, NOW);
    entity.jwks = Some(keys);
    let mut header = json!({"alg": FederationKeyManager::federation_alg(key),
        "typ": "entity-statement+jwt", "kid": kid});
    let jwt = purpose::sign_with_header(key, &header, &must_ok(serde_json::to_value(entity)));
    header["typ"] = json!("trust-mark+jwt");
    let mark = TrustMark {
        id: MARK_ID.into(),
        trust_mark: purpose::sign_with_header(
            key,
            &header,
            &json!({"iss": ANCHOR, "sub": LEAF, "trust_mark_type": MARK_ID,
                "iat": NOW - 100, "exp": NOW + 3600}),
        ),
    };
    [
        verify_entity_statement(&jwt, &jwks).map(|_| ()),
        verify_entity_configuration(&jwt).map(|_| ()),
        verify_trust_mark(&mark, LEAF, &jwks, NOW).map(|_| ()),
    ]
}

fn assert_duplicate<T>(result: Result<T, FederationError>, expected: &str) {
    let error = must_err(result);
    assert!(
        matches!(&error, FederationError::Jwk(aegaeon_jose::jwk::JwkError::DuplicateKid(kid))
            if kid == expected),
        "expected duplicate {expected:?}, got {error:?}"
    );
}

#[test]
fn duplicate_named_keys_reject_before_filtering_or_signature_trials() {
    let _guard = raw_json_env_guard();
    let key = InMemoryKeyManager::new();
    let named = must_some(FederationKeyManager::federation_public_jwk(&key));
    let kid = must_some(named["kid"].as_str());
    for result in verify_consumers(&key, json!({"keys": [named]}), kid) {
        must_ok(result);
    }

    let mut different = must_some(FederationKeyManager::federation_public_jwk(
        &InMemoryKeyManager::new(),
    ));
    different["kid"] = json!(kid);
    let mut unrelated = named.clone();
    unrelated["kid"] = json!("unrelated");
    let mut encryption = named.clone();
    encryption["use"] = json!("enc");
    let mut encryption_ops = named.clone();
    encryption_ops["key_ops"] = json!(["encrypt"]);
    for (keys, duplicate) in [
        (vec![named.clone(), named.clone()], kid),
        (vec![named.clone(), different.clone()], kid),
        (vec![different, named.clone()], kid),
        (
            vec![named.clone(), unrelated.clone(), unrelated],
            "unrelated",
        ),
        (vec![named.clone(), encryption], kid),
        (vec![named.clone(), encryption_ops], kid),
    ] {
        let keys = json!({"keys": keys});
        // Generic JOSE parsing is unchanged; both Federation parse boundaries
        // and all three public signature consumers reject the supplied set.
        must_ok(JwkSet::from_value(keys.clone()));
        let mut statement = sample_entity_config(LEAF, NOW);
        statement.jwks = Some(keys.clone());
        assert_duplicate(statement.parse_jwks(), duplicate);
        assert_duplicate(stored_anchor(keys.clone()).to_trust_anchor(), duplicate);
        for result in verify_consumers(&key, keys, kid) {
            assert_duplicate(result, duplicate);
        }
    }
}

#[test]
fn exact_ids_and_optional_key_ids_keep_existing_parse_semantics() {
    let _guard = raw_json_env_guard();
    let key = InMemoryKeyManager::new();
    let named = must_some(FederationKeyManager::federation_public_jwk(&key));
    let mut opaque = Vec::new();
    for kid in ["KeyID", "keyid", " KeyID "] {
        let mut jwk = named.clone();
        jwk["kid"] = json!(kid);
        opaque.push(jwk);
    }
    let keys = json!({"keys": opaque});
    for kid in ["KeyID", "keyid", " KeyID "] {
        for result in verify_consumers(&key, keys.clone(), kid) {
            must_ok(result);
        }
    }
    let mut duplicate = keys.clone();
    must_some(duplicate["keys"].as_array_mut()).push(keys["keys"][0].clone());
    for result in verify_consumers(&key, duplicate, "KeyID") {
        assert_duplicate(result, "KeyID");
    }

    let mut unnamed = named.clone();
    must_some(unnamed.as_object_mut()).remove("kid");
    let mixed = json!({"keys": [named, unnamed.clone(), unnamed.clone()]});
    let kid = must_some(mixed["keys"][0]["kid"].as_str());
    for result in verify_consumers(&key, mixed.clone(), kid) {
        must_ok(result);
    }
    for keys in [mixed, json!({"keys": [unnamed]}), json!({"keys": []})] {
        let mut statement = sample_entity_config(LEAF, NOW);
        statement.jwks = Some(keys.clone());
        must_ok(statement.parse_jwks());
        must_ok(stored_anchor(keys.clone()).to_trust_anchor());
        if keys["keys"].as_array().is_some_and(|keys| keys.len() < 2) {
            for result in verify_consumers(&key, keys, "no-matching-key") {
                assert!(matches!(must_err(result), FederationError::NoSuitableKey));
            }
        }
    }
}

#[test]
fn unique_keys_still_enforce_algorithm_use_and_key_operations() {
    let _guard = raw_json_env_guard();
    let key = InMemoryKeyManager::new();
    let named = must_some(FederationKeyManager::federation_public_jwk(&key));
    let kid = must_some(named["kid"].as_str());
    for (member, value) in [
        ("alg", json!("RS256")),
        ("use", json!("enc")),
        ("key_ops", json!(["encrypt"])),
    ] {
        let mut restricted = named.clone();
        restricted[member] = value;
        for result in verify_consumers(&key, json!({"keys": [restricted]}), kid) {
            assert!(matches!(must_err(result), FederationError::NoSuitableKey));
        }
    }
}

#[test]
fn duplicate_chain_keys_fail_fresh_cached_and_callback_admission() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let anchor = sample_trust_anchor(ANCHOR);
        let mut statements = vec![
            sample_entity_config(LEAF, NOW),
            sample_subordinate_statement(ANCHOR, LEAF, NOW),
            sample_entity_config(ANCHOR, NOW),
        ];
        statements[2].authority_hints = None;
        let duplicate_keys = json!({"keys": [sample_jwks_value()["keys"][0],
            sample_jwks_value()["keys"][0]]});
        // Valid controls plus duplicates in the configured anchor, issuer
        // configuration, superior endorsement, and leaf configuration.
        for boundary in 0..=4 {
            let mut current_anchor = anchor.clone();
            let mut current_statements = statements.clone();
            match boundary {
                1 => current_anchor.jwks = must_ok(JwkSet::from_value(duplicate_keys.clone())),
                2 => current_statements[2].jwks = Some(duplicate_keys.clone()),
                3 => current_statements[1].jwks = Some(duplicate_keys.clone()),
                4 => current_statements[0].jwks = Some(duplicate_keys.clone()),
                _ => {}
            }
            let jwts: Vec<_> = current_statements
                .iter()
                .map(|stmt| sign_entity_statement_for_test(sample_signing_key(), stmt))
                .collect();
            let mut fetcher = MockFetcher::new();
            fetcher.add_entity_config_with_jws(
                LEAF,
                current_statements[0].clone(),
                jwts[0].clone(),
            );
            fetcher.add_subordinate_stmt_with_jws(
                ANCHOR,
                LEAF,
                current_statements[1].clone(),
                jwts[1].clone(),
            );
            fetcher.add_entity_config_with_jws(
                ANCHOR,
                current_statements[2].clone(),
                jwts[2].clone(),
            );
            let anchors = std::slice::from_ref(&current_anchor);
            assert_eq!(
                resolve_trust_chain(LEAF, anchors, &fetcher, NOW)
                    .await
                    .is_ok(),
                boundary == 0
            );
            assert_eq!(
                resolve_trust_chain_with_jwts(LEAF, anchors, &fetcher, NOW)
                    .await
                    .is_ok(),
                boundary == 0
            );

            let cache = InMemoryTrustChainCacheRepo::new();
            let env_id = Uuid::new_v4();
            let cached_jwts = json!(jwts);
            must_ok(cache.upsert(env_id, LEAF, ANCHOR, &cached_jwts, NOW + 3600));
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let result = resolve_trust_chain_jwts_cached_with(
                LEAF,
                env_id,
                vec![current_anchor.clone()],
                &cache,
                &FederationCacheConfig::default(),
                NOW,
                |_| {
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async { Err(FederationError::Fetch("fresh unavailable".into())) }
                },
            )
            .await;
            assert_eq!(result.is_ok(), boundary == 0);
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(boundary != 0)
            );
            assert_eq!(
                must_some(must_ok(cache.get(env_id, LEAF, ANCHOR, NOW))).chain_jwts,
                cached_jwts
            );

            let fresh_cache = InMemoryTrustChainCacheRepo::new();
            let result = resolve_trust_chain_jwts_cached_with(
                LEAF,
                env_id,
                vec![current_anchor.clone()],
                &fresh_cache,
                &FederationCacheConfig::default(),
                NOW,
                |_| {
                    let resolved = ResolvedTrustChain::new(
                        TrustChain {
                            chain: current_statements.clone(),
                            anchor: current_anchor.clone(),
                        },
                        jwts.clone(),
                    );
                    async move { Ok(resolved) }
                },
            )
            .await;
            assert_eq!(result.is_ok(), boundary == 0);
            assert_eq!(
                must_ok(fresh_cache.get(env_id, LEAF, ANCHOR, NOW)).is_some(),
                boundary == 0
            );
        }
    });
}
