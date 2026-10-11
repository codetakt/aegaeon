use super::signed_parent::ObservedCache;
use crate::federation::trust_chain::verify_signed_path;
use std::sync::atomic::{AtomicUsize, Ordering};

fn map(value: Value) -> HashMap<String, Value> {
    must_ok(serde_json::from_value(value))
}

fn declare(fixture: &mut SignedPathFixture, index: usize, names: &[&str]) {
    fixture.subordinates[index].metadata_policy_crit =
        Some(names.iter().map(|name| (*name).into()).collect());
}

fn verified(fixture: &SignedPathFixture) -> Result<TrustChain, FederationError> {
    verify_signed_path(
        &fixture.jwts(),
        &fixture.configs[0].iss,
        &fixture.anchor,
        NOW,
    )
}

#[test]
fn signed_critical_policy_collects_all_superiors_before_processing() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for intermediates in [0, 2] {
            for declaration in 0..=intermediates {
                for occurrence in 0..=intermediates {
                    let mut f = SignedPathFixture::new(intermediates);
                    f.configs[0].metadata = Some(map(json!({"custom":{"x":["leaf","overlay"]}})));
                    f.subordinates[0].metadata =
                        Some(map(json!({"custom":{"x":["overlay","extra"]}})));
                    declare(&mut f, declaration, &["intersect", "intersect"]);
                    f.subordinates[occurrence].metadata_policy = Some(map(
                        json!({"custom":{"x":{"intersect":["overlay"],"unknown_noncritical":null}}}),
                    ));
                    let result = must_ok(
                        resolve_trust_chain_with_jwts(
                            &f.configs[0].iss,
                            &[f.anchor.clone()],
                            &f.fetcher(),
                            NOW,
                        )
                        .await,
                    );
                    assert_eq!(
                        must_ok(result.trust_chain.resolved_metadata()),
                        Some(map(json!({"custom":{"x":["overlay"]}})))
                    );
                    assert_eq!(
                        result.trust_chain.chain[1 + declaration * 2].metadata_policy_crit,
                        Some(vec!["intersect".into(), "intersect".into()])
                    );
                    for (jwt, typed) in result.chain_jwts.iter().zip(&result.trust_chain.chain) {
                        assert_eq!(
                            must_ok(serde_json::to_value(must_ok(
                                parse_entity_statement_unverified(jwt)
                            ))),
                            must_ok(serde_json::to_value(typed))
                        );
                    }
                    // Unsigned direct construction checks semantics, not authenticity.
                    assert_eq!(
                        must_ok(f.detached().trust_chain.resolved_metadata()),
                        must_ok(result.trust_chain.resolved_metadata())
                    );
                    f.subordinates[occurrence].metadata_policy = None;
                    must_ok(verified(&f)); // Supported names need not occur at all.
                }
            }
        }
        let mut f = SignedPathFixture::new(2);
        f.configs[0].metadata = Some(map(json!({"custom":{"x":["a","b","c"]}})));
        for index in [0, 2] {
            declare(&mut f, index, &["intersect"]);
        }
        f.subordinates[0].metadata_policy =
            Some(map(json!({"custom":{"x":{"intersect":["a","b"]}}})));
        f.subordinates[2].metadata_policy =
            Some(map(json!({"custom":{"x":{"intersect":["b","c"]}}})));
        assert_eq!(
            must_ok(must_ok(verified(&f)).resolved_metadata()),
            Some(map(json!({"custom":{"x":["b"]}})))
        );
        f.anchor.metadata_policy = Some(json!(f.subordinates[2].metadata_policy));
        must_ok(verified(&f));
        f.anchor.metadata_policy = Some(json!({"custom":{"x":{"intersect":["c","b"]}}}));
        assert!(verified(&f).is_err()); // Original array order still governs the local pin.
    });
}

#[test]
fn critical_policy_rejects_invalid_declarations_even_without_metadata() {
    let _guard = raw_json_env_guard();
    for declaration in [
        vec![],
        vec!["unknown"],
        vec!["subset_of"],
        vec!["Intersect"],
    ] {
        for index in 0..5 {
            let mut f = SignedPathFixture::new(1);
            f.configs[0].metadata = None;
            let mut direct = f.detached();
            direct.trust_chain.chain[index].metadata_policy_crit =
                Some(declaration.iter().map(|name| (*name).into()).collect());
            assert!(direct.trust_chain.resolved_metadata().is_err());
            if index % 2 == 0 {
                f.configs[index / 2].metadata_policy_crit = Some(vec!["intersect".into()]);
                assert!(f.detached().trust_chain.resolved_metadata().is_err());
            } else {
                declare(&mut f, index / 2, &declaration);
            }
            assert!(verified(&f).is_err());
        }
    }
    let mut f = SignedPathFixture::new(1);
    f.configs[0].metadata = None;
    declare(&mut f, 1, &["intersect"]);
    assert_eq!(must_ok(must_ok(verified(&f)).resolved_metadata()), None);
}

#[test]
fn critical_alias_validates_unused_filtered_and_absent_policy_domains() {
    let _guard = raw_json_env_guard();
    for absent in [false, true] {
        for filtered in [false, true] {
            for invalid in [
                json!({"intersect":true}),
                json!({"intersect":[null]}),
                json!({"intersect":["a",2]}),
                json!({"intersect":["a"],"subset_of":false}),
                json!({"intersect":["a"],"one_of":["a"]}),
                json!({"intersect":["a"],"superset_of":["b"]}),
                json!({"intersect":["a"],"value":["b"]}),
                json!({}),
            ] {
                let mut f = SignedPathFixture::new(1);
                if absent {
                    f.configs[0].metadata = None;
                }
                if filtered {
                    f.subordinates[0].constraints = Some(Constraints {
                        allowed_entity_types: Some(vec![]),
                        ..Constraints::default()
                    });
                }
                declare(&mut f, 0, &["intersect"]);
                let entity_type = if filtered {
                    "openid_relying_party"
                } else {
                    "unused"
                };
                f.subordinates[1].metadata_policy = Some(map(json!({entity_type:{"x":invalid}})));
                assert!(verified(&f).is_err());
                assert!(f.detached().trust_chain.resolved_metadata().is_err());
            }
            let mut f = SignedPathFixture::new(1);
            if absent {
                f.configs[0].metadata = None;
            }
            if filtered {
                f.subordinates[0].constraints = Some(Constraints {
                    allowed_entity_types: Some(vec![]),
                    ..Constraints::default()
                });
            }
            declare(&mut f, 1, &["intersect"]);
            let entity_type = if filtered {
                "openid_relying_party"
            } else {
                "unused"
            };
            f.subordinates[0].metadata_policy =
                Some(map(json!({entity_type:{"x":{"intersect":["a"]}}})));
            f.subordinates[1].metadata_policy = Some(map(json!({entity_type:{"x":{"add":["b"]}}})));
            assert!(verified(&f).is_err()); // Contradiction appears only after merging.
        }
    }
    let mut f = SignedPathFixture::new(1);
    f.configs[0].metadata = Some(map(json!({"keep":{"x":["a","b"]},"remove":{}})));
    declare(&mut f, 1, &["intersect"]);
    f.subordinates[0].constraints = Some(Constraints {
        allowed_entity_types: Some(vec!["keep".into()]),
        ..Constraints::default()
    });
    f.subordinates[0].metadata_policy = Some(map(
        json!({"keep":{"x":{"intersect":["a"],"unknown":false}},"remove":{"x":{"default":["a"],"intersect":["a"]}},"invented":{"x":{"value":["a"]}}}),
    ));
    assert_eq!(
        must_ok(must_ok(verified(&f)).resolved_metadata()),
        Some(map(json!({"keep":{"x":["a"]}})))
    );
    f.subordinates[1].metadata_policy_crit = None;
    assert_eq!(
        must_ok(must_ok(verified(&f)).resolved_metadata()),
        Some(map(json!({"keep":{"x":["a"]}})))
    );
}

fn replace_raw_declaration(f: &SignedPathFixture, value: Value) -> ResolvedTrustChain {
    let mut detached = f.detached();
    let mut statement = must_ok(serde_json::to_value(&f.subordinates[0]));
    statement["metadata_policy_crit"] = value;
    let key = &f.keys[1];
    let jwk = must_some(FederationKeyManager::federation_public_jwk(key));
    detached.chain_jwts[1] = super::super::purpose::sign_with_header(
        key,
        &json!({"alg":"ES256","typ":"entity-statement+jwt","kid":jwk["kid"]}),
        &statement,
    );
    detached.trust_chain.chain[1].metadata_policy_crit = None;
    detached
}

#[test]
fn critical_policy_cache_rebuilds_raw_declarations_and_preserves_failed_entries() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let mut f = SignedPathFixture::new(1);
        declare(&mut f, 0, &["intersect", "intersect"]);
        let valid = f.detached();
        let cache = ObservedCache::default();
        let env = Uuid::new_v4();
        let mut forged = valid.clone();
        forged.trust_chain.chain[1].metadata_policy_crit = Some(vec!["invented".into()]);
        let accepted = must_ok(
            resolve_trust_chain_jwts_cached_with(
                &f.configs[0].iss,
                env,
                vec![f.anchor.clone()],
                &cache,
                &FederationCacheConfig::default(),
                NOW,
                |_| std::future::ready(Ok(forged.clone())),
            )
            .await,
        );
        assert_eq!(
            accepted.trust_chain.chain[1].metadata_policy_crit,
            f.subordinates[0].metadata_policy_crit
        );
        let cached = must_ok(
            resolve_trust_chain_jwts_cached_with(
                &f.configs[0].iss,
                env,
                vec![f.anchor.clone()],
                &cache,
                &FederationCacheConfig::default(),
                NOW,
                |_| async { panic!("valid raw cache must be used") },
            )
            .await,
        );
        assert_eq!(
            cached.trust_chain.chain[1].metadata_policy_crit,
            f.subordinates[0].metadata_policy_crit
        );
        for raw in [Value::Null, json!([]), json!(["unsupported"]), json!([1])] {
            let invalid = replace_raw_declaration(&f, raw);
            for valid_fresh in [false, true] {
                let cache = ObservedCache::default();
                let env = Uuid::new_v4();
                must_ok(cache.inner.upsert(
                    env,
                    &f.configs[0].iss,
                    &f.anchor.entity_id,
                    &json!(invalid.chain_jwts),
                    NOW + 500,
                ));
                let before = must_some(must_ok(cache.inner.get(
                    env,
                    &f.configs[0].iss,
                    &f.anchor.entity_id,
                    NOW,
                )));
                let calls = AtomicUsize::new(0);
                let result = resolve_trust_chain_jwts_cached_with(
                    &f.configs[0].iss,
                    env,
                    vec![f.anchor.clone()],
                    &cache,
                    &FederationCacheConfig::default(),
                    NOW,
                    |_| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        std::future::ready(Ok(if valid_fresh {
                            valid.clone()
                        } else {
                            invalid.clone()
                        }))
                    },
                )
                .await;
                assert_eq!(result.is_ok(), valid_fresh);
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert_eq!(
                    cache.writes.load(Ordering::SeqCst),
                    usize::from(valid_fresh)
                );
                if !valid_fresh {
                    let after = must_some(must_ok(cache.inner.get(
                        env,
                        &f.configs[0].iss,
                        &f.anchor.entity_id,
                        NOW,
                    )));
                    assert_eq!(before.chain_jwts, after.chain_jwts);
                    assert_eq!(before.expires_at, after.expires_at);
                }
                let empty = ObservedCache::default();
                assert!(resolve_trust_chain_jwts_cached_with(
                    &f.configs[0].iss,
                    Uuid::new_v4(),
                    vec![f.anchor.clone()],
                    &empty,
                    &FederationCacheConfig::default(),
                    NOW,
                    |_| std::future::ready(Ok(invalid.clone()))
                )
                .await
                .is_err());
                assert_eq!(empty.writes.load(Ordering::SeqCst), 0);
            }
        }
    });
}

#[test]
fn critical_policy_fresh_traversal_backtracks_unsupported_first_authority() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let mut fixture = SignedPathFixture::new(1);
        let bad_id = "https://bad-intermediate.example";
        fixture.configs[0].authority_hints =
            Some(vec![bad_id.into(), fixture.configs[1].iss.clone()]);
        let mut bad_config = fixture.configs[1].clone();
        bad_config.iss = bad_id.into();
        bad_config.sub = bad_id.into();
        let mut bad_lower = fixture.subordinates[0].clone();
        bad_lower.iss = bad_id.into();
        let mut bad_upper = fixture.subordinates[1].clone();
        bad_upper.sub = bad_id.into();
        bad_upper.metadata_policy_crit = Some(vec!["unsupported".into()]);
        declare(&mut fixture, 1, &["intersect"]);
        let mut fetcher = fixture.fetcher();
        fetcher.add_entity_config_with_jws(
            bad_id,
            bad_config.clone(),
            sign_entity_statement_for_test(&fixture.keys[1], &bad_config),
        );
        fetcher.add_subordinate_stmt_with_jws(
            bad_id,
            &fixture.configs[0].iss,
            bad_lower.clone(),
            sign_entity_statement_for_test(&fixture.keys[1], &bad_lower),
        );
        fetcher.add_subordinate_stmt_with_jws(
            &fixture.configs[2].iss,
            bad_id,
            bad_upper.clone(),
            sign_entity_statement_for_test(&fixture.keys[2], &bad_upper),
        );
        let resolved = must_ok(
            resolve_trust_chain_with_jwts(
                &fixture.configs[0].iss,
                &[fixture.anchor.clone()],
                &fetcher,
                NOW,
            )
            .await,
        );
        let mut expected =
            vec![must_some(fetcher.entity_config_jwts.get(&fixture.configs[0].iss)).clone()];
        for (index, statement) in fixture.subordinates.iter().enumerate() {
            expected.push(
                must_some(
                    fetcher
                        .subordinate_stmt_jwts
                        .get(&(statement.iss.clone(), statement.sub.clone())),
                )
                .clone(),
            );
            expected.push(
                must_some(
                    fetcher
                        .entity_config_jwts
                        .get(&fixture.configs[index + 1].iss),
                )
                .clone(),
            );
        }
        assert_eq!(resolved.chain_jwts, expected);
        assert_eq!(resolved.trust_chain.chain.len(), 5);
        assert!(resolved
            .trust_chain
            .chain
            .iter()
            .all(|statement| statement.iss != bad_id && statement.sub != bad_id));
    });
}
