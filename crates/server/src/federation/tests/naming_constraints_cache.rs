use super::super::signed_parent::ObservedCache;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn naming_cache_and_custom_resolution_use_raw_claims_before_writes() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let mut f = SignedPathFixture::new(1);
        constrain(&mut f, 1, names(Some(&[".example.com"]), None));
        let valid = f.detached();
        let cache = ObservedCache::default();
        let env = Uuid::new_v4();
        let mut forged = valid.clone();
        forged.trust_chain.chain[3]
            .constraints
            .as_mut()
            .unwrap()
            .naming_constraints = Some(names(Some(&[]), None));
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
            must_ok(serde_json::to_value(&accepted.trust_chain.chain)),
            must_ok(serde_json::to_value(&valid.trust_chain.chain))
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
        assert_eq!(cached.chain_jwts, valid.chain_jwts);
        for raw in [
            json!({"permitted":[]}),
            json!({"excluded":["entity-1.example.com"]}),
            Value::Null,
            json!({"permitted":null}),
        ] {
            let mut invalid = valid.clone();
            let mut statement = must_ok(serde_json::to_value(&f.subordinates[1]));
            statement["constraints"]["naming_constraints"] = raw;
            let key = &f.keys[2];
            let jwk = must_some(FederationKeyManager::federation_public_jwk(key));
            invalid.chain_jwts[3] = super::super::super::purpose::sign_with_header(
                key,
                &json!({"alg":"ES256","typ":"entity-statement+jwt","kid":jwk["kid"]}),
                &statement,
            ); // Detached typed claims remain permissive.
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
            }
            let empty = ObservedCache::default();
            assert!(resolve_trust_chain_jwts_cached_with(
                &f.configs[0].iss,
                Uuid::new_v4(),
                vec![f.anchor.clone()],
                &empty,
                &FederationCacheConfig::default(),
                NOW,
                |_| std::future::ready(Ok(invalid.clone())),
            )
            .await
            .is_err());
            assert_eq!(empty.writes.load(Ordering::SeqCst), 0);
        }
    });
}

#[test]
fn naming_fresh_traversal_backtracks_restricted_first_authority() {
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
        bad_upper.constraints = Some(Constraints {
            naming_constraints: Some(names(Some(&[".example.com"]), None)),
            ..Constraints::default()
        });
        constrain(&mut fixture, 1, names(Some(&[".example.com"]), None));
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
