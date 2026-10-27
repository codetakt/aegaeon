use super::signed_parent::ObservedCache;
use std::sync::atomic::{AtomicUsize, Ordering};

fn policy(value: Value) -> HashMap<String, Value> {
    must_ok(serde_json::from_value(value))
}

#[test]
fn signed_chain_admission_rejects_unused_merge_and_application_errors() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for bad in [
            json!({}),
            json!({"unused":{"x":{"add":[true]}}}),
            json!({"openid_relying_party":{"missing":{"essential":true}}}),
        ] {
            let mut fixture = SignedPathFixture::new(1);
            fixture.subordinates[0].metadata_policy = Some(policy(bad));
            let cache = ObservedCache::default();
            let result = resolve_trust_chain_jwts_cached_with(
                &fixture.configs[0].iss,
                Uuid::new_v4(),
                vec![fixture.anchor.clone()],
                &cache,
                &FederationCacheConfig::default(),
                NOW,
                |_| std::future::ready(Ok(fixture.detached())),
            )
            .await;
            assert!(result.is_err());
            assert_eq!(cache.writes.load(Ordering::SeqCst), 0);
            assert!(resolve_trust_chain_with_jwts(
                &fixture.configs[0].iss,
                &[fixture.anchor.clone()],
                &fixture.fetcher(),
                NOW
            )
            .await
            .is_err());
        }
        let mut absent = SignedPathFixture::new(0);
        absent.configs[0].metadata = None;
        absent.subordinates[0].metadata_policy = Some(policy(json!({"unused":{"x":{}}})));
        assert!(resolve_trust_chain_with_jwts(
            &absent.configs[0].iss,
            &[absent.anchor.clone()],
            &absent.fetcher(),
            NOW
        )
        .await
        .is_err());
    });
}

#[test]
fn signed_chain_admission_backtracks_policy_invalid_first_authority() {
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
        bad_upper.metadata_policy = Some(policy(
            json!({"openid_relying_party":{"missing":{"essential":true}}}),
        ));
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

#[test]
fn cached_policy_failure_refetches_and_invalid_callback_cannot_renew() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let fixture = SignedPathFixture::new(0);
        // Reuse exact keys/identities, replacing only signed policy bytes.
        let fresh = fixture.detached();
        let mut bad = fresh.clone();
        bad.trust_chain.chain[1].metadata_policy = Some(policy(
            json!({"openid_relying_party":{"missing":{"essential":true}}}),
        ));
        bad.chain_jwts[1] =
            sign_entity_statement_for_test(&fixture.keys[1], &bad.trust_chain.chain[1]);
        for valid_fresh in [false, true] {
            let cache = ObservedCache::default();
            let env = Uuid::new_v4();
            must_ok(cache.inner.upsert(
                env,
                &fixture.configs[0].iss,
                &fixture.anchor.entity_id,
                &json!(bad.chain_jwts),
                NOW + 500,
            ));
            let before = must_some(must_ok(cache.inner.get(
                env,
                &fixture.configs[0].iss,
                &fixture.anchor.entity_id,
                NOW,
            )));
            let calls = AtomicUsize::new(0);
            let result = resolve_trust_chain_jwts_cached_with(
                &fixture.configs[0].iss,
                env,
                vec![fixture.anchor.clone()],
                &cache,
                &FederationCacheConfig::default(),
                NOW,
                |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok(if valid_fresh {
                        fresh.clone()
                    } else {
                        bad.clone()
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
            let after = must_some(must_ok(cache.inner.get(
                env,
                &fixture.configs[0].iss,
                &fixture.anchor.entity_id,
                NOW,
            )));
            if valid_fresh {
                assert_eq!(after.chain_jwts, json!(fresh.chain_jwts));
            } else {
                assert_eq!(after.chain_jwts, before.chain_jwts);
                assert_eq!(after.expires_at, before.expires_at);
            }
        }
    });
}

#[test]
fn stored_pin_changes_apply_to_next_cached_use_and_invalid_rows_remain_readable() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let fixture = SignedPathFixture::new(0);
        let env = Uuid::new_v4();
        let repo = InMemoryTrustAnchorRepo::new();
        let cache = ObservedCache::default();
        let jwks = must_some(fixture.configs[1].jwks.as_ref());
        must_ok(repo.upsert(env, &fixture.anchor.entity_id, jwks, None));
        must_ok(
            resolve_trust_chain_cached_with(
                &fixture.configs[0].iss,
                env,
                &repo,
                &cache,
                &FederationCacheConfig::default(),
                NOW,
                |_| std::future::ready(Ok(fixture.detached())),
            )
            .await,
        );
        assert_eq!(cache.writes.load(Ordering::SeqCst), 1);
        let pin = json!({"openid_relying_party":{"grant_types":{"essential":true}}});
        must_ok(repo.upsert(env, &fixture.anchor.entity_id, jwks, Some(&pin)));
        assert!(resolve_trust_chain_cached_with(
            &fixture.configs[0].iss,
            env,
            &repo,
            &cache,
            &FederationCacheConfig::default(),
            NOW,
            |_| std::future::ready(Ok(fixture.detached()))
        )
        .await
        .is_err());
        assert_eq!(cache.writes.load(Ordering::SeqCst), 1);
        // Custom test repository models an invalid pre-upgrade row.
        must_ok(repo.upsert(env, &fixture.anchor.entity_id, jwks, Some(&json!({}))));
        let stored = must_some(must_ok(repo.get(env, &fixture.anchor.entity_id)));
        assert_eq!(stored.metadata_policy, Some(json!({})));
        assert!(stored.to_trust_anchor().is_err());
        let calls = AtomicUsize::new(0);
        assert!(resolve_trust_chain_cached_with(
            &fixture.configs[0].iss,
            env,
            &repo,
            &cache,
            &FederationCacheConfig::default(),
            NOW,
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(fixture.detached()))
            }
        )
        .await
        .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(must_ok(repo.delete(env, &fixture.anchor.entity_id)));
    });
}
