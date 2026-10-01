use crate::federation::repositories::StoredTrustChain;
use crate::federation::trust_chain::verify_signed_path;
use std::sync::atomic::{AtomicUsize, Ordering};

type CacheFuture<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = Result<T, FederationError>> + Send + 'a>>;

fn replace_signed_hints(
    fixture: &SignedPathFixture,
    jwts: &mut [String],
    index: usize,
    hints: Option<Value>,
) {
    let mut payload = must_ok(serde_json::to_value(&fixture.configs[index]));
    let object = must_some(payload.as_object_mut());
    match hints {
        Some(value) => {
            object.insert("authority_hints".into(), value);
        }
        None => {
            object.remove("authority_hints");
        }
    }
    let key = &fixture.keys[index];
    let jwk = must_some(FederationKeyManager::federation_public_jwk(key));
    let header = json!({
        "alg": FederationKeyManager::federation_alg(key),
        "typ": "entity-statement+jwt",
        "kid": jwk["kid"],
    });
    jwts[index * 2] = super::super::purpose::sign_with_header(key, &header, &payload);
}

fn assert_signatures_valid(fixture: &SignedPathFixture, jwts: &[String]) {
    for jwt in jwts.iter().step_by(2) {
        must_ok(verify_entity_configuration(jwt));
    }
    // Check both issuer configuration and superior-endorsed keys independently
    // of the graph relation, and keep the configured anchor signature valid.
    for (index, statement) in fixture.subordinates.iter().enumerate() {
        must_ok(verify_entity_statement(
            &jwts[index * 2 + 1],
            &must_ok(fixture.configs[index + 1].parse_jwks()),
        ));
        must_ok(verify_entity_statement(
            &jwts[index * 2],
            &must_ok(statement.parse_jwks()),
        ));
    }
    must_ok(verify_entity_statement(
        must_some(jwts.last().map(String::as_str)),
        &fixture.anchor.jwks,
    ));
}

fn assert_parent_relation_error<T: std::fmt::Debug>(result: Result<T, FederationError>) {
    assert!(matches!(
        must_err(result),
        FederationError::Validation(message)
            if message == "subordinate issuer is not in signed subject authority_hints"
    ));
}

#[test]
fn signed_parent_relation_accepts_multiple_hints_and_nonroot_anchor() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for intermediates in [0, 2] {
            let mut fixture = SignedPathFixture::new(intermediates);
            for index in 0..fixture.subordinates.len() {
                fixture.configs[index].authority_hints = Some(vec![
                    "https://unavailable.example.com".into(),
                    fixture.subordinates[index].iss.clone(),
                    "https://another.example.com".into(),
                ]);
            }
            must_some(fixture.configs.last_mut()).authority_hints =
                Some(vec!["https://above-configured-anchor.example.com".into()]);
            let leaf = &fixture.configs[0].iss;
            must_ok(verify_signed_path(
                &fixture.jwts(),
                leaf,
                &fixture.anchor,
                NOW,
            ));
            let fetcher = fixture.fetcher();
            let anchors = [fixture.anchor.clone()];
            must_ok(resolve_trust_chain(leaf, &anchors, &fetcher, NOW).await);
            must_ok(resolve_trust_chain_with_jwts(leaf, &anchors, &fetcher, NOW).await);
        }
    });
}

#[test]
fn signed_parent_relation_rejects_each_subject_despite_valid_signatures() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let fixture = SignedPathFixture::new(2);
        let leaf = &fixture.configs[0].iss;
        for index in 0..fixture.subordinates.len() {
            let parent = &fixture.subordinates[index].iss;
            for hints in [
                None,
                Some(Value::Null),
                Some(json!([])),
                Some(json!(["https://unrelated.example.com"])),
                Some(json!([parent.to_uppercase()])),
                Some(json!([format!("{parent}/")])),
            ] {
                let mut jwts = fixture.jwts();
                replace_signed_hints(&fixture, &mut jwts, index, hints);
                assert_signatures_valid(&fixture, &jwts);
                assert_parent_relation_error(verify_signed_path(&jwts, leaf, &fixture.anchor, NOW));

                // Discovery sees plausible detached hints. Neither public
                // resolver may let them repair a different signed payload.
                let mut fetcher = fixture.fetcher();
                fetcher.add_entity_config_with_jws(
                    &fixture.configs[index].iss,
                    fixture.configs[index].clone(),
                    jwts[index * 2].clone(),
                );
                let anchors = [fixture.anchor.clone()];
                assert!(resolve_trust_chain(leaf, &anchors, &fetcher, NOW)
                    .await
                    .is_err());
                assert!(resolve_trust_chain_with_jwts(leaf, &anchors, &fetcher, NOW)
                    .await
                    .is_err());
            }
        }
    });
}

#[derive(Default)]
struct ObservedCache {
    inner: InMemoryTrustChainCacheRepo,
    writes: AtomicUsize,
}

impl TrustChainCacheRepository for ObservedCache {
    fn get<'a>(
        &'a self,
        environment_id: Uuid,
        leaf_entity_id: &'a str,
        anchor_entity_id: &'a str,
        now: i64,
    ) -> CacheFuture<'a, Option<StoredTrustChain>> {
        Box::pin(async move {
            self.inner
                .get(environment_id, leaf_entity_id, anchor_entity_id, now)
        })
    }

    fn upsert<'a>(
        &'a self,
        environment_id: Uuid,
        leaf_entity_id: &'a str,
        anchor_entity_id: &'a str,
        jwts: &'a Value,
        expires_at: i64,
    ) -> CacheFuture<'a, ()> {
        Box::pin(async move {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.inner.upsert(
                environment_id,
                leaf_entity_id,
                anchor_entity_id,
                jwts,
                expires_at,
            )
        })
    }

    fn cleanup_expired(&self, now: i64) -> CacheFuture<'_, u64> {
        Box::pin(async move { self.inner.cleanup_expired(now) })
    }
}

#[test]
fn signed_parent_relation_rejects_forged_fresh_callback_without_cache_write() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let fixture = SignedPathFixture::new(2);
        for index in 0..fixture.subordinates.len() {
            let cache = ObservedCache::default();
            let env_id = Uuid::new_v4();
            let result = resolve_trust_chain_jwts_cached_with(
                &fixture.configs[0].iss,
                env_id,
                vec![fixture.anchor.clone()],
                &cache,
                &FederationCacheConfig::default(),
                NOW,
                |_| {
                    let mut resolved = fixture.detached();
                    replace_signed_hints(&fixture, &mut resolved.chain_jwts, index, None);
                    async move { Ok(resolved) }
                },
            )
            .await;
            assert_parent_relation_error(result);
            assert_eq!(cache.writes.load(Ordering::SeqCst), 0);
            assert!(must_ok(cache.inner.get(
                env_id,
                &fixture.configs[0].iss,
                &fixture.anchor.entity_id,
                NOW
            ))
            .is_none());
        }
    });
}

#[test]
fn signed_parent_relation_uses_valid_raw_hints_on_fresh_callback_and_cache_hit() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let fixture = SignedPathFixture::new(2);
        let cache = ObservedCache::default();
        let env_id = Uuid::new_v4();
        let calls = AtomicUsize::new(0);
        for _ in 0..2 {
            let resolved = must_ok(
                resolve_trust_chain_jwts_cached_with(
                    &fixture.configs[0].iss,
                    env_id,
                    vec![fixture.anchor.clone()],
                    &cache,
                    &FederationCacheConfig::default(),
                    NOW,
                    |_| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        let mut detached = fixture.detached();
                        for config in detached.trust_chain.chain.iter_mut().step_by(2) {
                            config.authority_hints = None;
                        }
                        async move { Ok(detached) }
                    },
                )
                .await,
            );
            for index in 0..fixture.subordinates.len() {
                assert_eq!(
                    resolved.trust_chain.chain[index * 2].authority_hints,
                    fixture.configs[index].authority_hints
                );
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache.writes.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn signed_parent_relation_invalid_cache_falls_back_and_only_writes_valid_fresh_path() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let fixture = SignedPathFixture::new(2);
        for index in 0..fixture.subordinates.len() {
            for fresh_valid in [false, true] {
                let cache = ObservedCache::default();
                let env_id = Uuid::new_v4();
                let mut invalid = fixture.jwts();
                replace_signed_hints(&fixture, &mut invalid, index, Some(json!([])));
                must_ok(cache.inner.upsert(
                    env_id,
                    &fixture.configs[0].iss,
                    &fixture.anchor.entity_id,
                    &json!(invalid),
                    NOW + 3600,
                ));
                let calls = AtomicUsize::new(0);
                let result = resolve_trust_chain_jwts_cached_with(
                    &fixture.configs[0].iss,
                    env_id,
                    vec![fixture.anchor.clone()],
                    &cache,
                    &FederationCacheConfig::default(),
                    NOW,
                    |_| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        let mut resolved = fixture.detached();
                        if !fresh_valid {
                            resolved.chain_jwts = invalid.clone();
                        }
                        async move { Ok(resolved) }
                    },
                )
                .await;
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert_eq!(
                    cache.writes.load(Ordering::SeqCst),
                    usize::from(fresh_valid)
                );
                if fresh_valid {
                    must_ok(result);
                    let cached = must_some(must_ok(cache.inner.get(
                        env_id,
                        &fixture.configs[0].iss,
                        &fixture.anchor.entity_id,
                        NOW,
                    )));
                    must_ok(reconstruct_chain_from_cache(&cached, &fixture.anchor, NOW));
                } else {
                    assert_parent_relation_error(result);
                }
            }
        }
    });
}
