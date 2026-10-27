use super::signed_parent::ObservedCache;
use crate::federation::trust_chain::verify_signed_path;
use std::sync::atomic::{AtomicUsize, Ordering};

fn set_types(fixture: &mut SignedPathFixture, index: usize, allowed: &[&str]) {
    fixture.subordinates[index].constraints = Some(Constraints {
        allowed_entity_types: Some(allowed.iter().map(|value| (*value).into()).collect()),
        ..Constraints::default()
    });
}

fn metadata(value: Value) -> HashMap<String, Value> {
    must_ok(serde_json::from_value(value))
}

#[test]
fn signed_entity_type_filters_accumulate_without_rewriting_statements() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for intermediates in [0, 2] {
            for allowed in [
                None,
                Some(vec![]),
                Some(vec!["Custom", "Custom"]),
                Some(vec!["custom"]),
            ] {
                let mut fixture = SignedPathFixture::new(intermediates);
                fixture.configs[0].metadata = Some(metadata(
                    json!({"federation_entity":{},"Custom":{},"custom":{},"openid_relying_party":{}}),
                ));
                if let Some(allowed) = &allowed {
                    set_types(&mut fixture, 0, allowed);
                }
                let resolved = must_ok(
                    resolve_trust_chain_with_jwts(
                        &fixture.configs[0].iss,
                        &[fixture.anchor.clone()],
                        &fixture.fetcher(),
                        NOW,
                    )
                    .await,
                );
                let derived = must_some(must_ok(resolved.trust_chain.resolved_metadata()));
                for name in ["Custom", "custom", "openid_relying_party"] {
                    assert_eq!(
                        derived.contains_key(name),
                        allowed.as_ref().is_none_or(|types| types.contains(&name))
                    );
                }
                assert!(derived.contains_key("federation_entity"));
                assert_eq!(
                    resolved.trust_chain.chain[0].metadata,
                    fixture.configs[0].metadata
                );
                for (raw, statement) in resolved.chain_jwts.iter().zip(&resolved.trust_chain.chain)
                {
                    assert_eq!(
                        must_ok(serde_json::to_value(must_ok(
                            parse_entity_statement_unverified(raw)
                        ))),
                        must_ok(serde_json::to_value(statement))
                    );
                }
            }
        }
        for upper in [vec!["Custom", "another"], vec!["other"]] {
            let mut fixture = SignedPathFixture::new(2);
            fixture.configs[0].metadata = Some(metadata(
                json!({"federation_entity":{},"Custom":{},"other":{}}),
            ));
            set_types(&mut fixture, 0, &["Custom", "other"]);
            set_types(&mut fixture, 2, &upper);
            let chain = must_ok(verify_signed_path(
                &fixture.jwts(),
                &fixture.configs[0].iss,
                &fixture.anchor,
                NOW,
            ));
            let result = must_some(must_ok(chain.resolved_metadata()));
            assert_eq!(result.contains_key("Custom"), upper.contains(&"Custom"));
            assert_eq!(result.contains_key("other"), upper.contains(&"other"));
            assert!(result.contains_key("federation_entity"));
        }
        let mut disjoint = SignedPathFixture::new(1);
        set_types(&mut disjoint, 0, &["openid_relying_party"]);
        set_types(&mut disjoint, 1, &["other"]);
        let chain = must_ok(verify_signed_path(
            &disjoint.jwts(),
            &disjoint.configs[0].iss,
            &disjoint.anchor,
            NOW,
        ));
        let result = must_some(must_ok(chain.resolved_metadata()));
        assert_eq!(result.keys().collect::<Vec<_>>(), vec!["federation_entity"]);
    });
}

#[test]
fn entity_type_filter_preserves_overlay_policy_and_absence_order() {
    let _guard = raw_json_env_guard();
    let mut fixture = SignedPathFixture::new(1);
    fixture.configs[0].metadata = Some(metadata(json!({"keep":{"x":"leaf"},"remove":{}})));
    fixture.subordinates[0].metadata = Some(metadata(
        json!({"keep":{"x":"overlay"},"invented":{"x":"not-declared"}}),
    ));
    fixture.subordinates[1].metadata_policy = Some(metadata(
        json!({"keep":{"x":{"one_of":["overlay"]}},"remove":{"must_not_apply":{"essential":true}},"invented":{"x":{"value":"policy"}}}),
    ));
    set_types(&mut fixture, 0, &["keep", "invented"]);
    let chain = must_ok(verify_signed_path(
        &fixture.jwts(),
        &fixture.configs[0].iss,
        &fixture.anchor,
        NOW,
    ));
    assert_eq!(
        must_some(must_ok(chain.resolved_metadata())),
        metadata(json!({"keep":{"x":"overlay"}}))
    );
    fixture.subordinates[1].metadata_policy = Some(metadata(json!({"remove":{"x":{"add":true}}})));
    assert!(verify_signed_path(
        &fixture.jwts(),
        &fixture.configs[0].iss,
        &fixture.anchor,
        NOW
    )
    .is_err());
    fixture.subordinates[1].metadata_policy = None;
    set_types(&mut fixture, 0, &[]);
    let chain = must_ok(verify_signed_path(
        &fixture.jwts(),
        &fixture.configs[0].iss,
        &fixture.anchor,
        NOW,
    ));
    assert_eq!(chain.resolved_metadata().unwrap(), Some(HashMap::new()));
    fixture.configs[0].metadata = None;
    let chain = must_ok(verify_signed_path(
        &fixture.jwts(),
        &fixture.configs[0].iss,
        &fixture.anchor,
        NOW,
    ));
    assert!(must_ok(chain.resolved_metadata()).is_none());
    set_types(&mut fixture, 1, &["federation_entity"]);
    assert!(fixture.detached().trust_chain.resolved_metadata().is_err());
    assert!(validate_entity_statement(&fixture.subordinates[1], NOW).is_err());
    assert!(verify_signed_path(
        &fixture.jwts(),
        &fixture.configs[0].iss,
        &fixture.anchor,
        NOW
    )
    .is_err());
}

#[test]
fn standard_filter_and_local_leaf_predicate_have_distinct_effects() {
    let _guard = raw_json_env_guard();
    let mut fixture = SignedPathFixture::new(1);
    fixture.configs[0].metadata = Some(metadata(json!({"first":{},"second":{}})));
    set_types(&mut fixture, 1, &["second"]);
    fixture.subordinates[1]
        .constraints
        .as_mut()
        .unwrap()
        .allowed_leaf_entity_types = Some(vec!["first".into()]);
    let chain = must_ok(verify_signed_path(
        &fixture.jwts(),
        &fixture.configs[0].iss,
        &fixture.anchor,
        NOW,
    ));
    assert_eq!(
        must_some(must_ok(chain.resolved_metadata())),
        metadata(json!({"second":{}}))
    );
    for local in [vec![], vec!["absent".into()]] {
        fixture.subordinates[1]
            .constraints
            .as_mut()
            .unwrap()
            .allowed_leaf_entity_types = Some(local);
        assert!(verify_signed_path(
            &fixture.jwts(),
            &fixture.configs[0].iss,
            &fixture.anchor,
            NOW
        )
        .is_err());
    }
}

#[test]
fn entity_type_cache_uses_raw_filters_and_rejects_invalid_fresh_repair() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let mut fixture = SignedPathFixture::new(1);
        set_types(&mut fixture, 1, &[]);
        let valid = fixture.detached();
        let cache = ObservedCache::default();
        let env = Uuid::new_v4();
        let mut forged = valid.clone();
        forged.trust_chain.chain[3].constraints = None;
        let accepted = must_ok(
            resolve_trust_chain_jwts_cached_with(
                &fixture.configs[0].iss,
                env,
                vec![fixture.anchor.clone()],
                &cache,
                &FederationCacheConfig::default(),
                NOW,
                |_| std::future::ready(Ok(forged.clone())),
            )
            .await,
        );
        assert!(
            !must_some(must_ok(accepted.trust_chain.resolved_metadata()))
                .contains_key("openid_relying_party")
        );
        let cached = must_ok(
            resolve_trust_chain_jwts_cached_with(
                &fixture.configs[0].iss,
                env,
                vec![fixture.anchor.clone()],
                &cache,
                &FederationCacheConfig::default(),
                NOW,
                |_| async { panic!("valid raw cache should be used") },
            )
            .await,
        );
        assert!(!must_some(must_ok(cached.trust_chain.resolved_metadata()))
            .contains_key("openid_relying_party"));
        set_types(&mut fixture, 1, &["federation_entity"]);
        let mut invalid = fixture.detached();
        // Detached JSON cannot repair the invalid field in retained signed bytes.
        invalid.trust_chain.chain[3].constraints = None;
        for valid_fresh in [false, true] {
            let cache = ObservedCache::default();
            let env = Uuid::new_v4();
            must_ok(cache.inner.upsert(
                env,
                &fixture.configs[0].iss,
                &fixture.anchor.entity_id,
                &json!(invalid.chain_jwts),
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
            let after = must_some(must_ok(cache.inner.get(
                env,
                &fixture.configs[0].iss,
                &fixture.anchor.entity_id,
                NOW,
            )));
            if !valid_fresh {
                assert_eq!(before.chain_jwts, after.chain_jwts);
                assert_eq!(before.expires_at, after.expires_at);
            }
        }
    });
}
