use super::signed_parent::ObservedCache;
use crate::federation::trust_chain::verify_signed_path;
use std::sync::atomic::{AtomicUsize, Ordering};

fn replace_claims(
    fixture: &SignedPathFixture,
    jwts: &mut [String],
    index: usize,
    edit: impl FnOnce(&mut Value),
) {
    let parsed = must_ok(Jws::from_compact(&jwts[index]));
    let mut claims: Value = must_ok(serde_json::from_slice(&parsed.payload));
    edit(&mut claims);
    let key = &fixture.keys[index.div_ceil(2)];
    let header: Value = must_ok(serde_json::from_slice(&must_ok(
        URL_SAFE_NO_PAD.decode(must_some(jwts[index].split('.').next())),
    )));
    jwts[index] = super::super::purpose::sign_with_header(key, &header, &claims);
    assert_federation_signature_only(&jwts[index], key);
}

#[test]
fn superior_profile_requires_own_signed_fetch_and_list_on_every_edge() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for intermediates in [0, 2] {
            let mut fixture = SignedPathFixture::new(intermediates);
            must_some(fixture.configs.last_mut()).authority_hints =
                Some(vec!["https://higher.example".into()]);
            // First entity may itself have subordinates; terminal anchor need not be rootless.
            must_ok(verify_signed_path(
                &fixture.jwts(),
                &fixture.configs[0].iss,
                &fixture.anchor,
                NOW,
            ));
            for config_index in 1..fixture.configs.len() {
                for field in [
                    "federation_entity",
                    "federation_fetch_endpoint",
                    "federation_list_endpoint",
                ] {
                    let mut jwts = fixture.jwts();
                    replace_claims(&fixture, &mut jwts, config_index * 2, |claims| {
                        let metadata = must_some(claims["metadata"].as_object_mut());
                        if field == "federation_entity" {
                            metadata.remove(field);
                        } else {
                            must_some(metadata["federation_entity"].as_object_mut()).remove(field);
                        }
                    });
                    // These are valid standalone statements, but invalid in the known superior role.
                    must_ok(verify_entity_configuration(&jwts[config_index * 2]));
                    assert!(must_err(verify_signed_path(
                        &jwts,
                        &fixture.configs[0].iss,
                        &fixture.anchor,
                        NOW
                    ))
                    .to_string()
                    .contains("superior"));
                    let mut fetcher = fixture.fetcher();
                    fetcher.add_entity_config_with_jws(
                        &fixture.configs[config_index].iss,
                        fixture.configs[config_index].clone(),
                        jwts[config_index * 2].clone(),
                    );
                    assert!(resolve_trust_chain_with_jwts(
                        &fixture.configs[0].iss,
                        &[fixture.anchor.clone()],
                        &fetcher,
                        NOW
                    )
                    .await
                    .is_err());
                    // Endpoints carried by an S cannot repair a missing own configuration.
                    replace_claims(&fixture, &mut jwts, config_index * 2 - 1, |claims| {
                        claims["metadata"]["federation_entity"] = json!({"federation_fetch_endpoint":"https://sup.example/fetch", "federation_list_endpoint":"https://sup.example/list"});
                    });
                    assert!(verify_signed_path(
                        &jwts,
                        &fixture.configs[0].iss,
                        &fixture.anchor,
                        NOW
                    )
                    .is_err());
                }
            }
        }
    });
}

#[test]
fn profile_invalid_cache_falls_back_and_fresh_callbacks_cannot_repair_signed_claims() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let fixture = SignedPathFixture::new(2);
        for index in 0..fixture.jwts().len() {
            for role_error in [false, true] {
                if role_error && (index == 0 || index % 2 != 0) {
                    continue;
                }
                let mut invalid = fixture.jwts();
                replace_claims(&fixture, &mut invalid, index, |claims| {
                    if role_error {
                        must_some(claims["metadata"]["federation_entity"].as_object_mut())
                            .remove("federation_list_endpoint");
                    } else {
                        claims["crit"] = Value::Null;
                    }
                });
                for fresh_valid in [false, true] {
                    let cache = ObservedCache::default();
                    let env_id = Uuid::new_v4();
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
                    assert_eq!(result.is_ok(), fresh_valid);
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                    assert_eq!(
                        cache.writes.load(Ordering::SeqCst),
                        usize::from(fresh_valid)
                    );
                    let stored = must_some(must_ok(cache.inner.get(
                        env_id,
                        &fixture.configs[0].iss,
                        &fixture.anchor.entity_id,
                        NOW,
                    )));
                    if fresh_valid {
                        must_ok(reconstruct_chain_from_cache(&stored, &fixture.anchor, NOW));
                    } else {
                        assert_eq!(stored.chain_jwts, json!(invalid));
                    }
                }
            }
        }
    });
}

fn valid_metadata_policy(fixture: &mut SignedPathFixture) {
    let policy = json!({"openid_provider":{"issuer":{"essential":false}}});
    for statement in &mut fixture.subordinates {
        statement.metadata_policy = Some(must_ok(serde_json::from_value(policy.clone())));
    }
    fixture.anchor.metadata_policy = Some(policy);
}

fn oidc_fixture() -> SignedPathFixture {
    let mut fixture = SignedPathFixture::new(2);
    valid_metadata_policy(&mut fixture);
    let issuer = fixture.configs[0].iss.clone();
    must_some(fixture.configs[0].metadata.as_mut())
        .insert("openid_provider".into(), json!({"issuer":issuer}));
    fixture
}

#[test]
fn oidc_web_context_rejects_core_extensions_at_every_position_on_fresh_and_cached_use() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let fixture = oidc_fixture();
        for index in 0..fixture.jwts().len() {
            for field in ["aud", "trust_anchor"] {
                for value in [Value::Null, json!("https://extension.example")] {
                    let mut raw = fixture.jwts();
                    replace_claims(&fixture, &mut raw, index, |claims| {
                        claims[field] = value;
                    });
                    let anchor_repo = InMemoryTrustAnchorRepo::new();
                    let env_id = Uuid::new_v4();
                    must_ok(anchor_repo.upsert(
                        env_id,
                        &fixture.anchor.entity_id,
                        must_some(must_some(fixture.configs.last()).jwks.as_ref()),
                        fixture.anchor.metadata_policy.as_ref(),
                    ));
                    let cache = ObservedCache::default();
                    let calls = AtomicUsize::new(0);
                    for _ in 0..2 {
                        let result = resolve_trust_chain_artifacts_cached_with(
                            &fixture.configs[0].iss,
                            env_id,
                            &anchor_repo,
                            &cache,
                            &FederationCacheConfig::default(),
                            NOW,
                            |_| {
                                calls.fetch_add(1, Ordering::SeqCst);
                                let mut resolved = fixture.detached();
                                resolved.chain_jwts = raw.clone();
                                async move { Ok(resolved) }
                            },
                        )
                        .await;
                        let core = must_ok(result);
                        assert_eq!(core.chain_jwts, raw);
                        assert!(crate::web::admit_upstream_federation_metadata(
                            Ok(core),
                            "https://local.example"
                        )
                        .is_err());
                    }
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                    assert_eq!(cache.writes.load(Ordering::SeqCst), 1);
                }
            }
        }
    });
}

#[test]
fn oidc_web_context_requires_signed_leaf_role_even_if_subordinate_supplies_it() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for signed_role in [false, true] {
            let mut fixture = SignedPathFixture::new(0);
            valid_metadata_policy(&mut fixture);
            if signed_role {
                must_some(fixture.configs[0].metadata.as_mut())
                    .insert("openid_provider".into(), json!({}));
            }
            fixture.subordinates[0].metadata = Some(HashMap::from([(
                "openid_provider".into(),
                json!({"issuer":fixture.configs[0].iss}),
            )]));
            let anchor_repo = InMemoryTrustAnchorRepo::new();
            let env_id = Uuid::new_v4();
            must_ok(anchor_repo.upsert(
                env_id,
                &fixture.anchor.entity_id,
                must_some(fixture.configs[1].jwks.as_ref()),
                fixture.anchor.metadata_policy.as_ref(),
            ));
            let cache = ObservedCache::default();
            let calls = AtomicUsize::new(0);
            for _ in 0..2 {
                let core = must_ok(
                    resolve_trust_chain_artifacts_cached_with(
                        &fixture.configs[0].iss,
                        env_id,
                        &anchor_repo,
                        &cache,
                        &FederationCacheConfig::default(),
                        NOW,
                        |_| {
                            calls.fetch_add(1, Ordering::SeqCst);
                            let resolved = fixture.detached();
                            async move { Ok(resolved) }
                        },
                    )
                    .await,
                );
                assert_eq!(
                    crate::web::admit_upstream_federation_metadata(
                        Ok(core),
                        "https://local.example"
                    )
                    .is_ok(),
                    signed_role
                );
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    });
}

#[test]
fn artifacts_repository_wrapper_preserves_missing_and_invalid_anchor_failures() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for invalid in [false, true] {
            let repo = InMemoryTrustAnchorRepo::new();
            let env_id = Uuid::new_v4();
            if invalid {
                must_ok(repo.upsert(
                    env_id,
                    "https://anchor.example",
                    &json!({"keys":[{"kty":"invalid"}]}),
                    None,
                ));
            }
            let calls = AtomicUsize::new(0);
            let result = resolve_trust_chain_artifacts_cached_with(
                "https://leaf.example",
                env_id,
                &repo,
                &InMemoryTrustChainCacheRepo::new(),
                &FederationCacheConfig::default(),
                NOW,
                |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Err(FederationError::Fetch("must not resolve".into())) }
                },
            )
            .await;
            assert!(result.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                crate::web::admit_upstream_federation_metadata(result, "https://local.example")
                    .is_err(),
                invalid
            );
        }
    });
}

#[test]
fn artifacts_repository_wrapper_preserves_anchor_order_and_cached_fallback() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let fixture = oidc_fixture();
        let repo = InMemoryTrustAnchorRepo::new();
        let env_id = Uuid::new_v4();
        let first = "https://first-anchor.example";
        must_ok(repo.upsert(env_id, first, &sample_jwks_value(), Some(&json!({}))));
        must_ok(repo.upsert(
            env_id,
            &fixture.anchor.entity_id,
            must_some(must_some(fixture.configs.last()).jwks.as_ref()),
            fixture.anchor.metadata_policy.as_ref(),
        ));
        let cache = ObservedCache::default();
        let observed = std::sync::Mutex::new(Vec::new());
        for _ in 0..2 {
            let core = must_ok(
                resolve_trust_chain_artifacts_cached_with(
                    &fixture.configs[0].iss,
                    env_id,
                    &repo,
                    &cache,
                    &FederationCacheConfig::default(),
                    NOW,
                    |anchors| {
                        assert_eq!(anchors.len(), 1);
                        must_ok(observed.lock()).push(anchors[0].entity_id.clone());
                        let result = if anchors[0].entity_id == first {
                            Err(FederationError::Fetch("first unavailable".into()))
                        } else {
                            Ok(fixture.detached())
                        };
                        async move { result }
                    },
                )
                .await,
            );
            assert_eq!(core.trust_chain.anchor.entity_id, fixture.anchor.entity_id);
            assert!(must_ok(crate::web::admit_upstream_federation_metadata(
                Ok(core),
                "https://local.example"
            ))
            .is_some());
        }
        assert_eq!(
            *must_ok(observed.lock()),
            vec![
                first.to_string(),
                fixture.anchor.entity_id.clone(),
                first.to_string()
            ]
        );
        assert_eq!(cache.writes.load(Ordering::SeqCst), 1);
    });
}
