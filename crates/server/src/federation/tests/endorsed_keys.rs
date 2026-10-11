const NOW: i64 = 1_700_000_000;

mod signed_parent {
    use super::*;
    include!("signed_parent.rs");
}

struct SignedPathFixture {
    keys: Vec<InMemoryKeyManager>,
    configs: Vec<EntityStatement>,
    subordinates: Vec<EntityStatement>,
    anchor: TrustAnchor,
}

impl SignedPathFixture {
    fn new(intermediates: usize) -> Self {
        let keys: Vec<_> = (0..intermediates + 2)
            .map(|_| InMemoryKeyManager::new())
            .collect();
        let mut configs: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let mut config =
                    sample_entity_config(&format!("https://entity-{index}.example.com"), NOW);
                config.jwks = Some(federation_jwks_value(key));
                config.authority_hints = None;
                config
            })
            .collect();
        let mut subordinates = Vec::new();
        for index in 0..configs.len() - 1 {
            let superior = configs[index + 1].iss.clone();
            configs[index].authority_hints = Some(vec![superior.clone()]);
            let mut statement = sample_subordinate_statement(&superior, &configs[index].iss, NOW);
            statement.jwks = configs[index].jwks.clone();
            subordinates.push(statement);
        }
        let last = must_some(configs.last());
        let anchor = TrustAnchor {
            entity_id: last.iss.clone(),
            jwks: must_ok(last.parse_jwks()),
            metadata_policy: None,
        };
        Self {
            keys,
            configs,
            subordinates,
            anchor,
        }
    }

    fn fetcher(&self) -> MockFetcher {
        let mut fetcher = MockFetcher::new();
        for (index, config) in self.configs.iter().enumerate() {
            fetcher.add_entity_config_with_jws(
                &config.iss,
                config.clone(),
                sign_entity_statement_for_test(&self.keys[index], config),
            );
        }
        for (index, stmt) in self.subordinates.iter().enumerate() {
            fetcher.add_subordinate_stmt_with_jws(
                &stmt.iss,
                &stmt.sub,
                stmt.clone(),
                sign_entity_statement_for_test(&self.keys[index + 1], stmt),
            );
        }
        fetcher
    }

    fn jwts(&self) -> Vec<String> {
        let mut jwts = vec![sign_entity_statement_for_test(
            &self.keys[0],
            &self.configs[0],
        )];
        for (index, stmt) in self.subordinates.iter().enumerate() {
            jwts.push(sign_entity_statement_for_test(&self.keys[index + 1], stmt));
            jwts.push(sign_entity_statement_for_test(
                &self.keys[index + 1],
                &self.configs[index + 1],
            ));
        }
        jwts
    }

    fn detached(&self) -> ResolvedTrustChain {
        let mut chain = vec![self.configs[0].clone()];
        for (index, statement) in self.subordinates.iter().enumerate() {
            chain.push(statement.clone());
            chain.push(self.configs[index + 1].clone());
        }
        ResolvedTrustChain::new(
            TrustChain {
                chain,
                anchor: self.anchor.clone(),
            },
            self.jwts(),
        )
    }

    fn replace_unendorsed_key(&mut self, index: usize) {
        self.keys[index] = InMemoryKeyManager::new();
        self.configs[index].jwks = Some(federation_jwks_value(&self.keys[index]));
    }
}

#[test]
fn endorsed_direct_and_multiple_intermediate_paths_resolve() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for intermediates in 0..=2 {
            let fixture = SignedPathFixture::new(intermediates);
            let fetcher = fixture.fetcher();
            let anchors = [fixture.anchor.clone()];
            let chain = must_ok(
                resolve_trust_chain(&fixture.configs[0].iss, &anchors, &fetcher, NOW).await,
            );
            assert_eq!(chain.chain.len(), 3 + 2 * intermediates);
            let resolved = must_ok(
                resolve_trust_chain_with_jwts(&fixture.configs[0].iss, &anchors, &fetcher, NOW)
                    .await,
            );
            assert_eq!(resolved.chain_jwts.len(), 3 + 2 * intermediates);
        }
    });
}

#[test]
fn unendorsed_leaf_and_intermediate_signing_keys_fail_both_resolvers() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for index in 0..=2 {
            let mut fixture = SignedPathFixture::new(2);
            fixture.replace_unendorsed_key(index);
            let fetcher = fixture.fetcher();
            // Every discovery self-signature and lower signature under the
            // self-published key is valid; only the superior endorsement is broken.
            for jwt in fetcher.entity_config_jwts.values() {
                must_ok(verify_entity_configuration(jwt));
            }
            for ((issuer, _), jwt) in &fetcher.subordinate_stmt_jwts {
                let config = must_some(fetcher.entity_configs.get(issuer));
                must_ok(verify_entity_statement(jwt, &must_ok(config.parse_jwks())));
            }
            let anchors = [fixture.anchor.clone()];
            assert!(
                resolve_trust_chain(&fixture.configs[0].iss, &anchors, &fetcher, NOW)
                    .await
                    .is_err()
            );
            assert!(resolve_trust_chain_with_jwts(
                &fixture.configs[0].iss,
                &anchors,
                &fetcher,
                NOW
            )
            .await
            .is_err());
        }
    });
}

#[test]
fn anchor_configuration_must_use_current_configured_key() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let mut fixture = SignedPathFixture::new(0);
        // Keep the anchor's subordinate statement signed by the configured key while
        // replacing only the anchor configuration with another valid self-signature.
        let mut fetcher = fixture.fetcher();
        fixture.replace_unendorsed_key(1);
        fetcher.add_entity_config_with_jws(
            &fixture.anchor.entity_id,
            fixture.configs[1].clone(),
            sign_entity_statement_for_test(&fixture.keys[1], &fixture.configs[1]),
        );
        assert!(
            resolve_trust_chain(&fixture.configs[0].iss, &[fixture.anchor], &fetcher, NOW)
                .await
                .is_err()
        );
    });
}

#[test]
fn endorsed_key_overlap_allows_different_discovery_jwks_sets() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let mut fixture = SignedPathFixture::new(1);
        let extra = federation_jwks_value(&InMemoryKeyManager::new());
        let jwks = must_some(fixture.configs[1].jwks.as_mut());
        must_some(jwks["keys"].as_array_mut()).push(extra["keys"][0].clone());
        let fetcher = fixture.fetcher();
        must_ok(
            resolve_trust_chain(&fixture.configs[0].iss, &[fixture.anchor], &fetcher, NOW).await,
        );
    });
}

#[test]
fn invalid_endorsement_backtracks_to_later_authority_hint() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let mut fixture = SignedPathFixture::new(1);
        fixture.replace_unendorsed_key(1);
        must_some(fixture.configs[0].authority_hints.as_mut())
            .push(fixture.anchor.entity_id.clone());
        let mut direct =
            sample_subordinate_statement(&fixture.anchor.entity_id, &fixture.configs[0].iss, NOW);
        direct.jwks = fixture.configs[0].jwks.clone();
        let mut fetcher = fixture.fetcher();
        fetcher.add_subordinate_stmt_with_jws(
            &direct.iss,
            &direct.sub,
            direct.clone(),
            sign_entity_statement_for_test(&fixture.keys[2], &direct),
        );
        let resolved = must_ok(
            resolve_trust_chain_with_jwts(
                &fixture.configs[0].iss,
                &[fixture.anchor],
                &fetcher,
                NOW,
            )
            .await,
        );
        assert_eq!(resolved.trust_chain.chain.len(), 3);
        assert_eq!(resolved.chain_jwts.len(), 3);
    });
}

#[test]
fn missing_or_invalid_endorsed_jwks_fail_closed() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for jwks in [
            None,
            Some(json!({"keys": []})),
            Some(json!({"keys": [{"kty": "EC"}]})),
        ] {
            let mut fixture = SignedPathFixture::new(1);
            fixture.subordinates[1].jwks = jwks;
            assert!(resolve_trust_chain(
                &fixture.configs[0].iss,
                &[fixture.anchor.clone()],
                &fixture.fetcher(),
                NOW
            )
            .await
            .is_err());
        }
    });
}

#[test]
fn decoded_only_fetcher_explicitly_fails_missing_jws() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let fixture = SignedPathFixture::new(0);
        let fetcher = DecodedOnlyFetcher(fixture.fetcher());
        let error = must_err(
            resolve_trust_chain(&fixture.configs[0].iss, &[fixture.anchor], &fetcher, NOW).await,
        );
        assert!(error.to_string().contains("did not retain compact JWS"));
    });
}

#[test]
fn fresh_cache_callback_canonicalizes_detached_metadata_from_signed_bytes() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let fixture = SignedPathFixture::new(1);
        let cache = InMemoryTrustChainCacheRepo::new();
        let env_id = Uuid::new_v4();
        let resolved = must_ok(
            resolve_trust_chain_jwts_cached_with(
                &fixture.configs[0].iss,
                env_id,
                vec![fixture.anchor.clone()],
                &cache,
                &FederationCacheConfig::default(),
                NOW,
                |_| {
                    let mut forged = fixture.detached();
                    forged.trust_chain.chain[0].metadata = Some(HashMap::from([(
                        "openid_relying_party".to_string(),
                        json!({"forged": true}),
                    )]));
                    forged.trust_chain.anchor.entity_id = "https://forged.example.com".into();
                    async move { Ok(forged) }
                },
            )
            .await,
        );
        assert_eq!(
            must_ok(resolved.trust_chain.leaf()).metadata,
            fixture.configs[0].metadata
        );
        assert_eq!(
            resolved.trust_chain.anchor.entity_id,
            fixture.anchor.entity_id
        );
        assert!(must_ok(cache.get(
            env_id,
            &fixture.configs[0].iss,
            &fixture.anchor.entity_id,
            NOW
        ))
        .is_some());
    });
}

#[test]
fn fresh_cache_callback_rejects_invalid_signature_and_wrong_leaf() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for wrong_leaf in [false, true] {
            let fixture = SignedPathFixture::new(0);
            let cache = InMemoryTrustChainCacheRepo::new();
            let env_id = Uuid::new_v4();
            let leaf_id = if wrong_leaf {
                "https://wrong.example.com"
            } else {
                &fixture.configs[0].iss
            };
            let result = resolve_trust_chain_jwts_cached_with(
                leaf_id,
                env_id,
                vec![fixture.anchor.clone()],
                &cache,
                &FederationCacheConfig::default(),
                NOW,
                |_| {
                    let mut resolved = fixture.detached();
                    if !wrong_leaf {
                        resolved.chain_jwts[1].push('A');
                    }
                    async move { Ok(resolved) }
                },
            )
            .await;
            assert!(result.is_err());
            assert!(must_ok(cache.get(env_id, leaf_id, &fixture.anchor.entity_id, NOW)).is_none());
        }
    });
}

#[test]
fn cached_path_rechecks_endorsements_and_current_anchor_keys() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for attack in 0..3 {
            let mut fixture = SignedPathFixture::new(1);
            if attack == 0 {
                fixture.replace_unendorsed_key(1);
            }
            let cache = InMemoryTrustChainCacheRepo::new();
            let env_id = Uuid::new_v4();
            let mut jwts = fixture.jwts();
            if attack == 1 {
                jwts[1].push('A');
            }
            must_ok(cache.upsert(
                env_id,
                &fixture.configs[0].iss,
                &fixture.anchor.entity_id,
                &json!(jwts),
                NOW + 3600,
            ));
            if attack == 2 {
                fixture.anchor.jwks = must_ok(JwkSet::from_value(federation_jwks_value(
                    &InMemoryKeyManager::new(),
                )));
            }
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let result = resolve_trust_chain_jwts_cached_with(
                &fixture.configs[0].iss,
                env_id,
                vec![fixture.anchor],
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
        }
    });
}

struct DecodedOnlyFetcher(MockFetcher);

impl FederationFetcher for DecodedOnlyFetcher {
    fn fetch_entity_configuration<'a>(
        &'a self,
        entity_id: &'a str,
    ) -> FederationFetchFuture<'a, EntityStatement> {
        self.0.fetch_entity_configuration(entity_id)
    }

    fn fetch_subordinate_statement<'a>(
        &'a self,
        authority_entity_id: &'a str,
        authority_config: &'a EntityStatement,
        subordinate_entity_id: &'a str,
        issuer_jwks: &'a JwkSet,
    ) -> FederationFetchFuture<'a, EntityStatement> {
        self.0.fetch_subordinate_statement(
            authority_entity_id,
            authority_config,
            subordinate_entity_id,
            issuer_jwks,
        )
    }
}

#[test]
fn disjoint_issuer_configuration_keys_fail_resolution_and_cache() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for issuer_index in 1..=2 {
            let mut fixture = SignedPathFixture::new(1);
            let mut fetcher = fixture.fetcher();
            let mut jwts = fixture.jwts();
            let new_key = InMemoryKeyManager::new();
            let new_jwks = federation_jwks_value(&new_key);
            let issuer_config = &mut fixture.configs[issuer_index];
            issuer_config.jwks = Some(new_jwks.clone());
            let config_jws = sign_entity_statement_for_test(&new_key, issuer_config);
            if issuer_index == 2 {
                // Both anchor configuration and subordinate signatures remain
                // valid under configured anchor keys, but the configuration
                // no longer publishes the subordinate's actual signing key.
                let mut anchor_keys = federation_jwks_value(&fixture.keys[2]);
                must_some(anchor_keys["keys"].as_array_mut()).push(new_jwks["keys"][0].clone());
                fixture.anchor.jwks = must_ok(JwkSet::from_value(anchor_keys));
            }
            must_ok(verify_entity_configuration(&config_jws));
            fetcher.add_entity_config_with_jws(
                &issuer_config.iss,
                issuer_config.clone(),
                config_jws.clone(),
            );
            jwts[issuer_index * 2] = config_jws;
            let leaf_id = &fixture.configs[0].iss;
            let anchors = [fixture.anchor.clone()];
            assert!(resolve_trust_chain(leaf_id, &anchors, &fetcher, NOW)
                .await
                .is_err());
            assert!(
                resolve_trust_chain_with_jwts(leaf_id, &anchors, &fetcher, NOW)
                    .await
                    .is_err()
            );

            let cache = InMemoryTrustChainCacheRepo::new();
            let env_id = Uuid::new_v4();
            must_ok(cache.upsert(
                env_id,
                leaf_id,
                &fixture.anchor.entity_id,
                &json!(jwts),
                NOW + 3600,
            ));
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let result = resolve_trust_chain_jwts_cached_with(
                leaf_id,
                env_id,
                anchors.to_vec(),
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
                anchors.to_vec(),
                &fresh_cache,
                &FederationCacheConfig::default(),
                NOW,
                |_| {
                    let mut resolved = fixture.detached();
                    resolved.chain_jwts = jwts.clone();
                    async move { Ok(resolved) }
                },
            )
            .await;
            assert!(result.is_err());
            assert!(
                must_ok(fresh_cache.get(env_id, leaf_id, &fixture.anchor.entity_id, NOW)).is_none()
            );
        }
    });
}

mod statement_profile {
    use super::*;
    include!("statement_profile.rs");
}

#[test]
fn signed_policy_resolution_preserves_raw_direct_and_multi_edge_paths() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for intermediates in 0..=2 {
            let mut fixture = SignedPathFixture::new(intermediates);
            let policy = json!({"openid_relying_party":{"grant_types":{"subset_of":["authorization_code"]}}});
            for statement in &mut fixture.subordinates {
                statement.metadata_policy = Some(must_ok(serde_json::from_value(policy.clone())));
            }
            fixture.anchor.metadata_policy = Some(policy);
            fixture.subordinates[0].metadata = Some(HashMap::from([(
                "openid_relying_party".into(),
                json!({"grant_types":["authorization_code","implicit"],"client_name":"immediate"}),
            )]));
            let fetcher = fixture.fetcher();
            let result = must_ok(
                resolve_trust_chain_with_jwts(
                    &fixture.configs[0].iss,
                    &[fixture.anchor.clone()],
                    &fetcher,
                    NOW,
                )
                .await,
            );
            let before = result.chain_jwts.clone();
            let raw_claims = must_ok(serde_json::to_value(&result.trust_chain.chain));
            let metadata = must_some(must_ok(result.trust_chain.resolved_metadata()));
            assert_eq!(
                metadata["openid_relying_party"]["grant_types"],
                json!(["authorization_code"])
            );
            assert_eq!(
                metadata["openid_relying_party"]["client_name"],
                json!("immediate")
            );
            assert_eq!(result.chain_jwts, before);
            assert_eq!(
                must_ok(serde_json::to_value(&result.trust_chain.chain)),
                raw_claims
            );
        }
    });
}

#[test]
fn signed_policy_resolution_rejects_conflicts_before_return() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let mut fixture = SignedPathFixture::new(1);
        let upper = json!({"openid_relying_party":{"client_name":{"value":"upper"}}});
        let lower = json!({"openid_relying_party":{"client_name":{"value":"lower"}}});
        fixture.anchor.metadata_policy = Some(upper.clone());
        fixture.subordinates[1].metadata_policy = Some(must_ok(serde_json::from_value(upper)));
        fixture.subordinates[0].metadata_policy = Some(must_ok(serde_json::from_value(lower)));
        let cache = signed_parent::ObservedCache::default();
        assert!(resolve_trust_chain_jwts_cached_with(
            &fixture.configs[0].iss,
            Uuid::new_v4(),
            vec![fixture.anchor.clone()],
            &cache,
            &FederationCacheConfig::default(),
            NOW,
            |_| std::future::ready(Ok(fixture.detached()))
        )
        .await
        .is_err());
        assert_eq!(cache.writes.load(std::sync::atomic::Ordering::SeqCst), 0);
        let result = resolve_trust_chain_with_jwts(
            &fixture.configs[0].iss,
            &[fixture.anchor.clone()],
            &fixture.fetcher(),
            NOW,
        )
        .await;
        assert!(result.is_err());
    });
}

mod chain_policy_admission {
    use super::*;
    include!("chain_policy_admission.rs");
}

mod entity_type_constraints {
    use super::*;
    include!("entity_type_constraints.rs");
}

mod critical_policy {
    use super::*;
    include!("critical_policy.rs");
}

mod naming_constraints {
    use super::*;
    include!("naming_constraints.rs");
}
