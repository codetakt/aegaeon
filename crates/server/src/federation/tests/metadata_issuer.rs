use super::signed_parent::ObservedCache;
use std::sync::atomic::{AtomicUsize, Ordering};

const ROLES: [&str; 2] = ["openid_provider", "oauth_authorization_server"];

fn metadata(role: &str, value: Value) -> Option<HashMap<String, Value>> {
    Some(HashMap::from([(role.into(), value)]))
}

fn assert_issuer_error(error: FederationError, role: &str) {
    assert!(matches!(error, FederationError::Validation(ref message)
        if message == &format!("invalid {role} metadata field issuer")));
}

#[test]
fn supplied_issuer_signed_admission_binds_subject_exactly_for_both_roles() {
    let _guard = raw_json_env_guard();
    let subject = "https://subject.example/path";
    for role in ROLES {
        for configuration in [false, true] {
            for (value, allowed) in [
                (json!({}), true),
                (json!({"issuer":subject}), true),
                (json!({"issuer":"https://superior.example"}), false),
                (json!({"issuer":"https://foreign.example"}), false),
                (json!({"issuer":"https://subject.example/path/"}), false),
                (json!({"issuer":"https://SUBJECT.example/path"}), false),
                (json!({"issuer":"https://subject.example/%70ath"}), false),
                (json!({"issuer":" https://subject.example/path"}), false),
                (json!({"issuer":"https://subject.example/path "}), false),
                (json!({"issuer":""}), false),
                (json!({"issuer":null}), false),
                (json!({"issuer":true}), false),
                (json!({"issuer":12}), false),
                (json!({"issuer":[]}), false),
                (json!({"issuer":{}}), false),
            ] {
                let mut statement = if configuration {
                    sample_entity_config(subject, NOW)
                } else {
                    sample_subordinate_statement("https://superior.example", subject, NOW)
                };
                statement.metadata = metadata(role, value);
                let original = must_ok(serde_json::to_value(&statement));
                let jwt = sign_entity_statement_for_test(sample_signing_key(), &statement);
                assert_federation_signature_only(&jwt, sample_signing_key());
                let result = if configuration {
                    crate::federation::admit_entity_configuration(&jwt, subject, NOW)
                } else {
                    crate::federation::admission::admit_subordinate_statement(
                        &jwt,
                        &statement.iss,
                        subject,
                        &sample_jwks(),
                        NOW,
                    )
                };
                assert_eq!(result.is_ok(), allowed);
                assert_eq!(validate_entity_statement(&statement, NOW).is_ok(), allowed);
                if allowed {
                    assert_eq!(must_ok(serde_json::to_value(must_ok(result))), original);
                } else {
                    assert_issuer_error(must_err(result), role);
                }
                assert_eq!(must_ok(serde_json::to_value(&statement)), original);
            }
        }
    }
}

#[test]
fn supplied_issuer_checks_every_typed_original_before_overlay_filter_or_absence() {
    let _guard = raw_json_env_guard();
    let f = SignedPathFixture::new(1);
    for role in ROLES {
        for index in 0..5 {
            for stage in 0..3 {
                let mut chain = f.detached().trust_chain;
                chain.chain[0].metadata = metadata(role, json!({}));
                chain.chain[1].metadata = metadata(role, json!({"issuer":chain.chain[0].sub}));
                if stage == 1 {
                    chain.chain[1].constraints = Some(Constraints {
                        allowed_entity_types: Some(vec!["openid_relying_party".into()]),
                        ..Default::default()
                    });
                } else if stage == 2 {
                    chain.chain[0].metadata = None;
                }
                chain.chain[index].metadata =
                    metadata(role, json!({"issuer":"https://foreign.example"}));
                let original = must_ok(serde_json::to_value(&chain.chain));
                assert_issuer_error(must_err(chain.resolved_metadata()), role);
                assert_eq!(must_ok(serde_json::to_value(&chain.chain)), original);
            }
        }
    }
}

#[test]
fn supplied_issuer_checks_retained_policy_results_and_preserves_partial_metadata() {
    let _guard = raw_json_env_guard();
    let f = SignedPathFixture::new(0);
    for role in ROLES {
        let subject = &f.configs[0].sub;
        for operator in ["value", "default"] {
            for issuer in [
                json!(subject),
                json!("https://foreign.example"),
                json!(true),
                json!(7),
                json!([]),
                json!({}),
            ] {
                let mut chain = f.detached().trust_chain;
                chain.chain[0].metadata = metadata(role, json!({}));
                chain.chain[1].metadata_policy =
                    metadata(role, json!({"issuer":{(operator):issuer}}));
                let original = must_ok(serde_json::to_value(&chain.chain));
                let result = chain.resolved_metadata();
                if issuer == json!(subject) {
                    assert_eq!(must_some(must_ok(result))[role], json!({"issuer":subject}));
                } else {
                    assert_issuer_error(must_err(result), role);
                }
                assert_eq!(must_ok(serde_json::to_value(&chain.chain)), original);
                // Unused operands do not supply metadata to an absent role.
                chain.chain[0].metadata = None;
                assert!(must_ok(chain.resolved_metadata()).is_none());
            }
        }
        let mut chain = f.detached().trust_chain;
        chain.chain[0].metadata = metadata(role, json!({}));
        assert_eq!(
            must_some(must_ok(chain.resolved_metadata()))[role],
            json!({})
        );
        chain.chain[1].metadata = metadata(role, json!({"issuer":subject}));
        assert_eq!(
            must_some(must_ok(chain.resolved_metadata()))[role],
            json!({"issuer":subject})
        );
        chain.chain[1].metadata_policy =
            metadata(role, json!({"issuer":{"default":"https://unused.example"}}));
        assert_eq!(
            must_some(must_ok(chain.resolved_metadata()))[role],
            json!({"issuer":subject})
        );
        chain.chain[1].metadata_policy = metadata(role, json!({"issuer":{"value":null}}));
        assert_eq!(
            must_some(must_ok(chain.resolved_metadata()))[role],
            json!({})
        );
    }
}

#[test]
fn supplied_issuer_unknown_roles_and_flat_helpers_have_no_subject_binding() {
    let _guard = raw_json_env_guard();
    for role in [
        "federation_entity",
        "openid_relying_party",
        "oauth_client",
        "oauth_resource",
        "custom_type",
        "Openid_provider",
    ] {
        for issuer in [
            json!(false),
            json!(42),
            json!([]),
            json!({"nested":null}),
            json!("https://foreign.example"),
        ] {
            let mut f = SignedPathFixture::new(0);
            f.configs[0].metadata = metadata(role, json!({"issuer":issuer}));
            must_ok(validate_entity_statement(&f.configs[0], NOW));
            let jwt = sign_entity_statement_for_test(&f.keys[0], &f.configs[0]);
            must_ok(crate::federation::admit_entity_configuration(
                &jwt,
                &f.configs[0].sub,
                NOW,
            ));
            assert_eq!(
                must_some(must_ok(f.detached().trust_chain.resolved_metadata()))[role],
                json!({"issuer":issuer})
            );
        }
    }
    for role in ROLES {
        let policy = json!({"issuer":{"value":"https://foreign.example"}});
        for result in [
            apply_metadata_policy(&json!({}), &policy),
            crate::federation::apply_metadata_policy_for_entity_type(role, &json!({}), &policy),
        ] {
            assert_eq!(must_ok(result), json!({"issuer":"https://foreign.example"}));
        }
    }
}

#[test]
fn supplied_issuer_fresh_and_cached_paths_reject_bad_originals_and_policy_results() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for role in ROLES {
            for stage in 0..7 {
                let mut f = SignedPathFixture::new(1);
                for statement in f.configs.iter_mut().chain(f.subordinates.iter_mut()) {
                    statement
                        .metadata
                        .get_or_insert_with(HashMap::new)
                        .insert(role.into(), json!({"issuer":statement.sub}));
                }
                let valid = f.detached();
                let fresh = must_ok(
                    resolve_trust_chain_with_jwts(
                        &f.configs[0].iss,
                        &[f.anchor.clone()],
                        &f.fetcher(),
                        NOW,
                    )
                    .await,
                );
                assert_eq!(
                    must_some(must_ok(fresh.trust_chain.resolved_metadata()))[role]["issuer"],
                    json!(f.configs[0].sub)
                );
                if stage < 5 {
                    let statement = if stage % 2 == 0 {
                        &mut f.configs[stage / 2]
                    } else {
                        &mut f.subordinates[stage / 2]
                    };
                    statement
                        .metadata
                        .get_or_insert_with(HashMap::new)
                        .insert(role.into(), json!({"issuer":"https://foreign.example"}));
                } else {
                    f.configs[0].metadata = metadata(role, json!({}));
                    f.subordinates[0].metadata = None;
                    let operator = if stage == 5 { "value" } else { "default" };
                    f.subordinates[0].metadata_policy = metadata(
                        role,
                        json!({"issuer":{(operator):"https://foreign.example"}}),
                    );
                }
                let originals = must_ok(serde_json::to_value((&f.configs, &f.subordinates)));
                let mut invalid = f.detached();
                for (index, jwt) in invalid.chain_jwts.iter().enumerate() {
                    assert_federation_signature_only(jwt, &f.keys[index.div_ceil(2)]);
                }
                assert!(resolve_trust_chain_with_jwts(
                    &f.configs[0].iss,
                    &[f.anchor.clone()],
                    &f.fetcher(),
                    NOW,
                )
                .await
                .is_err());
                let invalid_jwts = invalid.chain_jwts.clone();
                // A good detached projection must not hide invalid signed originals.
                invalid.trust_chain = valid.trust_chain.clone();
                for cached in [false, true] {
                    for valid_fresh in [false, true] {
                        let cache = ObservedCache::default();
                        let environment = Uuid::new_v4();
                        if cached {
                            must_ok(cache.inner.upsert(
                                environment,
                                &f.configs[0].iss,
                                &f.anchor.entity_id,
                                &json!(invalid_jwts),
                                NOW + 500,
                            ));
                        }
                        let calls = AtomicUsize::new(0);
                        let result = resolve_trust_chain_jwts_cached_with(
                            &f.configs[0].iss,
                            environment,
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
                        assert_eq!(result.is_ok(), valid_fresh, "{role} stage {stage}");
                        assert_eq!(calls.load(Ordering::SeqCst), 1);
                        assert_eq!(
                            cache.writes.load(Ordering::SeqCst),
                            usize::from(valid_fresh)
                        );
                        if let Ok(accepted) = result {
                            assert_eq!(accepted.chain_jwts, valid.chain_jwts);
                            let hit = must_ok(
                                resolve_trust_chain_jwts_cached_with(
                                    &f.configs[0].iss,
                                    environment,
                                    vec![f.anchor.clone()],
                                    &cache,
                                    &FederationCacheConfig::default(),
                                    NOW,
                                    |_| async { panic!("valid cache must be used") },
                                )
                                .await,
                            );
                            assert_eq!(hit.chain_jwts, valid.chain_jwts);
                        } else if cached {
                            let row = must_some(must_ok(cache.inner.get(
                                environment,
                                &f.configs[0].iss,
                                &f.anchor.entity_id,
                                NOW,
                            )));
                            assert_eq!(row.chain_jwts, json!(invalid_jwts));
                        }
                    }
                }
                assert_eq!(
                    must_ok(serde_json::to_value((&f.configs, &f.subordinates))),
                    originals
                );
            }
        }
    });
}

#[test]
fn supplied_issuer_signed_partial_metadata_can_be_completed_without_rewriting() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for role in ROLES {
            for source in ["absent", "superior", "value", "default"] {
                let mut f = SignedPathFixture::new(1);
                f.configs[0].metadata = metadata(role, json!({}));
                let subject = f.configs[0].sub.clone();
                if source == "superior" {
                    f.subordinates[0].metadata = metadata(role, json!({"issuer":subject}));
                } else if source != "absent" {
                    // Higher policy also describes the final leaf when applied.
                    f.subordinates[1].metadata_policy =
                        metadata(role, json!({"issuer":{(source):subject}}));
                }
                let signed = f.detached();
                let originals = must_ok(serde_json::to_value(&signed.trust_chain.chain));
                let cache = ObservedCache::default();
                let environment = Uuid::new_v4();
                let fresh = must_ok(
                    resolve_trust_chain_with_jwts(&subject, &[f.anchor.clone()], &f.fetcher(), NOW)
                        .await,
                );
                let expected = if source == "absent" {
                    json!({})
                } else {
                    json!({"issuer":subject})
                };
                assert_eq!(
                    must_some(must_ok(fresh.trust_chain.resolved_metadata()))[role],
                    expected
                );
                for hit in [false, true] {
                    let result = must_ok(
                        resolve_trust_chain_jwts_cached_with(
                            &subject,
                            environment,
                            vec![f.anchor.clone()],
                            &cache,
                            &FederationCacheConfig::default(),
                            NOW,
                            |_| {
                                assert!(!hit, "valid cache must be used");
                                std::future::ready(Ok(signed.clone()))
                            },
                        )
                        .await,
                    );
                    assert_eq!(
                        must_some(must_ok(result.trust_chain.resolved_metadata()))[role],
                        expected
                    );
                    assert_eq!(result.chain_jwts, signed.chain_jwts);
                    assert_eq!(
                        must_ok(serde_json::to_value(&result.trust_chain.chain)),
                        originals
                    );
                }
            }
        }
    });
}
