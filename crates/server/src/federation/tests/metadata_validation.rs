use super::signed_parent::ObservedCache;
use std::sync::atomic::{AtomicUsize, Ordering};

const FEDERATION: &str = "federation_entity";
const ALGORITHMS: &str = "endpoint_auth_signing_alg_values_supported";
const ENDPOINTS: [&str; 7] = [
    "federation_fetch_endpoint",
    "federation_list_endpoint",
    "federation_resolve_endpoint",
    "federation_trust_mark_status_endpoint",
    "federation_trust_mark_list_endpoint",
    "federation_trust_mark_endpoint",
    "federation_historical_keys_endpoint",
];

fn flat(entity: &str, metadata: &Value, policy: &Value) -> Result<Value, FederationError> {
    crate::federation::apply_metadata_policy_for_entity_type(entity, metadata, policy)
}

fn signed_admission(entity: &str, metadata: Value, configuration: bool, allowed: bool) {
    let mut statement = if configuration {
        sample_entity_config("https://subject.example", NOW)
    } else {
        sample_subordinate_statement("https://issuer.example", "https://subject.example", NOW)
    };
    statement.metadata = Some(HashMap::from([(entity.into(), metadata)]));
    let original = must_ok(serde_json::to_value(&statement));
    let jwt = sign_entity_statement_for_test(sample_signing_key(), &statement);
    assert_federation_signature_only(&jwt, sample_signing_key());
    assert_eq!(
        verify_entity_statement(&jwt, &sample_jwks()).is_ok(),
        allowed
    );
    assert_eq!(validate_entity_statement(&statement, NOW).is_ok(), allowed);
    let admitted = if configuration {
        crate::federation::admit_entity_configuration(&jwt, &statement.sub, NOW)
    } else {
        crate::federation::admission::admit_subordinate_statement(
            &jwt,
            &statement.iss,
            &statement.sub,
            &sample_jwks(),
            NOW,
        )
    };
    assert_eq!(admitted.is_ok(), allowed);
    if let Ok(value) = admitted {
        assert_eq!(must_ok(serde_json::to_value(value)), original);
    }
    assert_eq!(must_ok(serde_json::to_value(&statement)), original);
}

#[test]
fn metadata_schema_forbids_protocol_keys_only_in_federation_role() {
    let _guard = raw_json_env_guard();
    for field in ["jwks", "jwks_uri", "signed_jwks_uri"] {
        for value in [
            Value::Null,
            json!({"keys": []}),
            json!("https://keys.example/private"),
            json!(true),
            json!([]),
        ] {
            for configuration in [false, true] {
                signed_admission(FEDERATION, json!({(field):value}), configuration, false);
            }
            assert!(flat(
                FEDERATION,
                &json!({(field):value}),
                &json!({(field):{"value":null}})
            )
            .is_err());
            let result = flat(FEDERATION, &json!({}), &json!({(field):{"value":value}}));
            if value.is_null() {
                assert_eq!(must_ok(result), json!({}));
            } else {
                assert!(must_err(result).to_string().contains(field));
            }
        }
    }
}

#[test]
fn metadata_schema_preserves_common_fields_extensions_and_protocol_key_controls() {
    let _guard = raw_json_env_guard();
    for entity in [
        FEDERATION,
        "openid_provider",
        "openid_relying_party",
        "oauth_client",
        "oauth_resource",
        "custom_type",
    ] {
        let mut metadata = json!({
            "organization_name":"", "display_name":" 日本語 ", "description":"line\nnext",
            "keywords":["", "same", "same"], "contacts":["", "not an email"],
            "logo_uri":"http://Example.org/logo?x=1#view", "policy_uri":"https://example.org/policy#terms",
            "information_uri":"urn:example:information", "organization_uri":"https://example.org/",
            "unknown":{"nested":null}, "array_extension":[null], "Contacts":false,
            "name#ja":{"extension":null}
        });
        if entity != FEDERATION {
            metadata["jwks"] = sample_jwks_value();
            metadata["jwks_uri"] = json!("https://keys.example/jwks");
            metadata["signed_jwks_uri"] = json!("https://keys.example/signed");
        }
        for configuration in [false, true] {
            signed_admission(entity, metadata.clone(), configuration, true);
            signed_admission(entity, json!({}), configuration, true);
        }
        assert_eq!(
            must_ok(flat(
                entity,
                &metadata,
                &json!({"unknown":{"essential":false}})
            )),
            metadata
        );
    }
    for algorithms in [
        json!([]),
        json!(["RS256", "experimental", "NONE", "None", "RS256"]),
    ] {
        for configuration in [false, true] {
            signed_admission(
                FEDERATION,
                json!({(ALGORITHMS):algorithms}),
                configuration,
                true,
            );
        }
        assert_eq!(
            must_ok(flat(
                FEDERATION,
                &json!({}),
                &json!({(ALGORITHMS):{"value":algorithms}})
            )),
            json!({(ALGORITHMS):algorithms})
        );
    }
}

#[test]
fn metadata_schema_rejects_common_field_shapes_in_signed_and_flat_inputs() {
    let _guard = raw_json_env_guard();
    for entity in [FEDERATION, "custom_type"] {
        for field in [
            "organization_name",
            "display_name",
            "description",
            "keywords",
            "contacts",
            "logo_uri",
            "policy_uri",
            "information_uri",
            "organization_uri",
        ] {
            let mut invalid = vec![Value::Null, json!(true), json!(12), json!({})];
            if matches!(field, "keywords" | "contacts") {
                invalid.extend([
                    json!("text"),
                    json!([]),
                    json!([null]),
                    json!(["ok", 1]),
                    json!([["nested"]]),
                ]);
            } else {
                invalid.push(json!([]));
            }
            if field.ends_with("_uri") {
                invalid.extend([
                    json!("relative/path"),
                    json!(""),
                    json!("https://example.org/ space"),
                    json!("https://example.org/\n"),
                    json!("https://example.org\\path"),
                    json!(" https://example.org/"),
                ]);
            }
            for value in invalid {
                for configuration in [false, true] {
                    signed_admission(entity, json!({(field):value}), configuration, false);
                }
                assert!(flat(
                    entity,
                    &json!({(field):value}),
                    &json!({(field):{"value":null}})
                )
                .is_err());
            }
        }
    }
    for value in [
        Value::Null,
        json!("RS256"),
        json!({}),
        json!([null]),
        json!([1]),
        json!(["RS256", "none"]),
    ] {
        for configuration in [false, true] {
            signed_admission(
                FEDERATION,
                json!({(ALGORITHMS):value}),
                configuration,
                false,
            );
        }
    }
}

#[test]
fn metadata_schema_checks_all_derived_endpoints_without_statement_placement() {
    let _guard = raw_json_env_guard();
    for field in ENDPOINTS {
        let valid = json!("HTTPS://Example.org:8443/path?x=a");
        let f = SignedPathFixture::new(0);
        for value in [
            json!(true),
            json!("http://private.example"),
            json!("https://user:secret@private.example"),
            json!("https://private.example#fragment"),
            json!("https:///private.example"),
            json!("https://private.example/ space"),
            json!("https://private.example\\path"),
        ] {
            let policy = json!({(field):{"value":value}});
            let error = must_err(flat(FEDERATION, &json!({}), &policy)).to_string();
            assert!(error.contains(field));
            assert!(!error.contains("private.example") && !error.contains("secret"));
            let mut chain = f.detached().trust_chain;
            chain.chain[0].metadata = Some(HashMap::from([(FEDERATION.into(), json!({}))]));
            chain.chain[1].metadata_policy = Some(HashMap::from([(FEDERATION.into(), policy)]));
            assert!(chain.resolved_metadata().is_err());
        }
        assert_eq!(
            must_ok(flat(
                FEDERATION,
                &json!({}),
                &json!({(field):{"default":valid}})
            )),
            json!({(field):valid})
        );
        let mut chain = f.detached().trust_chain;
        chain.chain[0].metadata = Some(HashMap::from([(FEDERATION.into(), json!({}))]));
        chain.chain[1].metadata_policy = Some(HashMap::from([(
            FEDERATION.into(),
            json!({(field):{"value":valid}}),
        )]));
        assert_eq!(
            must_some(must_ok(chain.resolved_metadata()))[FEDERATION],
            json!({(field):valid})
        );
    }
}

#[test]
fn metadata_schema_validates_every_typed_input_before_overlay_filter_or_absence() {
    let _guard = raw_json_env_guard();
    let f = SignedPathFixture::new(1);
    for index in 0..5 {
        for leaf_absent in [false, true] {
            for value in [
                json!({"contacts":[]}),
                json!({"organization_name":1}),
                json!({"unknown":null}),
                json!([]),
            ] {
                let mut chain = f.detached().trust_chain;
                chain.chain[0].metadata = (!leaf_absent).then(|| {
                    HashMap::from([("custom_type".into(), json!({"contacts":["valid"]}))])
                });
                chain.chain[1].metadata = Some(HashMap::from([(
                    "custom_type".into(),
                    json!({"contacts":["replacement"]}),
                )]));
                chain.chain[1].constraints = Some(Constraints {
                    allowed_entity_types: Some(vec![]),
                    ..Constraints::default()
                });
                chain.chain[index].metadata = Some(HashMap::from([("custom_type".into(), value)]));
                let original = must_ok(serde_json::to_value(&chain.chain));
                assert!(chain.resolved_metadata().is_err());
                assert_eq!(must_ok(serde_json::to_value(&chain.chain)), original);
            }
        }
    }
}

#[test]
fn metadata_schema_checks_final_policy_results_but_not_unused_operands() {
    let _guard = raw_json_env_guard();
    let f = SignedPathFixture::new(0);
    let cases = [
        (FEDERATION, "jwks", json!({"keys":[]})),
        (FEDERATION, ALGORITHMS, json!(["none"])),
        ("custom_type", "organization_name", json!(12)),
        ("custom_type", "contacts", json!([])),
        ("custom_type", "keywords", json!([null])),
        ("custom_type", "logo_uri", json!("relative")),
    ];
    for (entity, field, value) in cases {
        for operator in ["value", "default"] {
            let policy = json!({(field):{(operator):value}});
            assert!(flat(entity, &json!({}), &policy).is_err());
            let mut chain = f.detached().trust_chain;
            chain.chain[0].metadata = Some(HashMap::from([(entity.into(), json!({}))]));
            chain.chain[1].metadata_policy = Some(HashMap::from([(entity.into(), policy)]));
            assert!(chain.resolved_metadata().is_err());
            chain.chain[0].metadata = None;
            assert!(must_ok(chain.resolved_metadata()).is_none());
            chain.chain[0].metadata = Some(HashMap::from([("other_type".into(), json!({}))]));
            assert!(chain.resolved_metadata().is_ok());
        }
    }
    for field in ["contacts", "keywords"] {
        let metadata = json!({(field):["a"]});
        let policy = json!({(field):{"subset_of":["b"]}});
        assert!(flat("custom_type", &metadata, &policy).is_err());
        let mut chain = f.detached().trust_chain;
        chain.chain[0].metadata = Some(HashMap::from([("custom_type".into(), metadata.clone())]));
        chain.chain[1].metadata_policy = Some(HashMap::from([("custom_type".into(), policy)]));
        assert!(chain.resolved_metadata().is_err());
        for (operators, expected) in [
            (json!({"value":null}), json!({})),
            (
                json!({"value":["corrected"]}),
                json!({(field):["corrected"]}),
            ),
            (json!({"subset_of":["a"]}), metadata.clone()),
        ] {
            chain.chain[1].metadata_policy = Some(HashMap::from([(
                "custom_type".into(),
                json!({(field):operators}),
            )]));
            assert_eq!(
                must_some(must_ok(chain.resolved_metadata()))["custom_type"],
                expected
            );
            assert_eq!(
                must_ok(flat("custom_type", &metadata, &json!({(field):operators}))),
                expected
            );
        }
    }
    // The generic helper cannot infer that contacts is an informational list.
    assert_eq!(
        must_ok(apply_metadata_policy(
            &json!({}),
            &json!({"contacts":{"value":[]}})
        )),
        json!({"contacts":[]})
    );
    // Existing selected-algorithm/empty-set behavior is not generalized away.
    assert_eq!(
        must_ok(flat(
            "openid_provider",
            &json!({"id_token_signing_alg_values_supported":["RS256"]}),
            &json!({"id_token_signing_alg_values_supported":{"subset_of":[]}})
        )),
        json!({"id_token_signing_alg_values_supported":[]})
    );
}

#[test]
fn metadata_schema_fresh_and_cache_admission_use_originals_and_reject_bad_results() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for stage in 0..7 {
            let mut f = SignedPathFixture::new(1);
            f.configs[0].metadata = Some(HashMap::from([(
                "custom_type".into(),
                json!({"contacts":["valid"]}),
            )]));
            let valid = f.detached();
            must_ok(
                resolve_trust_chain_with_jwts(
                    &f.configs[0].iss,
                    &[f.anchor.clone()],
                    &f.fetcher(),
                    NOW,
                )
                .await,
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
                    .insert("custom_type".into(), json!({"contacts":[]}));
            } else {
                f.subordinates[0].metadata_policy = Some(HashMap::from([(
                    "custom_type".into(),
                    if stage == 5 {
                        json!({"contacts":{"value":[]}})
                    } else {
                        json!({"contacts":{"subset_of":["different"]}})
                    },
                )]));
            }
            let typed_original = must_ok(serde_json::to_value((&f.configs, &f.subordinates)));
            assert!(resolve_trust_chain_with_jwts(
                &f.configs[0].iss,
                &[f.anchor.clone()],
                &f.fetcher(),
                NOW
            )
            .await
            .is_err());
            let mut invalid = f.detached();
            let original = invalid.chain_jwts.clone();
            // A permissive detached projection cannot repair malformed raw claims.
            invalid.trust_chain = valid.trust_chain.clone();
            for valid_fresh in [false, true] {
                let cache = ObservedCache::default();
                let environment = Uuid::new_v4();
                must_ok(cache.inner.upsert(
                    environment,
                    &f.configs[0].iss,
                    &f.anchor.entity_id,
                    &json!(invalid.chain_jwts),
                    NOW + 500,
                ));
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
                assert_eq!(result.is_ok(), valid_fresh, "stage {stage}");
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert_eq!(
                    cache.writes.load(Ordering::SeqCst),
                    usize::from(valid_fresh)
                );
                let row = must_some(must_ok(cache.inner.get(
                    environment,
                    &f.configs[0].iss,
                    &f.anchor.entity_id,
                    NOW,
                )));
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
                            |_| async { panic!("valid cache should be used") },
                        )
                        .await,
                    );
                    assert_eq!(hit.chain_jwts, valid.chain_jwts);
                } else {
                    assert_eq!(row.chain_jwts, json!(original));
                    assert_eq!(row.expires_at, NOW + 500);
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
                |_| std::future::ready(Ok(invalid.clone()))
            )
            .await
            .is_err());
            assert_eq!(empty.writes.load(Ordering::SeqCst), 0);
            assert_eq!(
                must_ok(serde_json::to_value((&f.configs, &f.subordinates))),
                typed_original
            );
        }
    });
}
