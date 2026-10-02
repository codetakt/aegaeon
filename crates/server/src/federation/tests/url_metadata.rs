use super::registration_metadata::supplied;
use super::signed_parent::ObservedCache;
use crate::oidc::provider_urls::test_contract::*;
use std::sync::atomic::{AtomicUsize, Ordering};
const OP: &str = "openid_provider";
const AS: &str = "oauth_authorization_server";
fn metadata(role: &str, value: Value) -> Option<HashMap<String, Value>> {
    Some(HashMap::from([(role.into(), value)]))
}

#[test]
fn provider_urls_signed_field_maps_and_informational_uri_policy() {
    let _guard = raw_json_env_guard();
    for (role, endpoints) in [(OP, OP_ENDPOINTS), (AS, AS_ENDPOINTS)] {
        supplied(role, &json!({}), true);
        supplied(role, &json!({"issuer":"https://subject.example"}), true);
        for field in endpoints {
            for value in GOOD_ENDPOINTS {
                supplied(role, &json!({(*field):value}), true);
            }
            for value in bad_endpoints() {
                supplied(role, &json!({(*field):value}), false);
            }
        }
        for field in INFORMATIONAL {
            for value in [
                "http://docs.example",
                "urn:example:policy",
                "https://user:password@docs.example/path?q=1#fragment",
                "mailto:policy@example.com",
            ] {
                supplied(role, &json!({(*field):value}), true);
            }
            for value in bad_urls() {
                supplied(role, &json!({(*field):value}), false);
            }
        }
    }
}

#[test]
fn provider_urls_signed_issuer_keeps_case_port_path_and_subject_binding() {
    let _guard = raw_json_env_guard();
    for role in [OP, AS] {
        for issuer in ["HTTPS://Issuer.example:8443/path", "https://issuer.example"] {
            for configuration in [false, true] {
                let mut statement = if configuration {
                    sample_entity_config(issuer, NOW)
                } else {
                    sample_subordinate_statement("https://superior.example", issuer, NOW)
                };
                statement.metadata = metadata(role, json!({"issuer":issuer}));
                let jwt = sign_entity_statement_for_test(sample_signing_key(), &statement);
                assert_federation_signature_only(&jwt, sample_signing_key());
                let admitted = if configuration {
                    crate::federation::admit_entity_configuration(&jwt, issuer, NOW)
                } else {
                    crate::federation::admission::admit_subordinate_statement(
                        &jwt,
                        &statement.iss,
                        issuer,
                        &sample_jwks(),
                        NOW,
                    )
                };
                assert_eq!(
                    must_some(must_ok(admitted).metadata)[role]["issuer"],
                    issuer
                );
            }
        }
    }
}

#[test]
fn provider_urls_alias_known_maps_opaque_extensions_and_wrong_roles() {
    let _guard = raw_json_env_guard();
    for (role, aliases) in [(OP, OP_ALIASES), (AS, AS_ALIASES)] {
        for value in [
            Value::Null,
            json!({}),
            json!([]),
            json!(false),
            json!(42),
            json!("https://provider.example"),
        ] {
            supplied(role, &json!({"mtls_endpoint_aliases":value}), false);
        }
        supplied(
            role,
            &json!({"mtls_endpoint_aliases":{"future":null,"authorization_endpoint":{},"issuer":[],"unknown_endpoint":{"nested":null}}}),
            true,
        );
        for field in aliases {
            for value in GOOD_ENDPOINTS {
                supplied(
                    role,
                    &json!({"mtls_endpoint_aliases":{(*field):value,"future":{"nested":null}}}),
                    true,
                );
            }
            for value in bad_endpoints() {
                supplied(
                    role,
                    &json!({"mtls_endpoint_aliases":{(*field):value,"future":null}}),
                    false,
                );
            }
        }
    }
    supplied(
        AS,
        &json!({"userinfo_endpoint":{"nested":null},"end_session_endpoint":[],"mtls_endpoint_aliases":{"userinfo_endpoint":null}}),
        true,
    );
    for role in [
        "openid_relying_party",
        "oauth_client",
        "custom_type",
        "Openid_provider",
    ] {
        for field in OP_ENDPOINTS
            .iter()
            .chain(INFORMATIONAL)
            .chain(["mtls_endpoint_aliases"].iter())
        {
            supplied(role, &json!({(*field):{"nested":null}}), true);
        }
    }
}

#[test]
fn provider_urls_issuer_policy_and_derived_partial_values() {
    let _guard = raw_json_env_guard();
    let fixture = SignedPathFixture::new(0);
    for (role, endpoints) in [(OP, OP_ENDPOINTS), (AS, AS_ENDPOINTS)] {
        // Flat policy has no signed subject binding, so these assertions isolate URL syntax.
        for value in ["HTTPS://Issuer.example:8443/path", "https://issuer.example"] {
            let raw = json!({"issuer":value});
            assert_eq!(
                must_ok(crate::federation::apply_metadata_policy_for_entity_type(
                    role,
                    &raw,
                    &json!({"extension_noop":{"essential":false}})
                )),
                raw
            );
        }
        for value in bad_endpoints().into_iter().chain([
            json!("https://issuer.example/?"),
            json!("https://issuer.example/?q=1"),
        ]) {
            assert!(crate::federation::apply_metadata_policy_for_entity_type(
                role,
                &json!({"issuer":value}),
                &json!({"extension_noop":{"essential":false}})
            )
            .is_err());
        }
        for field in endpoints
            .iter()
            .chain(INFORMATIONAL)
            .chain(["mtls_endpoint_aliases"].iter())
        {
            let good = if *field == "mtls_endpoint_aliases" {
                json!({"future":null})
            } else {
                json!(GOOD_ENDPOINTS[1])
            };
            for operator in ["value", "default"] {
                for (value, allowed) in [(good.clone(), true), (json!(42), false)] {
                    let policy = json!({(*field):{(operator):value}});
                    let flat = crate::federation::apply_metadata_policy_for_entity_type(
                        role,
                        &json!({}),
                        &policy,
                    );
                    let mut chain = fixture.detached().trust_chain;
                    chain.chain[0].metadata = metadata(role, json!({}));
                    chain.chain[1].metadata_policy = metadata(role, policy);
                    let result = chain.resolved_metadata();
                    assert_eq!(flat.is_ok(), allowed, "{role} {field}");
                    assert_eq!(result.is_ok(), allowed, "{role} {field}");
                    if allowed {
                        assert_eq!(must_some(must_ok(result))[role], must_ok(flat));
                    }
                }
            }
        }
    }
}

#[test]
fn provider_urls_originals_cannot_be_hidden_by_overlay_removal_filter_or_absence() {
    let _guard = raw_json_env_guard();
    let fixture = SignedPathFixture::new(1);
    for role in [OP, AS] {
        for (field, bad, good) in [
            (
                "token_endpoint",
                json!("http://provider.example"),
                json!(GOOD_ENDPOINTS[0]),
            ),
            (
                "op_policy_uri",
                json!("relative"),
                json!("urn:example:policy"),
            ),
            (
                "mtls_endpoint_aliases",
                json!({"registration_endpoint":null}),
                json!({"future":null}),
            ),
        ] {
            for position in 0..5 {
                for stage in 0..4 {
                    let mut chain = fixture.detached().trust_chain;
                    chain.chain[0].metadata = metadata(role, json!({}));
                    chain.chain[1].metadata = metadata(role, json!({(field):good}));
                    if stage == 1 {
                        chain.chain[1].constraints = Some(Constraints {
                            allowed_entity_types: Some(vec!["custom_type".into()]),
                            ..Default::default()
                        });
                    } else if stage == 2 {
                        chain.chain[0].metadata = None;
                    } else if stage == 3 {
                        chain.chain[3].metadata_policy =
                            metadata(role, json!({(field):{"value":null}}));
                    }
                    chain.chain[position].metadata = metadata(role, json!({(field):bad}));
                    let original = must_ok(serde_json::to_value(&chain.chain));
                    assert!(chain.resolved_metadata().is_err());
                    assert_eq!(must_ok(serde_json::to_value(&chain.chain)), original);
                }
            }
        }
    }
}

#[test]
fn provider_urls_fresh_and_cached_chains_recheck_originals_and_derived_shapes() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for role in [OP, AS] {
            for (field, good, bad) in [
                (
                    "token_endpoint",
                    json!(GOOD_ENDPOINTS[0]),
                    json!("http://provider.example"),
                ),
                (
                    "op_policy_uri",
                    json!("urn:example:policy"),
                    json!("relative"),
                ),
                (
                    "mtls_endpoint_aliases",
                    json!({"future":null}),
                    json!({"registration_endpoint":null}),
                ),
            ] {
                for stage in 0..7 {
                    let mut f = SignedPathFixture::new(1);
                    for statement in f.configs.iter_mut().chain(f.subordinates.iter_mut()) {
                        statement
                            .metadata
                            .get_or_insert_with(HashMap::new)
                            .insert(role.into(), json!({(field):good}));
                    }
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
                        must_some(statement.metadata.as_mut())
                            .insert(role.into(), json!({(field):bad}));
                    } else {
                        f.configs[0].metadata = metadata(role, json!({}));
                        f.subordinates[0].metadata = None;
                        let operator = if stage == 5 { "value" } else { "default" };
                        f.subordinates[1].metadata_policy =
                            metadata(role, json!({(field):{(operator):bad}}));
                    }
                    let original = must_ok(serde_json::to_value((&f.configs, &f.subordinates)));
                    let mut invalid = f.detached();
                    for (i, jwt) in invalid.chain_jwts.iter().enumerate() {
                        assert_federation_signature_only(jwt, &f.keys[i.div_ceil(2)]);
                    }
                    assert!(resolve_trust_chain_with_jwts(
                        &f.configs[0].iss,
                        &[f.anchor.clone()],
                        &f.fetcher(),
                        NOW
                    )
                    .await
                    .is_err());
                    let signed_invalid = invalid.chain_jwts.clone();
                    invalid.trust_chain = valid.trust_chain.clone();
                    for cached in [false, true] {
                        for fresh_valid in [false, true] {
                            let cache = ObservedCache::default();
                            let environment = Uuid::new_v4();
                            if cached {
                                must_ok(cache.inner.upsert(
                                    environment,
                                    &f.configs[0].iss,
                                    &f.anchor.entity_id,
                                    &json!(signed_invalid),
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
                                    std::future::ready(Ok(if fresh_valid {
                                        valid.clone()
                                    } else {
                                        invalid.clone()
                                    }))
                                },
                            )
                            .await;
                            assert_eq!(result.is_ok(), fresh_valid);
                            assert_eq!(calls.load(Ordering::SeqCst), 1);
                            assert_eq!(
                                cache.writes.load(Ordering::SeqCst),
                                usize::from(fresh_valid)
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
                            }
                        }
                    }
                    assert_eq!(
                        must_ok(serde_json::to_value((&f.configs, &f.subordinates))),
                        original
                    );
                }
            }
        }
    });
}
