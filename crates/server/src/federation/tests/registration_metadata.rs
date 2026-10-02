use super::signed_parent::ObservedCache;
use std::sync::atomic::{AtomicUsize, Ordering};

const OP: &str = "openid_provider";
const RP: &str = "openid_relying_party";
const OP_MODES: &str = "client_registration_types_supported";
const ENDPOINT: &str = "federation_registration_endpoint";
const URL: &str = "https://Registration.example:8443/path?mode=explicit";

fn metadata(role: &str, value: Value) -> Option<HashMap<String, Value>> {
    Some(HashMap::from([(role.into(), value)]))
}

fn supplied(role: &str, value: &Value, allowed: bool) {
    for configuration in [false, true] {
        let mut statement = if configuration {
            sample_entity_config("https://subject.example", NOW)
        } else {
            sample_subordinate_statement("https://superior.example", "https://subject.example", NOW)
        };
        statement.metadata = metadata(role, value.clone());
        let original = must_ok(serde_json::to_value(&statement));
        let jwt = sign_entity_statement_for_test(sample_signing_key(), &statement);
        assert_federation_signature_only(&jwt, sample_signing_key());
        let result = if configuration {
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
        assert_eq!(result.is_ok(), allowed, "{role}: {value}");
        assert_eq!(validate_entity_statement(&statement, NOW).is_ok(), allowed);
        if let Ok(admitted) = result {
            assert_eq!(must_ok(serde_json::to_value(admitted)), original);
        }
        assert_eq!(must_ok(serde_json::to_value(&statement)), original);
    }
    let result = crate::federation::apply_metadata_policy_for_entity_type(
        role,
        value,
        &json!({"extension_noop":{"essential":false}}),
    );
    assert_eq!(result.is_ok(), allowed);
    if let Ok(retained) = result {
        assert_eq!(&retained, value);
    }
}

#[test]
fn registration_modes_preserve_extensible_arrays_and_reject_supplied_wrong_kinds() {
    let _guard = raw_json_env_guard();
    for (role, field) in [(OP, OP_MODES), (RP, "client_registration_types")] {
        supplied(role, &json!({}), true);
        for modes in [
            json!([]),
            json!(["automatic"]),
            json!(["explicit"]),
            json!([
                "explicit",
                "automatic",
                "explicit",
                "future",
                "EXPLICIT",
                "",
                " explicit"
            ]),
        ] {
            supplied(role, &json!({(field):modes}), true);
        }
        for modes in [
            Value::Null,
            json!(true),
            json!(42),
            json!("explicit"),
            json!({}),
            json!(["explicit", null]),
            json!(["automatic", false]),
            json!([1]),
            json!([[]]),
        ] {
            supplied(role, &json!({(field):modes}), false);
        }
    }
    for (role, value) in [
        (OP, json!({"client_registration_types":{"extension":null}})),
        (RP, json!({(OP_MODES):false, (ENDPOINT):{"extension":null}})),
        (
            "oauth_client",
            json!({"client_registration_types":7, (OP_MODES):false, (ENDPOINT):[]}),
        ),
        (
            "custom_type",
            json!({"client_registration_types":{}, (OP_MODES):false, (ENDPOINT):[]}),
        ),
        ("Openid_provider", json!({(OP_MODES):false, (ENDPOINT):[]})),
    ] {
        supplied(role, &value, true);
    }
}

#[test]
fn registration_endpoint_url_conditions_depend_on_exact_explicit_declaration() {
    let _guard = raw_json_env_guard();
    for modes in [
        None,
        Some(json!([])),
        Some(json!(["automatic"])),
        Some(json!(["EXPLICIT", " explicit", "explicit ", "future"])),
    ] {
        for endpoint in [
            URL,
            "http://unused.example/registration#fragment",
            "urn:example:registration",
            "https://user:password@unused.example/registration#fragment",
        ] {
            let mut value = json!({(ENDPOINT):endpoint});
            if let Some(modes) = modes.as_ref() {
                value[OP_MODES] = modes.clone();
            }
            supplied(OP, &value, true);
        }
    }
    for endpoint in [
        URL,
        "HTTPS://Registration.example/path?x=1",
        "https://registration.example/",
    ] {
        supplied(
            OP,
            &json!({(OP_MODES):["future", "explicit", "explicit"], (ENDPOINT):endpoint}),
            true,
        );
    }
    for endpoint in [
        "http://registration.example",
        "https://registration.example/#fragment",
        "https://user:password@registration.example",
        "https://@registration.example",
        "urn:example:registration",
    ] {
        supplied(
            OP,
            &json!({(OP_MODES):["explicit"], (ENDPOINT):endpoint}),
            false,
        );
    }
    for endpoint in [
        Value::Null,
        json!(false),
        json!(4),
        json!([]),
        json!({}),
        json!(""),
        json!("relative/path"),
        json!(" https://registration.example"),
        json!("https://registration.example/ "),
        json!("https://registration.example/\n"),
        json!("https://registration.example\\path"),
    ] {
        for modes in [json!([]), json!(["explicit"])] {
            supplied(OP, &json!({(OP_MODES):modes, (ENDPOINT):endpoint}), false);
        }
    }
}

#[test]
fn registration_originals_cannot_be_hidden_by_overlay_filter_or_metadata_absence() {
    let _guard = raw_json_env_guard();
    let fixture = SignedPathFixture::new(1);
    for (role, bad, good) in [
        (
            RP,
            json!({"client_registration_types":false}),
            json!({"client_registration_types":[]}),
        ),
        (OP, json!({(OP_MODES):"explicit"}), json!({(OP_MODES):[]})),
        (
            OP,
            json!({(OP_MODES):["explicit"], (ENDPOINT):"http://unused.example"}),
            json!({(OP_MODES):["explicit"], (ENDPOINT):URL}),
        ),
    ] {
        for position in 0..5 {
            for stage in 0..3 {
                let mut chain = fixture.detached().trust_chain;
                chain.chain[0].metadata = metadata(role, json!({}));
                chain.chain[1].metadata = metadata(role, good.clone());
                if stage == 1 {
                    chain.chain[1].constraints = Some(Constraints {
                        allowed_entity_types: Some(vec!["custom_type".into()]),
                        ..Default::default()
                    });
                } else if stage == 2 {
                    chain.chain[0].metadata = None;
                }
                chain.chain[position].metadata = metadata(role, bad.clone());
                let original = must_ok(serde_json::to_value(&chain.chain));
                assert!(chain.resolved_metadata().is_err());
                assert_eq!(must_ok(serde_json::to_value(&chain.chain)), original);
            }
        }
    }
}

#[test]
fn registration_policy_checks_retained_values_without_requiring_partial_completion() {
    let _guard = raw_json_env_guard();
    let fixture = SignedPathFixture::new(0);
    for (role, field, values) in [
        (
            RP,
            "client_registration_types",
            vec![
                (json!([]), true),
                (json!(["future", "explicit"]), true),
                (json!(false), false),
                (json!([null]), false),
            ],
        ),
        (
            OP,
            OP_MODES,
            vec![
                (json!(["explicit"]), true),
                (json!(["EXPLICIT"]), true),
                (json!("explicit"), false),
                (json!([1]), false),
            ],
        ),
        (
            OP,
            ENDPOINT,
            vec![
                (json!(URL), true),
                (json!("http://unused.example"), true),
                (json!("relative"), false),
                (json!({}), false),
            ],
        ),
    ] {
        for operator in ["value", "default"] {
            for (value, allowed) in &values {
                let policy = json!({(field):{(operator):value}});
                let flat = crate::federation::apply_metadata_policy_for_entity_type(
                    role,
                    &json!({}),
                    &policy,
                );
                let mut chain = fixture.detached().trust_chain;
                chain.chain[0].metadata = metadata(role, json!({}));
                chain.chain[1].metadata_policy = metadata(role, policy);
                let original = must_ok(serde_json::to_value(&chain.chain));
                let result = chain.resolved_metadata();
                assert_eq!(flat.is_ok(), *allowed);
                assert_eq!(result.is_ok(), *allowed);
                if *allowed {
                    assert_eq!(must_some(must_ok(result))[role], must_ok(flat));
                }
                assert_eq!(must_ok(serde_json::to_value(&chain.chain)), original);
                chain.chain[0].metadata = None;
                assert!(must_ok(chain.resolved_metadata()).is_none());
            }
        }
    }
    let partial = json!({(OP_MODES):["explicit"]});
    assert_eq!(
        must_ok(crate::federation::apply_metadata_policy_for_entity_type(
            OP,
            &partial,
            &json!({"extension_noop":{"essential":false}})
        )),
        partial
    );
    for operator in ["value", "default"] {
        let policy = json!({(ENDPOINT):{(operator):URL}});
        let result = must_ok(crate::federation::apply_metadata_policy_for_entity_type(
            OP, &partial, &policy,
        ));
        assert_eq!(result, json!({(OP_MODES):["explicit"], (ENDPOINT):URL}));
        assert!(crate::federation::apply_metadata_policy_for_entity_type(
            OP,
            &partial,
            &json!({(ENDPOINT):{(operator):"http://unused.example"}})
        )
        .is_err());
    }
    let complete = json!({(OP_MODES):["explicit"], (ENDPOINT):URL});
    assert_eq!(
        must_ok(crate::federation::apply_metadata_policy_for_entity_type(
            OP,
            &complete,
            &json!({(ENDPOINT):{"value":null}})
        )),
        partial
    );
    assert_eq!(
        must_ok(crate::federation::apply_metadata_policy(
            &json!({}),
            &json!({(OP_MODES):{"value":false}})
        )),
        json!({(OP_MODES):false})
    );
}

#[test]
fn registration_fresh_and_cached_chains_recheck_all_signed_positions_and_results() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for (role, field) in [(OP, OP_MODES), (RP, "client_registration_types")] {
            for stage in 0..7 {
                let mut f = SignedPathFixture::new(1);
                for statement in f.configs.iter_mut().chain(f.subordinates.iter_mut()) {
                    statement
                        .metadata
                        .get_or_insert_with(HashMap::new)
                        .insert(role.into(), json!({(field):["explicit"]}));
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
                        .insert(role.into(), json!({(field):false}));
                } else {
                    f.configs[0].metadata = metadata(role, json!({}));
                    f.subordinates[0].metadata = None;
                    let operator = if stage == 5 { "value" } else { "default" };
                    f.subordinates[1].metadata_policy =
                        metadata(role, json!({(field):{(operator):false}}));
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
    });
}

#[test]
fn registration_signed_partial_metadata_accepts_superior_and_upper_policy_completion() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for source in ["absent", "superior", "value", "default"] {
            let mut f = SignedPathFixture::new(1);
            f.configs[0].metadata = metadata(OP, json!({(OP_MODES):["explicit"]}));
            if source == "superior" {
                f.subordinates[0].metadata = metadata(OP, json!({(ENDPOINT):URL}));
            } else if source != "absent" {
                f.subordinates[1].metadata_policy =
                    metadata(OP, json!({(ENDPOINT):{(source):URL}}));
            }
            let signed = f.detached();
            let original = must_ok(serde_json::to_value(&signed.trust_chain.chain));
            let fresh = must_ok(
                resolve_trust_chain_with_jwts(
                    &f.configs[0].iss,
                    &[f.anchor.clone()],
                    &f.fetcher(),
                    NOW,
                )
                .await,
            );
            let mut expected = json!({(OP_MODES):["explicit"]});
            if source != "absent" {
                expected[ENDPOINT] = json!(URL);
            }
            assert_eq!(
                must_some(must_ok(fresh.trust_chain.resolved_metadata()))[OP],
                expected
            );
            let cache = ObservedCache::default();
            let environment = Uuid::new_v4();
            for hit in [false, true] {
                let result = must_ok(
                    resolve_trust_chain_jwts_cached_with(
                        &f.configs[0].iss,
                        environment,
                        vec![f.anchor.clone()],
                        &cache,
                        &FederationCacheConfig::default(),
                        NOW,
                        |_| {
                            assert!(!hit);
                            std::future::ready(Ok(signed.clone()))
                        },
                    )
                    .await,
                );
                assert_eq!(
                    must_some(must_ok(result.trust_chain.resolved_metadata()))[OP],
                    expected
                );
                assert_eq!(result.chain_jwts, signed.chain_jwts);
                assert_eq!(
                    must_ok(serde_json::to_value(&result.trust_chain.chain)),
                    original
                );
            }
        }
    });
}
