use super::registration_metadata::supplied;
use super::signed_parent::ObservedCache;
use crate::oidc::capabilities::test_contract::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const OP: &str = "openid_provider";
const AS: &str = "oauth_authorization_server";

fn metadata(role: &str, value: Value) -> Option<HashMap<String, Value>> {
    Some(HashMap::from([(role.into(), value)]))
}

#[test]
fn capabilities_exact_role_maps_check_signed_configurations_and_subordinates() {
    let _guard = raw_json_env_guard();
    for (role, arrays, booleans) in [(OP, OP_ARRAYS, OP_BOOLEANS), (AS, AS_ARRAYS, AS_BOOLEANS)] {
        supplied(role, &json!({}), true);
        for field in arrays {
            for value in [
                json!([]),
                if matches!(*field, "ui_locales_supported" | "claims_locales_supported") {
                    json!(["en", "EN", "x-private", "fr"])
                } else {
                    json!(["future", "", "NONE", " none", "future"])
                },
            ] {
                supplied(role, &json!({(*field):value}), true);
            }
            for value in [
                Value::Null,
                json!("secret-invalid"),
                json!(true),
                json!(4),
                json!({}),
                json!([null]),
                json!([false]),
                json!([1]),
                json!([{}]),
                json!([[]]),
                json!(["future", 2]),
            ] {
                supplied(role, &json!({(*field):value}), false);
            }
        }
        for field in booleans {
            for value in [true, false] {
                supplied(role, &json!({(*field):value}), true);
            }
            for value in [Value::Null, json!("true"), json!(1), json!([]), json!({})] {
                supplied(role, &json!({(*field):value}), false);
            }
        }
        let mut complete = json!({"extension":{"nested":null}});
        for field in arrays {
            complete[*field] =
                if matches!(*field, "ui_locales_supported" | "claims_locales_supported") {
                    json!(["en", "EN"])
                } else {
                    json!(["future", "future"])
                };
        }
        for field in booleans {
            complete[*field] = json!(true);
        }
        supplied(role, &complete, true);
    }
}

#[test]
fn capabilities_auth_none_is_exact_and_scoped_to_three_auth_arrays() {
    let _guard = raw_json_env_guard();
    for role in [OP, AS] {
        for field in AUTH_ARRAYS {
            for value in [json!(["none"]), json!(["RS256", "none"])] {
                supplied(role, &json!({(*field):value}), false);
            }
            for value in [
                json!([]),
                json!(["RS384"]),
                json!(["NONE", " none", "none ", "None"]),
            ] {
                supplied(role, &json!({(*field):value}), true);
            }
        }
        // No supplied-stage companion presence or mandatory RS256 auth member.
        supplied(
            role,
            &json!({"token_endpoint_auth_methods_supported":["private_key_jwt"],
            "revocation_endpoint_auth_methods_supported":["client_secret_jwt"],
            "introspection_endpoint_auth_methods_supported":["private_key_jwt"]}),
            true,
        );
    }
    for field in [
        "id_token_signing_alg_values_supported",
        "userinfo_signing_alg_values_supported",
        "request_object_signing_alg_values_supported",
    ] {
        supplied(OP, &json!({(field):["none"]}), true);
    }
}

#[test]
fn capabilities_wrong_roles_and_unknown_nested_extensions_keep_their_values() {
    let _guard = raw_json_env_guard();
    for field in OP_ARRAYS
        .iter()
        .filter(|field| !AS_ARRAYS.contains(field))
        .chain(
            OP_BOOLEANS
                .iter()
                .filter(|field| !AS_BOOLEANS.contains(field)),
        )
    {
        supplied(AS, &json!({(*field):{"nested":null}}), true);
    }
    for role in [
        "openid_relying_party",
        "oauth_client",
        "custom_type",
        "Openid_provider",
    ] {
        for field in OP_ARRAYS.iter().chain(OP_BOOLEANS) {
            supplied(role, &json!({(*field):{"nested":null}}), true);
        }
    }
}

#[test]
fn capabilities_originals_cannot_be_hidden_by_overlay_removal_filter_or_absence() {
    let _guard = raw_json_env_guard();
    let fixture = SignedPathFixture::new(1);
    for role in [OP, AS] {
        for (field, bad, good) in [
            ("scopes_supported", json!(false), json!([])),
            ("ui_locales_supported", json!(["en_US"]), json!(["en"])),
            ("display_name#en", json!(false), json!("Name")),
            ("require_signed_request_object", json!([]), json!(false)),
            (
                "token_endpoint_auth_signing_alg_values_supported",
                json!(["none"]),
                json!(["RS384"]),
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
fn capabilities_flat_and_typed_policy_results_check_every_field_mapping() {
    let _guard = raw_json_env_guard();
    let fixture = SignedPathFixture::new(0);
    for (role, arrays, booleans) in [(OP, OP_ARRAYS, OP_BOOLEANS), (AS, AS_ARRAYS, AS_BOOLEANS)] {
        for field in arrays.iter().chain(booleans) {
            let good = if arrays.contains(field) {
                json!([])
            } else {
                json!(false)
            };
            for operator in ["value", "default"] {
                for (value, allowed) in [(good.clone(), true), (json!({"secret":null}), false)] {
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
        for field in AUTH_ARRAYS {
            assert!(crate::federation::apply_metadata_policy_for_entity_type(
                role,
                &json!({}),
                &json!({(*field):{"value":["none"]}})
            )
            .is_err());
        }
    }
}

#[test]
fn capabilities_fresh_and_cached_chains_recheck_originals_and_derived_shapes() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        for role in [OP, AS] {
            for (field, good, bad) in [
                ("scopes_supported", json!([]), json!(false)),
                ("ui_locales_supported", json!(["en"]), json!(["eng"])),
                ("display_name#en", json!("Name"), json!([])),
                ("require_signed_request_object", json!(false), json!([])),
                (
                    "token_endpoint_auth_signing_alg_values_supported",
                    json!(["RS384"]),
                    json!(["none"]),
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
