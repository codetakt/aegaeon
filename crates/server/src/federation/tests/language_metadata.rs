use super::registration_metadata::supplied;

const COMMON: &[(&str, u8)] = &[
    ("organization_name", 0),
    ("display_name", 0),
    ("description", 0),
    ("keywords", 1),
    ("contacts", 1),
    ("logo_uri", 2),
    ("policy_uri", 2),
    ("information_uri", 2),
    ("organization_uri", 2),
];

fn extra(role: &str) -> Vec<(&'static str, u8)> {
    match role {
        "openid_provider" | "oauth_authorization_server" => vec![
            ("service_documentation", 2),
            ("op_policy_uri", 2),
            ("op_tos_uri", 2),
        ],
        "openid_relying_party" | "oauth_client" => {
            vec![("client_name", 0), ("client_uri", 2), ("tos_uri", 2)]
        }
        "oauth_resource" => vec![
            ("resource_name", 0),
            ("resource_documentation", 2),
            ("resource_policy_uri", 2),
            ("resource_tos_uri", 2),
        ],
        _ => vec![],
    }
}

#[test]
fn language_localized_and_base_schemas_cover_every_role_and_preserve_text() {
    let _guard = raw_json_env_guard();
    for role in [
        "openid_provider",
        "oauth_authorization_server",
        "openid_relying_party",
        "oauth_client",
        "oauth_resource",
        "federation_entity",
        "custom_type",
    ] {
        for &(base, kind) in COMMON.iter().chain(extra(role).iter()) {
            let valid = match kind {
                0 => json!("e\u{301} 日本語"),
                1 => json!(["", "日本語"]),
                _ => json!("mailto:info@example.test"),
            };
            let invalid = match kind {
                0 => json!([]),
                1 => json!([]),
                _ => json!("https://example.test/ literal space"),
            };
            for name in [
                base.to_owned(),
                format!("{base}#en"),
                format!("{base}#EN"),
                format!("{base}#x-private"),
            ] {
                supplied(role, &json!({(&name):valid}), true);
                supplied(role, &json!({(&name):invalid}), false);
                for operator in ["value", "default"] {
                    for (value, allowed) in [(&valid, true), (&invalid, false)] {
                        assert_eq!(
                            apply_metadata_policy_for_entity_type(
                                role,
                                &json!({}),
                                &json!({(&name):{(operator):value}})
                            )
                            .is_ok(),
                            allowed
                        );
                    }
                }
            }
            for tag in ["", "eng", "en_US", "en#US", "en-cmn", "sl-rozaj-ROZAJ"] {
                supplied(role, &json!({(format!("{base}#{tag}")):valid}), false);
            }
        }
    }
}

#[test]
fn language_unknown_wrong_role_and_nonlocalizable_names_remain_opaque() {
    let _guard = raw_json_env_guard();
    for role in [
        "openid_provider",
        "oauth_authorization_server",
        "openid_relying_party",
        "oauth_client",
        "oauth_resource",
        "custom_type",
    ] {
        for name in [
            "custom#not_a_tag",
            "jwks_uri#en",
            "issuer#en",
            "future#",
            "Display_name#eng",
        ] {
            supplied(role, &json!({(name):{"nested":null}}), true);
        }
        for &(base, _) in extra("openid_provider")
            .iter()
            .chain(extra("oauth_client").iter())
            .chain(extra("oauth_resource").iter())
        {
            if extra(role).iter().any(|(known, _)| *known == base) {
                continue;
            }
            supplied(
                role,
                &json!({(base):{"nested":null}, (format!("{base}#not_a_tag")):false}),
                true,
            );
        }
    }
    // Generic untyped application does not infer a Federation role/schema.
    assert!(apply_metadata_policy(
        &json!({"display_name#eng": false}),
        &json!({"display_name#eng":{"essential":true}})
    )
    .is_ok());
}

#[test]
fn language_policy_names_are_checked_at_raw_typed_pin_and_role_boundaries() {
    let _guard = raw_json_env_guard();
    for role in ["openid_provider", "oauth_client", "custom_type"] {
        for (name, allowed) in [
            ("display_name#en", true),
            ("display_name#EN", true),
            ("display_name#eng", false),
            ("display_name#en#US", false),
            ("custom#not_a_tag", true),
        ] {
            // Unknown operator value is deliberately not a final display value.
            let policy = json!({(role):{(name):{"future_operator":{"opaque":null}}}});
            let mut statement = sample_subordinate_statement(
                "https://superior.example",
                "https://subject.example",
                NOW,
            );
            statement.metadata_policy = Some(must_ok(serde_json::from_value(policy.clone())));
            let jwt = sign_entity_statement_for_test(sample_signing_key(), &statement);
            assert_federation_signature_only(&jwt, sample_signing_key());
            assert_eq!(
                crate::federation::admission::admit_subordinate_statement(
                    &jwt,
                    &statement.iss,
                    &statement.sub,
                    &sample_jwks(),
                    NOW
                )
                .is_ok(),
                allowed
            );
            assert_eq!(validate_entity_statement(&statement, NOW).is_ok(), allowed);
            assert_eq!(
                crate::federation::metadata_policy::validate_metadata_policy_pin(Some(&policy))
                    .is_ok(),
                allowed
            );
            assert_eq!(
                apply_metadata_policy_for_entity_type(role, &json!({}), &policy[role]).is_ok(),
                allowed
            );
            let mut chain = SignedPathFixture::new(1).detached().trust_chain;
            chain.chain[0].metadata = None;
            chain.chain[3].metadata_policy = statement.metadata_policy.clone();
            assert_eq!(chain.resolved_metadata().is_ok(), allowed);
        }
    }
}

#[test]
fn language_literal_policy_comparisons_and_unsuffixed_values_do_not_negotiate() {
    let _guard = raw_json_env_guard();
    let role = "openid_provider";
    let original = json!({"display_name":"unspecified", "display_name#en":"English", "display_name#EN":"Other English", "ui_locales_supported":["EN","fr","EN"]});
    let output = must_ok(apply_metadata_policy_for_entity_type(
        role,
        &original,
        &json!({"display_name#en":{"value":"Changed"}, "ui_locales_supported":{"subset_of":["en"]}}),
    ));
    assert_eq!(output["display_name"], "unspecified");
    assert_eq!(output["display_name#en"], "Changed");
    assert_eq!(output["display_name#EN"], "Other English");
    assert_eq!(output["ui_locales_supported"], json!([]));
    let alias = json!({"display_name#EN":"Original"});
    assert!(apply_metadata_policy_for_entity_type(
        role,
        &alias,
        &json!({"display_name#en":{"essential":true}})
    )
    .is_err());
    assert_eq!(
        must_ok(apply_metadata_policy_for_entity_type(
            role,
            &alias,
            &json!({"display_name#en":{"default":"New"}})
        )),
        json!({"display_name#EN":"Original","display_name#en":"New"})
    );
    assert!(apply_metadata_policy_for_entity_type(
        role,
        &json!({"display_name#de-CH":"Swiss"}),
        &json!({"display_name#de":{"essential":true}})
    )
    .is_err());
    assert_eq!(
        must_ok(apply_metadata_policy_for_entity_type(
            role,
            &json!({"ui_locales_supported":["EN"]}),
            &json!({"ui_locales_supported":{"add":["en"]}})
        ))["ui_locales_supported"],
        json!(["EN", "en"])
    );
    for operator in ["value", "default"] {
        for right in [json!(["EN"]), json!(["en", "fr"])] {
            let mut chain = SignedPathFixture::new(1).detached().trust_chain;
            chain.chain[0].metadata = Some(HashMap::from([(role.into(), json!({}))]));
            chain.chain[1].metadata_policy = Some(HashMap::from([(
                role.into(),
                json!({"ui_locales_supported":{(operator):["en"]}}),
            )]));
            chain.chain[3].metadata_policy = Some(HashMap::from([(
                role.into(),
                json!({"ui_locales_supported":{(operator):right}}),
            )]));
            assert!(chain.resolved_metadata().is_err());
        }
    }
    let mut chain = SignedPathFixture::new(1).detached().trust_chain;
    chain.chain[0].metadata = Some(HashMap::from([(role.into(), json!({}))]));
    chain.chain[1].metadata_policy = Some(HashMap::from([(
        role.into(),
        json!({"display_name#en":{"value":"A"}}),
    )]));
    chain.chain[3].metadata_policy = Some(HashMap::from([(
        role.into(),
        json!({"display_name#EN":{"value":"B"}}),
    )]));
    let accepted = must_some(must_ok(chain.resolved_metadata()));
    assert_eq!(accepted[role]["display_name#en"], "A");
    assert_eq!(accepted[role]["display_name#EN"], "B");
    let pin = json!({"display_name#en":{"value":"é"},"ui_locales_supported":{"value":["en","fr"]}});
    assert!(!crate::federation::metadata_policy::policy_equiv(
        &pin,
        &json!({"display_name#en":{"value":"e\u{301}"},"ui_locales_supported":{"value":["en","fr"]}})
    ));
    assert!(!crate::federation::metadata_policy::policy_equiv(
        &pin,
        &json!({"display_name#EN":{"value":"é"},"ui_locales_supported":{"value":["en","fr"]}})
    ));
    assert!(!crate::federation::metadata_policy::policy_equiv(
        &pin,
        &json!({"display_name#en":{"value":"é"},"ui_locales_supported":{"value":["fr","en"]}})
    ));
}

#[test]
fn language_decoded_escaped_keys_are_duplicates_but_case_aliases_are_not() {
    let _guard = raw_json_env_guard();
    let mut statement = sample_entity_config("https://subject.example", NOW);
    statement.metadata = Some(HashMap::from([(
        "openid_provider".into(),
        json!({"display_name#en":"A","display_name#EN":"B"}),
    )]));
    let literal = must_ok(serde_json::to_string(&statement));
    for (payload, allowed) in [
        (literal.clone(), true),
        (
            literal.replace("display_name#EN", r"display_name#\u0065n"),
            false,
        ),
    ] {
        let jwt = super::super::admission::sign_payload(&payload);
        assert_federation_signature_only(&jwt, sample_signing_key());
        assert_eq!(
            crate::federation::admit_entity_configuration(&jwt, &statement.sub, NOW).is_ok(),
            allowed
        );
    }
}

#[test]
fn language_signed_alias_policies_on_separate_links_preserve_exact_names() {
    let _guard = raw_json_env_guard();
    block_on_test_future(async {
        let mut fixture = SignedPathFixture::new(1);
        fixture.configs[0].metadata = Some(HashMap::from([(
            "openid_provider".into(),
            json!({"display_name":"unspecified"}),
        )]));
        fixture.subordinates[0].metadata_policy = Some(HashMap::from([(
            "openid_provider".into(),
            json!({"display_name#en":{"value":"A"}}),
        )]));
        fixture.subordinates[1].metadata_policy = Some(HashMap::from([(
            "openid_provider".into(),
            json!({"display_name#EN":{"value":"B"}}),
        )]));
        let result = must_ok(
            resolve_trust_chain_with_jwts(
                &fixture.configs[0].iss,
                &[fixture.anchor.clone()],
                &fixture.fetcher(),
                NOW,
            )
            .await,
        );
        let metadata = must_some(must_ok(result.trust_chain.resolved_metadata()));
        assert_eq!(metadata["openid_provider"]["display_name#en"], "A");
        assert_eq!(metadata["openid_provider"]["display_name#EN"], "B");
        assert_eq!(metadata["openid_provider"]["display_name"], "unspecified");
    });
}

#[test]
fn language_malformed_suffixes_at_all_original_positions_survive_no_hiding_operation() {
    let _guard = raw_json_env_guard();
    let fixture = SignedPathFixture::new(1);
    for position in 0..5 {
        for hide in ["overlay", "filter", "absence", "removal"] {
            let mut chain = fixture.detached().trust_chain;
            chain.chain[0].metadata = Some(HashMap::from([(
                "openid_provider".into(),
                json!({"display_name#en":"Valid"}),
            )]));
            if hide == "filter" {
                chain.chain[1].constraints = Some(Constraints {
                    allowed_entity_types: Some(vec!["custom".into()]),
                    ..Default::default()
                });
            } else if hide == "absence" {
                chain.chain[0].metadata = None;
            } else if hide == "removal" {
                chain.chain[3].metadata_policy = Some(HashMap::from([(
                    "openid_provider".into(),
                    json!({"display_name#en":{"value":null}}),
                )]));
            }
            chain.chain[position].metadata = Some(HashMap::from([(
                "openid_provider".into(),
                json!({"display_name#en_US":"Invalid original"}),
            )]));
            assert!(chain.resolved_metadata().is_err(), "{position} {hide}");
        }
    }
}
