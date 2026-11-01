use super::registration_metadata::supplied;

#[test]
fn protocol_keys_signed_originals_and_typed_policy_keep_role_boundaries() {
    let _guard = raw_json_env_guard();
    for role in [
        "openid_provider",
        "openid_relying_party",
        "oauth_authorization_server",
        "oauth_client",
        "oauth_resource",
    ] {
        supplied(role, &json!({}), true);
        supplied(
            role,
            &json!({"jwks":{"keys":[]},"jwks_uri":"HTTPS://Keys.example:8443/path?q=1","signed_jwks_uri":"https://keys.example/signed"}),
            true,
        );
        supplied(
            role,
            &json!({"jwks":{"keys":[null,{},7,{"kty":"future","extra":{"d":null}}],"extension":null}}),
            true,
        );
        for value in [
            json!({}),
            Value::Null,
            json!({"keys":{}}),
            json!({"keys":[{"kty":"future","d":null}]}),
        ] {
            supplied(role, &json!({"jwks":value}), false);
        }
        for field in ["jwks_uri", "signed_jwks_uri"] {
            for value in [Value::Null, json!("http://keys.example"), json!(false)] {
                supplied(role, &json!({(field):value}), false);
            }
        }
        for operator in ["value", "default", "add"] {
            let policy = json!({"jwks":{(operator):{"keys":null}}});
            assert!(crate::federation::apply_metadata_policy_for_entity_type(
                role,
                &json!({}),
                &policy
            )
            .is_err());
        }
        // Invalid input cannot be laundered through deletion or replacement.
        for replacement in [Value::Null, json!({"keys":[]})] {
            assert!(crate::federation::apply_metadata_policy_for_entity_type(
                role,
                &json!({"jwks":{}}),
                &json!({"jwks":{"value":replacement}})
            )
            .is_err());
        }
    }
    supplied(
        "future_role",
        &json!({"jwks":7,"signed_jwks_uri":false}),
        true,
    );
    for field in ["jwks", "jwks_uri", "signed_jwks_uri"] {
        supplied(
            "federation_entity",
            &json!({(field):"https://keys.example"}),
            false,
        );
    }
}

#[test]
fn protocol_keys_invalid_originals_survive_no_hiding_stage() {
    let _guard = raw_json_env_guard();
    let fixture = SignedPathFixture::new(1);
    for role in [
        "openid_provider",
        "openid_relying_party",
        "oauth_authorization_server",
        "oauth_client",
        "oauth_resource",
    ] {
        for position in 0..5 {
            for stage in 0..4 {
                let mut chain = fixture.detached().trust_chain;
                chain.chain[0].metadata =
                    Some(HashMap::from([(role.into(), json!({"jwks":{"keys":[]}}))]));
                chain.chain[1].metadata = chain.chain[0].metadata.clone();
                if stage == 1 {
                    chain.chain[1].constraints = Some(Constraints {
                        allowed_entity_types: Some(vec!["future".into()]),
                        ..Default::default()
                    });
                }
                if stage == 2 {
                    chain.chain[0].metadata = None;
                }
                if stage == 3 {
                    chain.chain[3].metadata_policy = Some(HashMap::from([(
                        role.into(),
                        json!({"jwks":{"value":null}}),
                    )]));
                }
                chain.chain[position].metadata = Some(HashMap::from([(
                    role.into(),
                    json!({"jwks":{"keys":false}}),
                )]));
                let original = must_ok(serde_json::to_value(&chain.chain));
                assert!(chain.resolved_metadata().is_err());
                assert_eq!(must_ok(serde_json::to_value(&chain.chain)), original);
            }
        }
    }
}
