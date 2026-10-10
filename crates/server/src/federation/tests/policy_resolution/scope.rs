#[test]
fn scope_without_effective_policy_preserves_metadata() {
    for entity_type in ["openid_relying_party", "oauth_client"] {
        for scope in [json!("read read"), json!("read  write"), json!(["read"])] {
            let metadata = json!({"scope":scope,"client_name":"unchanged"});
            for policy in [
                json!({"client_name":{"essential":true}}),
                json!({"scope":{"unknown_extension":{"arbitrary":null}}}),
            ] {
                assert_eq!(
                    must_ok(apply_metadata_policy_for_entity_type(
                        entity_type, &metadata, &policy,
                    )),
                    metadata
                );
            }
            let mut chain = policy_chain(Value::Null, Value::Null, None);
            chain.chain[0].metadata =
                Some(HashMap::from([(entity_type.into(), metadata.clone())]));
            for policy in [
                None,
                Some(json!({"client_name":{"essential":true}})),
                Some(json!({"scope":{"unknown_extension":true}})),
            ] {
                chain.chain[1].metadata_policy =
                    policy.map(|p| HashMap::from([(entity_type.into(), p)]));
                assert_eq!(
                    must_some(must_ok(chain.resolved_metadata()))[entity_type],
                    metadata
                );
            }
        }
    }
}

#[test]
fn scope_value_replaces_or_removes_without_decoding_prior_value() {
    for entity_type in ["openid_relying_party", "oauth_client"] {
        for prior in [
            json!("read  write"),
            json!(["read"]),
            json!({"unexpected":true}),
            json!(42),
            json!(false),
        ] {
            for (value, expected) in [
                (json!(["read", "write"]), json!({"scope":"read write"})),
                (json!([]), json!({"scope":""})),
                (Value::Null, json!({})),
            ] {
                let metadata = json!({"scope":prior});
                let policy = json!({"scope":{"value":value}});
                assert_eq!(
                    must_ok(apply_metadata_policy_for_entity_type(
                        entity_type, &metadata, &policy,
                    )),
                    expected
                );
                let mut chain = policy_chain(Value::Null, Value::Null, None);
                chain.chain[0].metadata =
                    Some(HashMap::from([(entity_type.into(), json!({}))]));
                // Immediate-superior metadata is applied before the resolved policy.
                chain.chain[1].metadata =
                    Some(HashMap::from([(entity_type.into(), metadata)]));
                chain.chain[3].metadata_policy =
                    Some(HashMap::from([(entity_type.into(), policy)]));
                assert_eq!(
                    must_some(must_ok(chain.resolved_metadata()))[entity_type],
                    expected
                );
            }
        }
    }
}

#[test]
fn scope_conversion_keeps_operand_and_metadata_admission_checks() {
    for entity_type in ["openid_relying_party", "oauth_client"] {
        for policy in [
            json!({"scope":{"default":["read"]}}),
            json!({"scope":{"add":["read"]}}),
            json!({"scope":{"subset_of":["read"]}}),
            json!({"scope":{"superset_of":["read"]}}),
            json!({"scope":{"essential":false}}),
        ] {
            assert!(apply_metadata_policy_for_entity_type(
                entity_type,
                &json!({"scope":"read  write"}),
                &policy,
            )
            .is_err());
        }
        for value in [json!(["invalid token"]), json!("read"), json!([1])] {
            assert!(apply_metadata_policy_for_entity_type(
                entity_type,
                &json!({"scope":"read"}),
                &json!({"scope":{"value":value}}),
            )
            .is_err());
        }
        // Null metadata parameters remain forbidden before policy application.
        for value in [Value::Null, json!(["read"])] {
            assert!(apply_metadata_policy_for_entity_type(
                entity_type,
                &json!({"scope":null}),
                &json!({"scope":{"value":value}}),
            )
            .is_err());
        }
    }
}
