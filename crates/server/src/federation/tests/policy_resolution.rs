fn apply_field(current: Value, operators: Value) -> Result<Value, FederationError> {
    apply_metadata_policy(&current, &json!({"x": operators}))
}

mod scope {
    use super::*;
    include!("policy_resolution/scope.rs");
}

#[test]
fn policy_resolution_operator_actions_and_null_boundary() {
    let cases = [
        (json!({"x":"old"}), json!({"value":null}), json!({})),
        (
            json!({}),
            json!({"add":["a"],"default":["b"]}),
            json!({"x":["a"]}),
        ),
        (
            json!({}),
            json!({"value":"a","default":"b"}),
            json!({"x":"a"}),
        ),
        (
            json!({"x":["b"]}),
            json!({"subset_of":["a"],"essential":true}),
            json!({"x":[]}),
        ),
        (json!({}), json!({"one_of":[]}), json!({})),
        (
            json!({}),
            json!({"value":{"nested":null},"essential":true}),
            json!({"x":{"nested":null}}),
        ),
        (
            json!({}),
            json!({"default":[true,null,[1]]}),
            json!({"x":[true,null,[1]]}),
        ),
        (
            json!({"x":[1]}),
            json!({"superset_of":[1.0]}),
            json!({"x":[1]}),
        ),
    ];
    for (metadata, operators, expected) in cases {
        assert_eq!(must_ok(apply_field(metadata, operators)), expected);
    }
    for operators in [
        json!({"value":null,"default":"a"}),
        json!({"value":null,"essential":true}),
        json!({"default":null}),
    ] {
        assert!(apply_field(json!({}), operators).is_err());
    }
    assert!(apply_field(json!({"unrelated":null}), json!({"essential":false})).is_err());
    assert!(apply_field(json!({"x":null}), json!({"value":"a"})).is_err());
}

#[test]
fn policy_resolution_pair_conditions_independent_of_presence() {
    let valid = [
        json!({"value":["a","b"],"add":["a"]}),
        json!({"value":["a"],"subset_of":["a","b"]}),
        json!({"value":["a","b"],"superset_of":["b"]}),
        json!({"value":"a","one_of":["a","b"]}),
        json!({"add":["a"],"subset_of":["a","b"]}),
        json!({"superset_of":["a"],"subset_of":["a","b"]}),
        json!({"value":null,"essential":false}),
    ];
    for operators in valid {
        assert!(apply_field(json!({}), operators).is_ok());
    }
    let invalid = [
        json!({"value":["a"],"add":["b"]}),
        json!({"value":["b"],"subset_of":["a"]}),
        json!({"value":["a"],"superset_of":["b"]}),
        json!({"value":"b","one_of":["a"]}),
        json!({"add":["b"],"subset_of":["a"]}),
        json!({"superset_of":["b"],"subset_of":["a"]}),
        json!({"one_of":["a"],"add":[]}),
        json!({"one_of":["a"],"subset_of":[]}),
        json!({"one_of":["a"],"superset_of":[]}),
        json!({"value":"a","add":[]}),
    ];
    for operators in invalid {
        assert!(
            apply_field(json!({}), operators.clone()).is_err(),
            "{operators}"
        );
    }
}

#[test]
fn policy_resolution_set_domains_and_exact_equality() {
    for op in ["add", "one_of", "subset_of", "superset_of", "intersect"] {
        for unsupported in [
            json!([true]),
            json!([null]),
            json!([[1]]),
            json!([1, "a"]),
            json!("a"),
        ] {
            assert!(apply_field(json!({}), json!({op:unsupported})).is_err());
        }
    }
    for item in [json!("a"), json!(1), json!({"a":[1,2],"b":null})] {
        assert!(apply_field(json!({"x":item.clone()}), json!({"one_of":[item.clone()]})).is_ok());
        assert!(apply_field(json!({"x":[item.clone()]}), json!({"add":[item]})).is_ok());
    }
    let numeric = [
        (json!(1), json!(1.0)),
        (json!(1000), json!(1e3)),
        (json!(0), json!(-0.0)),
        (json!({"n":1}), json!({"n":1.0})),
    ];
    for (left, right) in numeric {
        assert!(apply_field(json!({"x":left}), json!({"one_of":[right]})).is_ok());
    }
    assert!(apply_field(
        json!({"x":9007199254740993_u64}),
        json!({"one_of":[9007199254740992_u64]})
    )
    .is_err());
    assert!(apply_field(json!({"x":{"a":[1,2]}}), json!({"one_of":[{"a":[2,1]}]})).is_err());
}

fn policy_chain(upper: Value, lower: Value, metadata: Option<Value>) -> TrustChain {
    let mut leaf = sample_entity_config("https://leaf.example", 100);
    leaf.metadata = metadata.map(|value| HashMap::from([("openid_relying_party".into(), value)]));
    let mut lower_s =
        sample_subordinate_statement("https://middle.example", "https://leaf.example", 100);
    let middle = sample_entity_config("https://middle.example", 100);
    let mut upper_s =
        sample_subordinate_statement("https://anchor.example", "https://middle.example", 100);
    let anchor_c = sample_entity_config("https://anchor.example", 100);
    lower_s.metadata_policy = (!lower.is_null()).then(|| must_ok(serde_json::from_value(lower)));
    upper_s.metadata_policy = (!upper.is_null()).then(|| must_ok(serde_json::from_value(upper)));
    TrustChain {
        chain: vec![leaf, lower_s, middle, upper_s, anchor_c],
        anchor: sample_trust_anchor("https://anchor.example"),
    }
}

fn wrapped(ops: Value) -> Value {
    json!({"openid_relying_party":{"x":ops}})
}

#[test]
fn policy_resolution_hierarchical_conflicts_and_merges() {
    for (left, right) in [
        (json!({"value":"a"}), json!({"value":"b"})),
        (json!({"default":"a"}), json!({"default":"b"})),
        (json!({"one_of":["a"]}), json!({"one_of":["b"]})),
        (json!({"subset_of":["a"]}), json!({"superset_of":["b"]})),
        (json!({"value":null}), json!({"essential":true})),
    ] {
        for metadata in [None, Some(json!({})), Some(json!({"x":"present"}))] {
            assert!(
                policy_chain(wrapped(left.clone()), wrapped(right.clone()), metadata)
                    .resolved_metadata()
                    .is_err()
            );
        }
    }
    let chain = policy_chain(
        wrapped(
            json!({"add":["a"],"superset_of":["a"],"subset_of":["a","b","c"],"essential":false}),
        ),
        wrapped(json!({"add":["b"],"superset_of":["b"],"subset_of":["b","a"],"essential":true})),
        Some(json!({})),
    );
    assert_eq!(
        must_some(must_ok(chain.resolved_metadata()))["openid_relying_party"]["x"],
        json!(["a", "b"])
    );
    let chain = policy_chain(
        wrapped(json!({"value":1})),
        wrapped(json!({"value":1.0})),
        Some(json!({})),
    );
    assert_eq!(
        must_some(must_ok(chain.resolved_metadata()))["openid_relying_party"]["x"],
        json!(1)
    );
}

#[test]
fn policy_resolution_unused_types_and_original_grammar() {
    for invalid in [
        json!({}),
        json!({"unused":{}}),
        json!({"unused":{"x":{}}}),
        json!({"unused":{"x":{"add":[false]}}}),
    ] {
        for leaf in [None, Some(json!({}))] {
            assert!(policy_chain(invalid.clone(), Value::Null, leaf)
                .resolved_metadata()
                .is_err());
        }
    }
    let chain = policy_chain(
        json!({"unused":{"x":{"extension":{"anything":null}}}}),
        Value::Null,
        None,
    );
    assert!(must_ok(chain.resolved_metadata()).is_none());
    let chain = policy_chain(
        json!({"openid_relying_party":{"name#ja":{"value":"a"}},"oauth_client":{"name#ja":{"value":"b"}}}),
        json!({"openid_relying_party":{"name#en":{"value":"c"}}}),
        Some(json!({})),
    );
    let result = must_some(must_ok(chain.resolved_metadata()));
    assert_eq!(
        result["openid_relying_party"],
        json!({"name#ja":"a","name#en":"c"})
    );
    assert!(!result.contains_key("oauth_client"));
}

#[test]
fn policy_resolution_immediate_overlay_and_layout() {
    let mut chain = policy_chain(Value::Null, Value::Null, Some(json!({"x":"leaf"})));
    chain.chain[1].metadata = Some(HashMap::from([
        (
            "openid_relying_party".into(),
            json!({"x":"immediate","added":1}),
        ),
        ("undeclared".into(), json!({"x":true})),
    ]));
    chain.chain[3].metadata = Some(HashMap::from([(
        "openid_relying_party".into(),
        json!({"x":"ancestor"}),
    )]));
    assert_eq!(
        must_some(must_ok(chain.resolved_metadata()))["openid_relying_party"],
        json!({"x":"immediate","added":1})
    );
    chain.chain[0].metadata = Some(HashMap::from([("openid_relying_party".into(), json!({}))]));
    let declared_empty = must_some(must_ok(chain.resolved_metadata()));
    assert_eq!(declared_empty.len(), 1);
    assert_eq!(
        declared_empty["openid_relying_party"],
        json!({"x":"immediate","added":1})
    );
    chain.chain[1].metadata_policy = Some(must_ok(serde_json::from_value(wrapped(
        json!({"value":"policy"}),
    ))));
    assert_eq!(
        must_some(must_ok(chain.resolved_metadata()))["openid_relying_party"]["x"],
        json!("policy")
    );
    chain.chain[1].sub = "https://other.example".into();
    assert!(chain.resolved_metadata().is_err());
    chain.chain.remove(1);
    assert!(chain.resolved_metadata().is_err());
}

#[test]
fn policy_resolution_scope_context_and_local_alias() {
    for entity_type in ["oauth_client", "openid_relying_party"] {
        let apply = |m, p| super::super::apply_metadata_policy_for_entity_type(entity_type, &m, &p);
        assert_eq!(
            must_ok(apply(
                json!({"scope":"read read write"}),
                json!({"scope":{"subset_of":["read"],"essential":true}})
            )),
            json!({"scope":"read"})
        );
        assert_eq!(
            must_ok(apply(
                json!({"scope":"read"}),
                json!({"scope":{"subset_of":[],"essential":true}})
            )),
            json!({"scope":""})
        );
        assert_eq!(
            must_ok(apply(
                json!({}),
                json!({"scope":{"add":["read"],"default":["write"],"superset_of":["read"]}})
            )),
            json!({"scope":"read"})
        );
        assert_eq!(
            must_ok(apply(json!({}), json!({"scope":{"default":["read"]}}))),
            json!({"scope":"read"})
        );
        assert_eq!(
            must_ok(apply(json!({}), json!({"scope":{"subset_of":["read"]}}))),
            json!({})
        );
        for bad in [
            " read",
            "read ",
            "read  write",
            "read\twrite",
            "read\\write",
            "réad",
        ] {
            assert!(apply(json!({"scope":bad}), json!({"scope":{"essential":false}})).is_err());
        }
        for bad in [
            json!({"value":"read write"}),
            json!({"default":["read write"]}),
            json!({"add":[1]}),
        ] {
            assert!(apply(json!({}), json!({"scope":bad})).is_err());
        }
    }
    assert_eq!(
        must_ok(apply_metadata_policy(
            &json!({}),
            &json!({"scope":{"value":"arbitrary text"}})
        )),
        json!({"scope":"arbitrary text"})
    );
    assert_eq!(
        must_ok(super::super::apply_metadata_policy_for_entity_type(
            "openid_provider",
            &json!({"scopes_supported":["read","write"]}),
            &json!({"scopes_supported":{"subset_of":["read"]}})
        )),
        json!({"scopes_supported":["read"]})
    );
    assert!(apply_field(json!({}), json!({"add":["b"],"intersect":["a"]})).is_err());
    let chain = policy_chain(
        wrapped(json!({"intersect":["a"]})),
        wrapped(json!({"subset_of":["a","b"],"intersect":["b"]})),
        Some(json!({"x":["a","b"]})),
    );
    assert_eq!(
        must_some(must_ok(chain.resolved_metadata()))["openid_relying_party"]["x"],
        json!([])
    );
}

#[test]
fn policy_resolution_specification_section_6_1_5_example() {
    let upper = json!({"openid_relying_party":{
        "grant_types":{"default":["authorization_code"],"subset_of":["authorization_code","refresh_token"],"superset_of":["authorization_code"]},
        "token_endpoint_auth_method":{"one_of":["private_key_jwt","self_signed_tls_client_auth"],"essential":true},
        "token_endpoint_auth_signing_alg":{"one_of":["PS256","ES256"]},
        "subject_type":{"value":"pairwise"},"contacts":{"add":["helpdesk@federation.example.org"]}}});
    let lower = json!({"openid_relying_party":{
        "grant_types":{"subset_of":["authorization_code"]},
        "token_endpoint_auth_method":{"one_of":["self_signed_tls_client_auth"]},
        "contacts":{"add":["helpdesk@org.example.org"]}}});
    let mut chain = policy_chain(
        upper,
        lower,
        Some(
            json!({"redirect_uris":["https://rp.example.org/callback"],"response_types":["code"],"token_endpoint_auth_method":"self_signed_tls_client_auth","contacts":["rp_admins@rp.example.org"]}),
        ),
    );
    chain.chain[1].metadata = Some(HashMap::from([(
        "openid_relying_party".into(),
        json!({"sector_identifier_uri":"https://org.example.org/sector-ids.json","policy_uri":"https://org.example.org/policy.html"}),
    )]));
    assert_eq!(
        must_some(must_ok(chain.resolved_metadata()))["openid_relying_party"],
        json!({
        "redirect_uris":["https://rp.example.org/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"self_signed_tls_client_auth","subject_type":"pairwise","sector_identifier_uri":"https://org.example.org/sector-ids.json","policy_uri":"https://org.example.org/policy.html","contacts":["rp_admins@rp.example.org","helpdesk@federation.example.org","helpdesk@org.example.org"]})
    );
}

#[test]
fn policy_resolution_optional_array_domains_and_scope_through_chain() {
    for item in [json!("a"), json!(1.0), json!({"key": [1, null]})] {
        for op in ["add", "subset_of", "superset_of", "intersect"] {
            let metadata = json!({"x":[item.clone()]});
            assert_eq!(
                must_ok(apply_field(metadata.clone(), json!({op:[item.clone()]}))),
                metadata
            );
        }
    }
    for entity_type in ["openid_relying_party", "oauth_client"] {
        let mut chain = policy_chain(Value::Null, Value::Null, None);
        chain.chain[0].metadata = Some(HashMap::from([(
            entity_type.into(),
            json!({"scope":"read write"}),
        )]));
        chain.chain[1].metadata_policy = Some(HashMap::from([(
            entity_type.into(),
            json!({"scope":{"subset_of":["read"],"essential":true}}),
        )]));
        assert_eq!(
            must_some(must_ok(chain.resolved_metadata()))[entity_type]["scope"],
            json!("read")
        );
        chain.chain[0].metadata = Some(HashMap::from([(entity_type.into(), json!({}))]));
        assert!(chain.resolved_metadata().is_err());
        chain.chain[1].metadata_policy = None;
        chain.chain[0].metadata = Some(HashMap::from([(entity_type.into(), json!({"scope":""}))]));
        assert_eq!(
            must_some(must_ok(chain.resolved_metadata()))[entity_type]["scope"],
            json!("")
        );
    }
}

#[test]
fn policy_resolution_null_leaf_cannot_be_hidden_by_overlay() {
    let mut chain = policy_chain(Value::Null, Value::Null, Some(json!({"x":null})));
    chain.chain[1].metadata = Some(HashMap::from([(
        "openid_relying_party".into(),
        json!({"x":"replacement"}),
    )]));
    assert!(chain.resolved_metadata().is_err());
}
