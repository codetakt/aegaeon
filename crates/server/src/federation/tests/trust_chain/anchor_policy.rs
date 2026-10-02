// ── max_path_length enforcement ──────────────────────────────────

fn resolve_trust_chain_for_test(
    leaf_entity_id: &str,
    trust_anchors: &[TrustAnchor],
    fetcher: &dyn FederationFetcher,
    now: i64,
) -> Result<TrustChain, FederationError> {
    let _guard = raw_json_env_guard();
    block_on_test_future(crate::federation::resolve_trust_chain(
        leaf_entity_id,
        trust_anchors,
        fetcher,
        now,
    ))
}

#[test]
fn max_path_length_direct_chain_allowed() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: None,
    }];

    let mut sub_stmt = sample_subordinate_statement(ta_id, leaf_id, now);
    sub_stmt.constraints = Some(Constraints {
        allowed_entity_types: None,
        max_path_length: Some(0),
        allowed_leaf_entity_types: None,
    });

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, sample_entity_config(leaf_id, now));
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(ta_id, leaf_id, sub_stmt);

    let chain = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);
    assert!(
        chain.is_ok(),
        "direct chain with max_path_length=0 should succeed"
    );
}

#[test]
fn allowed_leaf_entity_types_direct_chain_rejects_disallowed_leaf_metadata() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: None,
    }];

    let mut sub_stmt = sample_subordinate_statement(ta_id, leaf_id, now);
    sub_stmt.constraints = Some(Constraints {
        allowed_entity_types: None,
        max_path_length: None,
        allowed_leaf_entity_types: Some(vec!["openid_provider".to_string()]),
    });

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, sample_entity_config(leaf_id, now));
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(ta_id, leaf_id, sub_stmt);

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);
    assert!(
        result.is_err(),
        "allowed_leaf_entity_types must reject a leaf whose metadata entity type is not allowed"
    );
}

#[test]
fn allowed_leaf_entity_types_intermediate_chain_rejects_ancestor_constraint() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let int_id = "https://intermediate.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: None,
    }];

    let mut leaf_config = sample_entity_config(leaf_id, now);
    leaf_config.authority_hints = Some(vec![int_id.to_string()]);

    let mut int_config = sample_entity_config(int_id, now);
    int_config.authority_hints = Some(vec![ta_id.to_string()]);

    let mut ta_sub_stmt = sample_subordinate_statement(ta_id, int_id, now);
    ta_sub_stmt.constraints = Some(Constraints {
        allowed_entity_types: None,
        max_path_length: None,
        allowed_leaf_entity_types: Some(vec!["openid_provider".to_string()]),
    });

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, leaf_config);
    fetcher.add_entity_config(int_id, int_config);
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(
        int_id,
        leaf_id,
        sample_subordinate_statement(int_id, leaf_id, now),
    );
    fetcher.add_subordinate_stmt(ta_id, int_id, ta_sub_stmt);

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);
    assert!(
        result.is_err(),
        "allowed_leaf_entity_types must apply across intermediate ancestors"
    );
}

#[test]
fn allowed_leaf_entity_types_accepts_matching_leaf_metadata() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: None,
    }];

    let mut sub_stmt = sample_subordinate_statement(ta_id, leaf_id, now);
    sub_stmt.constraints = Some(Constraints {
        allowed_entity_types: None,
        max_path_length: None,
        allowed_leaf_entity_types: Some(vec!["openid_relying_party".to_string()]),
    });

    let mut fetcher = MockFetcher::new();
    let mut leaf = sample_entity_config(leaf_id, now);
    must_some(leaf.metadata.as_mut()).remove("federation_entity");
    fetcher.add_entity_config(leaf_id, leaf);
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(ta_id, leaf_id, sub_stmt);

    let chain = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);
    assert!(
        chain.is_ok(),
        "allowed_leaf_entity_types should accept matching leaf metadata entity types"
    );
}

// ── Optional local anchor policy pin ─────────────────────────────

fn resolve_pinned_policy(
    pin: Option<Value>,
    signed_policy: Option<Value>,
) -> Result<TrustChain, FederationError> {
    let now = 1_700_000_000;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";
    let anchor = TrustAnchor {
        entity_id: ta_id.into(),
        jwks: sample_jwks(),
        metadata_policy: pin,
    };
    let mut subordinate = sample_subordinate_statement(ta_id, leaf_id, now);
    subordinate.metadata_policy =
        signed_policy.map(|policy| must_ok(serde_json::from_value(policy)));
    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, sample_entity_config(leaf_id, now));
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(ta_id, leaf_id, subordinate);
    resolve_trust_chain_for_test(leaf_id, &[anchor], &fetcher, now)
}

fn valid_pin() -> Value {
    json!({"openid_relying_party":{"grant_types":{"subset_of":["authorization_code","refresh_token"]}}})
}

#[test]
fn anchor_policy_match_succeeds() {
    assert!(resolve_pinned_policy(Some(valid_pin()), Some(valid_pin())).is_ok());
}

#[test]
fn anchor_policy_mismatch_skips_anchor() {
    let other =
        json!({"openid_relying_party":{"grant_types":{"subset_of":["authorization_code"]}}});
    assert!(resolve_pinned_policy(Some(valid_pin()), Some(other)).is_err());
}

#[test]
fn anchor_policy_none_allows_signed_or_absent_policy() {
    assert!(resolve_pinned_policy(None, Some(valid_pin())).is_ok());
    assert!(resolve_pinned_policy(None, None).is_ok());
}

#[test]
fn anchor_policy_present_vs_sub_none_rejects() {
    assert!(resolve_pinned_policy(Some(valid_pin()), None).is_err());
}

#[test]
fn anchor_policy_invalid_empty_null_and_nested_forms_reject() {
    for invalid in [
        json!({}),
        Value::Null,
        json!(true),
        json!({"openid_relying_party":{}}),
        json!({"openid_relying_party":{"x":{}}}),
        json!({"openid_relying_party":{"x":{"add":[true]}}}),
    ] {
        assert!(resolve_pinned_policy(Some(invalid), None).is_err());
    }
}

#[test]
fn anchor_policy_array_order_remains_significant() {
    let reordered = json!({"openid_relying_party":{"grant_types":{"subset_of":["refresh_token","authorization_code"]}}});
    assert!(resolve_pinned_policy(Some(valid_pin()), Some(reordered)).is_err());
}

#[test]
fn anchor_policy_key_order_invariant_and_unknown_operators_retained() {
    let pin: Value = must_ok(serde_json::from_str(
        r#"{"openid_relying_party":{"x":{"extension":{"b":2,"a":1},"essential":false}}}"#,
    ));
    let reordered: Value = must_ok(serde_json::from_str(
        r#"{"openid_relying_party":{"x":{"essential":false,"extension":{"a":1,"b":2}}}}"#,
    ));
    assert!(resolve_pinned_policy(Some(pin.clone()), Some(reordered)).is_ok());
    assert!(resolve_pinned_policy(
        Some(pin),
        Some(json!({"openid_relying_party":{"x":{"essential":false}}}))
    )
    .is_err());
}
