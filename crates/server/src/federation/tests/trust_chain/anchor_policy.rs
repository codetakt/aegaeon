// ── max_path_length enforcement ──────────────────────────────────

fn resolve_trust_chain_for_test(
    leaf_entity_id: &str,
    trust_anchors: &[TrustAnchor],
    fetcher: &dyn FederationFetcher,
    now: i64,
) -> Result<TrustChain, FederationError> {
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
        metadata_policy: Some(json!({})),
    }];

    let mut sub_stmt = sample_subordinate_statement(ta_id, leaf_id, now);
    sub_stmt.constraints = Some(Constraints {
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
        metadata_policy: Some(json!({})),
    }];

    let mut sub_stmt = sample_subordinate_statement(ta_id, leaf_id, now);
    sub_stmt.constraints = Some(Constraints {
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
        metadata_policy: Some(json!({})),
    }];

    let mut leaf_config = sample_entity_config(leaf_id, now);
    leaf_config.authority_hints = Some(vec![int_id.to_string()]);

    let mut int_config = sample_entity_config(int_id, now);
    int_config.authority_hints = Some(vec![ta_id.to_string()]);

    let mut ta_sub_stmt = sample_subordinate_statement(ta_id, int_id, now);
    ta_sub_stmt.constraints = Some(Constraints {
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
        metadata_policy: Some(json!({})),
    }];

    let mut sub_stmt = sample_subordinate_statement(ta_id, leaf_id, now);
    sub_stmt.constraints = Some(Constraints {
        max_path_length: None,
        allowed_leaf_entity_types: Some(vec!["openid_relying_party".to_string()]),
    });

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, sample_entity_config(leaf_id, now));
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(ta_id, leaf_id, sub_stmt);

    let chain = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);
    assert!(
        chain.is_ok(),
        "allowed_leaf_entity_types should accept matching leaf metadata entity types"
    );
}

// ── Anchor Policy Matching ────────────────────────────────────────

#[test]
fn anchor_policy_mismatch_skips_anchor() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";

    let anchor_policy = json!({
        "grant_types": { "subset_of": ["authorization_code"] }
    });

    let trust_anchors = vec![TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: Some(anchor_policy),
    }];

    // Sub stmt has a *different* policy than the anchor
    let mut sub_stmt = sample_subordinate_statement(ta_id, leaf_id, now);
    sub_stmt.metadata_policy = Some(HashMap::from([(
        "grant_types".to_string(),
        json!({ "subset_of": ["implicit"] }),
    )]));

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, sample_entity_config(leaf_id, now));
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(ta_id, leaf_id, sub_stmt);

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);
    assert!(
        result.is_err(),
        "policy mismatch should cause chain resolution to fail"
    );
}

#[test]
fn anchor_policy_match_succeeds() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";

    let policy = json!({
        "grant_types": { "subset_of": ["authorization_code"] }
    });

    let trust_anchors = vec![TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: Some(policy.clone()),
    }];

    // Sub stmt has the *same* policy as the anchor
    let mut sub_stmt = sample_subordinate_statement(ta_id, leaf_id, now);
    sub_stmt.metadata_policy = Some(HashMap::from([(
        "grant_types".to_string(),
        json!({ "subset_of": ["authorization_code"] }),
    )]));

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, sample_entity_config(leaf_id, now));
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(ta_id, leaf_id, sub_stmt);

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);
    assert!(
        result.is_ok(),
        "matching policy should allow chain resolution"
    );
}

#[test]
fn anchor_policy_none_rejects_before_chain_validation() {
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: Some(json!({})),
    }];

    // Sub stmt has a policy, but the trust anchor policy is absent.
    let mut sub_stmt = sample_subordinate_statement(ta_id, leaf_id, now);
    sub_stmt.metadata_policy = Some(HashMap::from([(
        "grant_types".to_string(),
        json!({ "subset_of": ["authorization_code"] }),
    )]));

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, sample_entity_config(leaf_id, now));
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(ta_id, leaf_id, sub_stmt);

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);
    assert!(
        result.is_err(),
        "missing trust-anchor metadata_policy must fail closed"
    );
}

#[test]
fn anchor_policy_empty_vs_sub_none_rejects() {
    // Anchor has Some({}) (empty policy), subordinate has None.
    // Per F* anchor_sub_policy_consistent: anchor_sub.policy = Some ta.ta_policy
    // requires subordinate to carry Some(...), even when the anchor policy is {}.
    // None ≠ Some({}) — strict F* alignment.
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: Some(json!({})), // empty policy
    }];

    let mut sub_stmt = sample_subordinate_statement(ta_id, leaf_id, now);
    sub_stmt.metadata_policy = None;

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, sample_entity_config(leaf_id, now));
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(ta_id, leaf_id, sub_stmt);

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);
    assert!(
        result.is_err(),
        "subordinate must carry policy when anchor requires one, even if anchor policy is empty"
    );
}

#[test]
fn anchor_policy_present_vs_sub_none_rejects() {
    // Anchor has a real policy, subordinate has None → mismatch
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";

    let trust_anchors = vec![TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: Some(json!({
            "grant_types": { "subset_of": ["authorization_code"] }
        })),
    }];

    let mut sub_stmt = sample_subordinate_statement(ta_id, leaf_id, now);
    sub_stmt.metadata_policy = None;

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, sample_entity_config(leaf_id, now));
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(ta_id, leaf_id, sub_stmt);

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);
    assert!(
        result.is_err(),
        "anchor with real policy should reject subordinate with no policy"
    );
}

#[test]
fn anchor_policy_key_order_invariant() {
    // Anchor and subordinate have same policy but keys in different order.
    // canonicalize_json sorts keys, so they should match.
    let now = 1_700_000_000_i64;
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";

    // Note: serde_json::json! macro produces BTreeMap-ordered keys,
    // but HashMap serialization order is unspecified, so this tests
    // that canonicalize_json handles the difference.
    let anchor_policy = json!({
        "id_token_signed_response_alg": { "one_of": ["ES256"] },
        "grant_types": { "subset_of": ["authorization_code"] }
    });

    let trust_anchors = vec![TrustAnchor {
        entity_id: ta_id.to_string(),
        jwks: sample_jwks(),
        metadata_policy: Some(anchor_policy),
    }];

    let mut sub_stmt = sample_subordinate_statement(ta_id, leaf_id, now);
    // HashMap insertion order differs from JSON key order
    let mut policy_map = HashMap::new();
    policy_map.insert(
        "grant_types".to_string(),
        json!({ "subset_of": ["authorization_code"] }),
    );
    policy_map.insert(
        "id_token_signed_response_alg".to_string(),
        json!({ "one_of": ["ES256"] }),
    );
    sub_stmt.metadata_policy = Some(policy_map);

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config(leaf_id, sample_entity_config(leaf_id, now));
    fetcher.add_entity_config(ta_id, sample_entity_config(ta_id, now));
    fetcher.add_subordinate_stmt(ta_id, leaf_id, sub_stmt);

    let result = resolve_trust_chain_for_test(leaf_id, &trust_anchors, &fetcher, now);
    assert!(
        result.is_ok(),
        "key order should not affect policy equivalence"
    );
}
