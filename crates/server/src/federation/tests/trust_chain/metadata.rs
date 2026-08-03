// ── Trust Chain Metadata Resolution ──────────────────────────────

#[test]
fn trust_chain_resolved_metadata_no_policy() {
    let now = 1_700_000_000_i64;
    let leaf = sample_entity_config("https://rp.example.com", now);
    let sub_stmt =
        sample_subordinate_statement("https://ta.example.com", "https://rp.example.com", now);
    let ta = sample_entity_config("https://ta.example.com", now);

    let chain = TrustChain {
        chain: vec![leaf, sub_stmt, ta],
        anchor: TrustAnchor {
            entity_id: "https://ta.example.com".to_string(),
            jwks: sample_jwks(),
            metadata_policy: None,
        },
    };

    let resolved = must_some(must_ok(chain.resolved_metadata()));
    // No policy → metadata unchanged
    assert!(resolved.contains_key("openid_relying_party"));
}

#[test]
fn trust_chain_resolved_metadata_with_policy() {
    let now = 1_700_000_000_i64;
    let leaf = sample_entity_config("https://rp.example.com", now);

    let mut sub_stmt =
        sample_subordinate_statement("https://ta.example.com", "https://rp.example.com", now);
    sub_stmt.metadata_policy = Some(HashMap::from([(
        "openid_relying_party".to_string(),
        json!({
            "grant_types": {
                "subset_of": ["authorization_code"]
            }
        }),
    )]));

    let ta = sample_entity_config("https://ta.example.com", now);
    let chain = TrustChain {
        chain: vec![leaf, sub_stmt, ta],
        anchor: TrustAnchor {
            entity_id: "https://ta.example.com".to_string(),
            jwks: sample_jwks(),
            metadata_policy: None,
        },
    };

    let resolved = must_some(must_ok(chain.resolved_metadata()));
    let rp_metadata = &resolved["openid_relying_party"];
    // grant_types ["authorization_code"] is a subset of ["authorization_code"] → ok
    assert_eq!(rp_metadata["grant_types"], json!(["authorization_code"]));
}

#[test]
fn trust_chain_resolved_metadata_policy_violation() {
    let now = 1_700_000_000_i64;
    let mut leaf = sample_entity_config("https://rp.example.com", now);
    // Leaf claims implicit grant
    leaf.metadata = Some(HashMap::from([(
        "openid_relying_party".to_string(),
        json!({
            "grant_types": ["implicit"]
        }),
    )]));

    let mut sub_stmt =
        sample_subordinate_statement("https://ta.example.com", "https://rp.example.com", now);
    sub_stmt.metadata_policy = Some(HashMap::from([(
        "openid_relying_party".to_string(),
        json!({
            "grant_types": {
                "subset_of": ["authorization_code"]
            }
        }),
    )]));

    let ta = sample_entity_config("https://ta.example.com", now);
    let chain = TrustChain {
        chain: vec![leaf, sub_stmt, ta],
        anchor: TrustAnchor {
            entity_id: "https://ta.example.com".to_string(),
            jwks: sample_jwks(),
            metadata_policy: None,
        },
    };

    let err = must_err(chain.resolved_metadata());
    assert!(matches!(err, FederationError::MetadataPolicy(_)));
}

#[test]
fn trust_chain_no_metadata() {
    let now = 1_700_000_000_i64;
    let mut leaf = sample_entity_config("https://rp.example.com", now);
    leaf.metadata = None;

    let sub_stmt =
        sample_subordinate_statement("https://ta.example.com", "https://rp.example.com", now);
    let ta = sample_entity_config("https://ta.example.com", now);

    let chain = TrustChain {
        chain: vec![leaf, sub_stmt, ta],
        anchor: TrustAnchor {
            entity_id: "https://ta.example.com".to_string(),
            jwks: sample_jwks(),
            metadata_policy: None,
        },
    };

    assert!(must_ok(chain.resolved_metadata()).is_none());
}
