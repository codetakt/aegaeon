// ── StoredTrustAnchor Conversion ────────────────────────────────

#[test]
fn stored_trust_anchor_to_trust_anchor() {
    let stored = StoredTrustAnchor {
        id: Uuid::new_v4(),
        environment_id: Uuid::new_v4(),
        entity_id: "https://ta.example.com".to_string(),
        jwks: sample_jwks_value(),
        metadata_policy: None,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
    };

    let ta = must_ok(stored.to_trust_anchor());
    assert_eq!(ta.entity_id, "https://ta.example.com");
    assert_eq!(ta.jwks.keys().len(), 1);
}

#[test]
fn stored_trust_anchor_invalid_jwks() {
    let stored = StoredTrustAnchor {
        id: Uuid::new_v4(),
        environment_id: Uuid::new_v4(),
        entity_id: "https://ta.example.com".to_string(),
        jwks: json!({"not": "a valid jwks"}),
        metadata_policy: None,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
    };

    assert!(stored.to_trust_anchor().is_err());
}

// ── InMemoryTrustAnchorRepo ─────────────────────────────────────

#[test]
fn trust_anchor_repo_crud() {
    let repo = InMemoryTrustAnchorRepo::new();
    let env_id = Uuid::new_v4();
    let jwks = sample_jwks_value();

    // Initially empty
    let anchors = must_ok(repo.list_for_environment(env_id));
    assert!(anchors.is_empty());

    // Insert
    let anchor = must_ok(repo.upsert(env_id, "https://ta.example.com", &jwks, None));
    assert_eq!(anchor.entity_id, "https://ta.example.com");
    assert_eq!(anchor.environment_id, env_id);

    // Get
    let fetched = must_ok(repo.get(env_id, "https://ta.example.com"));
    assert!(fetched.is_some());
    assert_eq!(must_some(fetched).entity_id, "https://ta.example.com");

    // Get non-existent
    let missing = must_ok(repo.get(env_id, "https://other.example.com"));
    assert!(missing.is_none());

    // List
    let anchors = must_ok(repo.list_for_environment(env_id));
    assert_eq!(anchors.len(), 1);

    // Different environment should be empty
    let other_env = Uuid::new_v4();
    let anchors = must_ok(repo.list_for_environment(other_env));
    assert!(anchors.is_empty());

    // Update (upsert)
    let new_jwks = json!({"keys": []});
    let updated = must_ok(repo.upsert(env_id, "https://ta.example.com", &new_jwks, None));
    assert_eq!(updated.jwks, new_jwks);
    assert_eq!(must_ok(repo.list_for_environment(env_id)).len(), 1);

    // Delete
    let deleted = must_ok(repo.delete(env_id, "https://ta.example.com"));
    assert!(deleted);
    assert!(must_ok(repo.list_for_environment(env_id)).is_empty());

    // Delete non-existent
    let deleted = must_ok(repo.delete(env_id, "https://ta.example.com"));
    assert!(!deleted);
}

#[test]
fn trust_anchor_repo_multiple_environments() {
    let repo = InMemoryTrustAnchorRepo::new();
    let env1 = Uuid::new_v4();
    let env2 = Uuid::new_v4();
    let jwks = sample_jwks_value();

    let _ = must_ok(repo.upsert(env1, "https://ta1.example.com", &jwks, None));
    let _ = must_ok(repo.upsert(env2, "https://ta2.example.com", &jwks, None));
    let _ = must_ok(repo.upsert(env1, "https://ta3.example.com", &jwks, None));

    assert_eq!(must_ok(repo.list_for_environment(env1)).len(), 2);
    assert_eq!(must_ok(repo.list_for_environment(env2)).len(), 1);
}

#[test]
fn trust_anchor_repo_metadata_policy() {
    let repo = InMemoryTrustAnchorRepo::new();
    let env_id = Uuid::new_v4();
    let jwks = sample_jwks_value();
    let policy = json!({
        "openid_relying_party": {
            "grant_types": { "subset_of": ["authorization_code"] }
        }
    });

    let anchor = must_ok(repo.upsert(env_id, "https://ta.example.com", &jwks, Some(&policy)));
    assert_eq!(anchor.metadata_policy, Some(policy));
}
