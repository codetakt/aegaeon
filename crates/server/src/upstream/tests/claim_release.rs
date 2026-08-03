use super::*;

#[test]
fn parse_upstream_claim_release_policy_defaults_managed_custom_claims_to_blocked() {
    let federation = json!({
        "attributeMapping": [
            { "from": "groups", "to": "roles", "rule": "mapGroups" },
            { "from": "department", "to": "organization" },
            { "from": "email", "to": "email", "rule": "lower" }
        ]
    });
    let attribute_mappings = must_ok(parse_upstream_attribute_mappings(Some(&federation)));

    let policy = must_some(must_ok(parse_upstream_claim_release_policy(
        Some(&federation),
        &attribute_mappings,
    )));

    assert_eq!(
        policy.managed_custom_claims,
        vec!["organization".to_string(), "roles".to_string()]
    );
    assert!(policy.id_token_custom_claims.is_empty());
    assert!(policy.userinfo_custom_claims.is_empty());
}

#[test]
fn parse_upstream_claim_release_policy_accepts_supported_surfaces() {
    let federation = json!({
        "attributeMapping": [
            { "from": "groups", "to": "roles", "rule": "mapGroups" },
            { "from": "department", "to": "organization" }
        ],
        "claimRelease": [
            { "claim": "roles", "surfaces": ["id_token", "userinfo"] },
            { "claim": "organization", "surfaces": ["userinfo"] }
        ]
    });
    let attribute_mappings = must_ok(parse_upstream_attribute_mappings(Some(&federation)));

    let policy = must_some(must_ok(parse_upstream_claim_release_policy(
        Some(&federation),
        &attribute_mappings,
    )));

    assert_eq!(policy.id_token_custom_claims, vec!["roles".to_string()]);
    assert_eq!(
        policy.userinfo_custom_claims,
        vec!["organization".to_string(), "roles".to_string()]
    );
}

#[test]
fn parse_upstream_claim_release_policy_rejects_unknown_custom_claim() {
    let federation = json!({
        "attributeMapping": [
            { "from": "groups", "to": "roles", "rule": "mapGroups" }
        ],
        "claimRelease": [
            { "claim": "department", "surfaces": ["userinfo"] }
        ]
    });
    let attribute_mappings = must_ok(parse_upstream_attribute_mappings(Some(&federation)));

    let err = must_err(parse_upstream_claim_release_policy(
        Some(&federation),
        &attribute_mappings,
    ));

    assert!(err.contains("claimRelease[].claim"));
}

#[test]
fn filter_downstream_custom_claims_blocks_unreleased_managed_claims() {
    let mut custom_claims = HashMap::new();
    custom_claims.insert("roles".to_string(), json!(["admins"]));
    custom_claims.insert("organization".to_string(), json!("Platform"));
    custom_claims.insert("department".to_string(), json!("Identity"));

    let policy = super::UpstreamClaimReleasePolicy {
        managed_custom_claims: vec!["organization".to_string(), "roles".to_string()],
        id_token_custom_claims: vec!["organization".to_string()],
        userinfo_custom_claims: vec!["roles".to_string()],
    };

    let id_token_claims = filter_downstream_custom_claims(
        &custom_claims,
        Some(&policy),
        DownstreamClaimSurface::IdToken,
    );
    assert_eq!(
        id_token_claims.get("organization"),
        Some(&json!("Platform"))
    );
    assert_eq!(id_token_claims.get("department"), Some(&json!("Identity")));
    assert!(!id_token_claims.contains_key("roles"));

    let userinfo_claims = filter_downstream_custom_claims(
        &custom_claims,
        Some(&policy),
        DownstreamClaimSurface::Userinfo,
    );
    assert_eq!(userinfo_claims.get("roles"), Some(&json!(["admins"])));
    assert_eq!(userinfo_claims.get("department"), Some(&json!("Identity")));
    assert!(!userinfo_claims.contains_key("organization"));
}
