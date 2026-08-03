// ── Metadata Policy ──────────────────────────────────────────────

#[test]
fn metadata_policy_value_operator() {
    let metadata = json!({
        "grant_types": ["authorization_code", "refresh_token"]
    });
    let policy = json!({
        "grant_types": { "value": ["authorization_code"] }
    });
    let result = must_ok(apply_metadata_policy(&metadata, &policy));
    assert_eq!(result["grant_types"], json!(["authorization_code"]));
}

#[test]
fn metadata_policy_default_operator() {
    let metadata = json!({
        "response_types": ["code"]
    });
    let policy = json!({
        "grant_types": { "default": ["authorization_code"] }
    });
    let result = must_ok(apply_metadata_policy(&metadata, &policy));
    // grant_types was absent, so default is applied
    assert_eq!(result["grant_types"], json!(["authorization_code"]));
    // response_types is untouched
    assert_eq!(result["response_types"], json!(["code"]));
}

#[test]
fn metadata_policy_default_not_applied_if_present() {
    let metadata = json!({
        "grant_types": ["refresh_token"]
    });
    let policy = json!({
        "grant_types": { "default": ["authorization_code"] }
    });
    let result = must_ok(apply_metadata_policy(&metadata, &policy));
    // grant_types already present, default not applied
    assert_eq!(result["grant_types"], json!(["refresh_token"]));
}

#[test]
fn metadata_policy_essential_present() {
    let metadata = json!({
        "redirect_uris": ["https://rp.example.com/callback"]
    });
    let policy = json!({
        "redirect_uris": { "essential": true }
    });
    assert!(apply_metadata_policy(&metadata, &policy).is_ok());
}

#[test]
fn metadata_policy_essential_missing() {
    let metadata = json!({});
    let policy = json!({
        "redirect_uris": { "essential": true }
    });
    let err = must_err(apply_metadata_policy(&metadata, &policy));
    assert!(matches!(err, FederationError::MetadataPolicy(_)));
}

#[test]
fn metadata_policy_one_of_valid() {
    let metadata = json!({
        "id_token_signed_response_alg": "ES256"
    });
    let policy = json!({
        "id_token_signed_response_alg": { "one_of": ["ES256", "RS256"] }
    });
    assert!(apply_metadata_policy(&metadata, &policy).is_ok());
}

#[test]
fn metadata_policy_one_of_invalid() {
    let metadata = json!({
        "id_token_signed_response_alg": "HS256"
    });
    let policy = json!({
        "id_token_signed_response_alg": { "one_of": ["ES256", "RS256"] }
    });
    let err = must_err(apply_metadata_policy(&metadata, &policy));
    assert!(matches!(err, FederationError::MetadataPolicy(_)));
}

#[test]
fn metadata_policy_subset_of_valid() {
    let metadata = json!({
        "grant_types": ["authorization_code"]
    });
    let policy = json!({
        "grant_types": { "subset_of": ["authorization_code", "refresh_token"] }
    });
    assert!(apply_metadata_policy(&metadata, &policy).is_ok());
}

#[test]
fn metadata_policy_subset_of_invalid() {
    let metadata = json!({
        "grant_types": ["authorization_code", "implicit"]
    });
    let policy = json!({
        "grant_types": { "subset_of": ["authorization_code", "refresh_token"] }
    });
    let err = must_err(apply_metadata_policy(&metadata, &policy));
    assert!(matches!(err, FederationError::MetadataPolicy(_)));
}

#[test]
fn metadata_policy_superset_of_valid() {
    let metadata = json!({
        "grant_types": ["authorization_code", "refresh_token", "client_credentials"]
    });
    let policy = json!({
        "grant_types": { "superset_of": ["authorization_code", "refresh_token"] }
    });
    assert!(apply_metadata_policy(&metadata, &policy).is_ok());
}

#[test]
fn metadata_policy_superset_of_invalid() {
    let metadata = json!({
        "grant_types": ["authorization_code"]
    });
    let policy = json!({
        "grant_types": { "superset_of": ["authorization_code", "refresh_token"] }
    });
    let err = must_err(apply_metadata_policy(&metadata, &policy));
    assert!(matches!(err, FederationError::MetadataPolicy(_)));
}

#[test]
fn metadata_policy_add_operator() {
    let metadata = json!({
        "grant_types": ["authorization_code"]
    });
    let policy = json!({
        "grant_types": { "add": ["refresh_token"] }
    });
    let result = must_ok(apply_metadata_policy(&metadata, &policy));
    let grant_types = must_some(result["grant_types"].as_array());
    assert!(grant_types.contains(&json!("authorization_code")));
    assert!(grant_types.contains(&json!("refresh_token")));
}

#[test]
fn metadata_policy_add_no_duplicates() {
    let metadata = json!({
        "grant_types": ["authorization_code"]
    });
    let policy = json!({
        "grant_types": { "add": ["authorization_code"] }
    });
    let result = must_ok(apply_metadata_policy(&metadata, &policy));
    let grant_types = must_some(result["grant_types"].as_array());
    assert_eq!(grant_types.len(), 1);
}

#[test]
fn metadata_policy_rejects_unknown_operator() {
    let metadata = json!({
        "grant_types": ["authorization_code"]
    });
    let policy = json!({
        "grant_types": { "unknown_operator": ["authorization_code"] }
    });
    let err = must_err(apply_metadata_policy(&metadata, &policy));
    assert!(matches!(err, FederationError::MetadataPolicy(_)));
}

#[test]
fn metadata_policy_rejects_malformed_operator_shapes() {
    let metadata = json!({
        "grant_types": ["authorization_code"]
    });
    let cases = vec![
        json!({ "grant_types": { "intersect": "authorization_code" } }),
        json!({ "grant_types": { "one_of": "authorization_code" } }),
        json!({ "grant_types": { "subset_of": "authorization_code" } }),
        json!({ "grant_types": { "superset_of": "authorization_code" } }),
        json!({ "grant_types": { "essential": "true" } }),
    ];

    for policy in cases {
        let err = must_err(apply_metadata_policy(&metadata, &policy));
        assert!(matches!(err, FederationError::MetadataPolicy(_)));
    }
}

#[test]
fn metadata_policy_rejects_array_operators_against_non_array_values() {
    let metadata = json!({
        "grant_types": "authorization_code"
    });
    let cases = vec![
        json!({ "grant_types": { "add": ["refresh_token"] } }),
        json!({ "grant_types": { "intersect": ["authorization_code"] } }),
        json!({ "grant_types": { "subset_of": ["authorization_code"] } }),
        json!({ "grant_types": { "superset_of": ["authorization_code"] } }),
    ];

    for policy in cases {
        let err = must_err(apply_metadata_policy(&metadata, &policy));
        assert!(matches!(err, FederationError::MetadataPolicy(_)));
    }
}

#[test]
fn metadata_policy_combined_operators() {
    let metadata = json!({
        "grant_types": ["authorization_code"]
    });
    let policy = json!({
        "grant_types": {
            "subset_of": ["authorization_code", "refresh_token"],
            "default": ["client_credentials"]
        },
        "response_types": {
            "default": ["code"],
            "essential": true
        }
    });
    let result = must_ok(apply_metadata_policy(&metadata, &policy));
    assert_eq!(result["grant_types"], json!(["authorization_code"]));
    assert_eq!(result["response_types"], json!(["code"]));
}

// ── Metadata Policy: intersect operator ─────────────────────────

#[test]
fn metadata_policy_intersect_operator() {
    let metadata = json!({
        "grant_types": ["authorization_code", "refresh_token", "implicit"]
    });
    let policy = json!({
        "grant_types": { "intersect": ["authorization_code", "refresh_token"] }
    });
    let result = must_ok(apply_metadata_policy(&metadata, &policy));
    let grant_types = must_some(result["grant_types"].as_array());
    assert_eq!(grant_types.len(), 2);
    assert!(grant_types.contains(&json!("authorization_code")));
    assert!(grant_types.contains(&json!("refresh_token")));
}

#[test]
fn metadata_policy_intersect_empty_result() {
    let metadata = json!({
        "grant_types": ["implicit"]
    });
    let policy = json!({
        "grant_types": { "intersect": ["authorization_code", "refresh_token"] }
    });
    let result = must_ok(apply_metadata_policy(&metadata, &policy));
    let grant_types = must_some(result["grant_types"].as_array());
    assert!(grant_types.is_empty());
}

#[test]
fn metadata_policy_intersect_with_subset_of() {
    let metadata = json!({
        "grant_types": ["authorization_code", "refresh_token", "implicit"]
    });
    let policy = json!({
        "grant_types": {
            "intersect": ["authorization_code", "refresh_token"],
            "subset_of": ["authorization_code", "refresh_token"]
        }
    });
    let result = must_ok(apply_metadata_policy(&metadata, &policy));
    let grant_types = must_some(result["grant_types"].as_array());
    assert_eq!(grant_types.len(), 2);
}
