use super::*;

#[test]
fn parse_upstream_attribute_mappings_accepts_supported_targets_and_rules() {
    let federation = json!({
        "attributeMapping": [
            { "from": "groups", "to": "roles", "rule": "mapGroups" },
            { "from": "email", "to": "email", "rule": "lower" },
            { "from": "displayName", "to": "name" }
        ]
    });

    let mappings = must_ok(parse_upstream_attribute_mappings(Some(&federation)));

    assert_eq!(mappings.len(), 3);
    assert!(matches!(
        mappings[0].target,
        UpstreamAttributeMappingTarget::Custom(ref target) if target == "roles"
    ));
    assert_eq!(mappings[0].rule, UpstreamAttributeMappingRule::MapGroups);
    assert_eq!(mappings[1].rule, UpstreamAttributeMappingRule::Lower);
    assert!(matches!(
        mappings[2].target,
        UpstreamAttributeMappingTarget::DisplayName
    ));
}

#[test]
fn parse_upstream_attribute_mappings_rejects_unsupported_reserved_target() {
    let federation = json!({
        "attributeMapping": [
            { "from": "avatar", "to": "picture" }
        ]
    });

    let err = must_err(parse_upstream_attribute_mappings(Some(&federation)));

    assert!(err.contains("attributeMapping[].to"));
}

#[test]
fn project_upstream_attribute_mappings_maps_supported_targets() {
    let mut additional_claims = HashMap::new();
    additional_claims.insert("email".to_string(), json!("USER@Example.com"));
    additional_claims.insert("displayName".to_string(), json!("Jane Doe"));
    additional_claims.insert("emailVerified".to_string(), json!(true));
    additional_claims.insert(
        "groups".to_string(),
        json!(["Admins", "Developers", "admins"]),
    );
    additional_claims.insert("department".to_string(), json!("Platform"));

    let id_token = IdToken {
        claims: IdTokenClaims {
            iss: "https://issuer.example".to_string(),
            sub: "subject-123".to_string(),
            aud: Audience::Single("client".to_string()),
            exp: 10,
            iat: 1,
            auth_time: Some(1),
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            sid: None,
            at_hash: None,
            c_hash: None,
            nbf: None,
            jti: None,
            additional_claims,
        },
        signing_alg: "RS256".to_string(),
    };
    let mappings = vec![
        UpstreamAttributeMapping {
            from: "groups".to_string(),
            target: UpstreamAttributeMappingTarget::Custom("roles".to_string()),
            rule: UpstreamAttributeMappingRule::MapGroups,
        },
        UpstreamAttributeMapping {
            from: "department".to_string(),
            target: UpstreamAttributeMappingTarget::Custom("organization".to_string()),
            rule: UpstreamAttributeMappingRule::Copy,
        },
        UpstreamAttributeMapping {
            from: "email".to_string(),
            target: UpstreamAttributeMappingTarget::Email,
            rule: UpstreamAttributeMappingRule::Lower,
        },
        UpstreamAttributeMapping {
            from: "displayName".to_string(),
            target: UpstreamAttributeMappingTarget::DisplayName,
            rule: UpstreamAttributeMappingRule::Copy,
        },
        UpstreamAttributeMapping {
            from: "emailVerified".to_string(),
            target: UpstreamAttributeMappingTarget::EmailVerified,
            rule: UpstreamAttributeMappingRule::Copy,
        },
    ];

    let projection = must_ok(project_upstream_attribute_mappings(&mappings, &id_token));

    assert_eq!(projection.email, Some(Some("user@example.com".to_string())));
    assert_eq!(projection.email_verified, Some(true));
    assert_eq!(projection.display_name, Some(Some("Jane Doe".to_string())));
    assert_eq!(
        projection.custom_claims.get("roles"),
        Some(&json!(["admins", "developers"]))
    );
    assert_eq!(
        projection.custom_claims.get("organization"),
        Some(&json!("Platform"))
    );

    let merged = merge_upstream_custom_claims(
        &json!({
            "legacy": "keep",
            "roles": ["old-role"],
        }),
        &projection,
    );
    assert_eq!(
        merged,
        json!({
            "legacy": "keep",
            "roles": ["admins", "developers"],
            "organization": "Platform",
        })
    );
}
