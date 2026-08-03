
// ---------------------------------------------------------------
// P1: validate_connection_input
// ---------------------------------------------------------------

fn valid_connection_input() -> ConnectionInput {
    ConnectionInput {
        connection_identifier: "my-conn".to_string(),
        name: "My Connection".to_string(),
        connection_type: "OIDC".to_string(),
        issuer_url: "https://idp.example.com".to_string(),
        client_id: "client123".to_string(),
        client_auth_method: "client_secret_basic".to_string(),
        status: "ACTIVE".to_string(),
        oauth_profile_id: None,
    }
}

fn valid_configuration_document_federation() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 1,
        "issuerHost": "issuer.example.com",
        "issuerUrl": "https://issuer.example.com",
        "federation": {
            "upstreamIssuer": "https://accounts.example.com",
            "clientId": "client-123",
            "redirectUri": "https://issuer.example.com/oauth2/callback",
            "jwksCache": {
                "jwksUri": "https://accounts.example.com/jwks",
                "maxAgeSeconds": 3600
            },
            "attributeMapping": [
                { "from": "groups", "to": "roles", "rule": "mapGroups" }
            ],
            "logout": {
                "backChannel": true,
                "sessionHintClaim": "sid",
                "recoveryPolicy": "force_prompt_login"
            }
        }
    })
}

#[test]
fn validate_configuration_document_federation_accepts_valid_minimal_block() {
    let document = valid_configuration_document_federation();
    assert!(validate_configuration_document_federation(&document, "req-1").is_ok());
}

#[test]
fn validate_configuration_document_federation_rejects_unknown_root_field() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["unexpected"] = serde_json::json!(true);

    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_unknown_jwks_cache_field() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["jwksCache"]["unexpected"] = serde_json::json!(true);

    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_unknown_attribute_mapping_field() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["attributeMapping"][0]["unexpected"] = serde_json::json!(true);

    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_unknown_claim_release_field() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["claimRelease"] = serde_json::json!([{
        "claim": "roles",
        "surfaces": ["userinfo"],
        "unexpected": true
    }]);

    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_unknown_jit_provisioning_field() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["jitProvisioning"] = serde_json::json!({
        "enabled": true,
        "unexpected": true
    });

    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_unknown_logout_field() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["logout"]["unexpected"] = serde_json::json!(true);

    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_invalid_upstream_issuer() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["upstreamIssuer"] = serde_json::json!("http://accounts.example.com");
    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_invalid_jwks_uri() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["jwksCache"]["jwksUri"] =
        serde_json::json!("https://accounts.example.com/jwks?cache=1");
    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_non_routable_urls() {
    let mut upstream = valid_configuration_document_federation();
    upstream["federation"]["upstreamIssuer"] = serde_json::json!("https://127.0.0.1");
    assert!(validate_configuration_document_federation(&upstream, "req-1").is_err());

    let mut jwks = valid_configuration_document_federation();
    jwks["federation"]["jwksCache"]["jwksUri"] = serde_json::json!("https://[fc00::1]/jwks");
    assert!(validate_configuration_document_federation(&jwks, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_embedded_secret() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["clientSecret"] = serde_json::json!("super-secret");
    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[tokio::test]
async fn validate_configuration_document_federation_url_error_details_do_not_echo_input_url(
) -> TestResult {
    let sensitive_uri = "https://accounts.example.com/jwks?client_secret=hidden";
    let mut document = valid_configuration_document_federation();
    document["federation"]["jwksCache"]["jwksUri"] = serde_json::json!(sensitive_uri);

    let response = must_err!(
        validate_configuration_document_federation(&document, "req-1"),
        "secret-bearing federation URL must be rejected",
    );
    let body = management_error_response_body(response).await?;
    assert_eq!(
        body.details.as_ref(),
        Some(&serde_json::json!({
            "field": "configurationDocument.federation.jwksCache.jwksUri"
        }))
    );
    let serialized = serde_json::to_string(&body)?;
    assert!(!serialized.contains(sensitive_uri));
    assert!(!serialized.contains("client_secret"));
    assert!(!serialized.contains("hidden"));
    Ok(())
}

#[test]
fn validate_configuration_document_federation_rejects_empty_attribute_mapping_from() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["attributeMapping"] =
        serde_json::json!([{ "from": "   ", "to": "roles" }]);
    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_unsupported_attribute_mapping_target() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["attributeMapping"] =
        serde_json::json!([{ "from": "avatar", "to": "picture" }]);
    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_unknown_attribute_mapping_rule() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["attributeMapping"] =
        serde_json::json!([{ "from": "groups", "to": "roles", "rule": "explode" }]);
    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_accepts_valid_claim_release_policy() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["attributeMapping"] = serde_json::json!([
        { "from": "groups", "to": "roles", "rule": "mapGroups" },
        { "from": "department", "to": "organization" }
    ]);
    document["federation"]["claimRelease"] = serde_json::json!([
        { "claim": "roles", "surfaces": ["userinfo"] },
        { "claim": "organization", "surfaces": ["id_token", "userinfo"] }
    ]);
    assert!(validate_configuration_document_federation(&document, "req-1").is_ok());
}

#[test]
fn validate_configuration_document_federation_rejects_claim_release_for_unknown_custom_claim() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["claimRelease"] =
        serde_json::json!([{ "claim": "department", "surfaces": ["userinfo"] }]);
    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_claim_release_with_invalid_surface() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["claimRelease"] =
        serde_json::json!([{ "claim": "roles", "surfaces": ["access_token"] }]);
    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_accepts_valid_jit_provisioning_policy() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["jitProvisioning"] = serde_json::json!({
        "enabled": true,
        "domainAllowlist": ["example.com"],
        "collisionPolicy": "reuse_existing_email",
        "initialStatus": "BLOCKED"
    });
    assert!(validate_configuration_document_federation(&document, "req-1").is_ok());
}

#[test]
fn validate_configuration_document_federation_rejects_invalid_jit_allowlist_domain() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["jitProvisioning"] = serde_json::json!({
        "enabled": true,
        "domainAllowlist": ["bad domain"]
    });
    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_invalid_jit_collision_policy() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["jitProvisioning"] = serde_json::json!({
        "enabled": true,
        "collisionPolicy": "merge"
    });
    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_invalid_jit_initial_status() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["jitProvisioning"] = serde_json::json!({
        "enabled": true,
        "initialStatus": "DELETED"
    });
    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_logout_without_backchannel() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["logout"] = serde_json::json!({
        "sessionHintClaim": "sid"
    });
    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}

#[test]
fn validate_configuration_document_federation_rejects_invalid_logout_recovery_policy() {
    let mut document = valid_configuration_document_federation();
    document["federation"]["logout"]["recoveryPolicy"] = serde_json::json!("ignore");
    assert!(validate_configuration_document_federation(&document, "req-1").is_err());
}
