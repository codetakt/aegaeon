
// ---------------------------------------------------------------
// P1: connection_input_from_create / connection_input_from_update
// ---------------------------------------------------------------

#[test]
fn connection_input_from_create_defaults() {
    let req = CreateConnectionRequest {
        base_configuration_version_id: Uuid::nil().to_string(),
        connection_identifier: " my-conn ".to_string(),
        name: " My Connection ".to_string(),
        connection_type: None,
        issuer_url: " https://idp.example.com ".to_string(),
        client_id: " client123 ".to_string(),
        client_auth_method: None,
        client_secret: None,
        status: None,
        oauth_profile_id: None,
    };
    let input = connection_input_from_create(&req);
    assert_eq!(input.connection_identifier, "my-conn");
    assert_eq!(input.name, "My Connection");
    assert_eq!(input.connection_type, "OIDC");
    assert_eq!(input.client_auth_method, "client_secret_basic");
    assert_eq!(input.status, "ACTIVE");
}

#[test]
fn connection_input_from_update_preserves_existing() {
    let existing = Connection {
        id: Uuid::new_v4().to_string(),
        environment_id: Uuid::new_v4().to_string(),
        configuration_version_id: Uuid::new_v4().to_string(),
        oauth_profile_id: Some("old-profile".to_string()),
        connection_identifier: "old-conn".to_string(),
        name: "Old Name".to_string(),
        connection_type: "OIDC".to_string(),
        issuer_url: "https://old.example.com".to_string(),
        client_id: "old-client".to_string(),
        client_auth_method: "client_secret_post".to_string(),
        status: "ACTIVE".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    let req = UpdateConnectionRequest {
        base_configuration_version_id: Uuid::nil().to_string(),
        connection_identifier: None,
        name: Some(" New Name ".to_string()),
        connection_type: None,
        issuer_url: None,
        client_id: None,
        client_auth_method: None,
        client_secret: None,
        status: None,
        oauth_profile_id: None,
    };
    let input = connection_input_from_update(&existing, &req);
    assert_eq!(input.connection_identifier, "old-conn");
    assert_eq!(input.name, "New Name");
    assert_eq!(input.issuer_url, "https://old.example.com");
    assert_eq!(input.oauth_profile_id, Some("old-profile".to_string()));
}

#[test]
fn connection_input_from_update_clears_oauth_profile() {
    let existing = Connection {
        id: Uuid::new_v4().to_string(),
        environment_id: Uuid::new_v4().to_string(),
        configuration_version_id: Uuid::new_v4().to_string(),
        oauth_profile_id: Some("old-profile".to_string()),
        connection_identifier: "conn".to_string(),
        name: "Name".to_string(),
        connection_type: "OIDC".to_string(),
        issuer_url: "https://example.com".to_string(),
        client_id: "client".to_string(),
        client_auth_method: "none".to_string(),
        status: "ACTIVE".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    let req = UpdateConnectionRequest {
        base_configuration_version_id: Uuid::nil().to_string(),
        connection_identifier: None,
        name: None,
        connection_type: None,
        issuer_url: None,
        client_id: None,
        client_auth_method: None,
        client_secret: None,
        status: None,
        oauth_profile_id: Some(Some("  ".to_string())),
    };
    let input = connection_input_from_update(&existing, &req);
    assert_eq!(input.oauth_profile_id, None);
}

// ---------------------------------------------------------------
// P1: oauth_profile_input_from_create / oauth_profile_input_from_update
// ---------------------------------------------------------------

#[test]
fn oauth_profile_input_from_create_trims_fields() {
    let req = CreateOAuthProfileRequest {
        name: " My Profile ".to_string(),
        description: Some("  desc  ".to_string()),
        profile_type: " downstream ".to_string(),
        is_default: false,
        require_pkce: true,
        require_state_parameter: false,
        require_iss_parameter: false,
        sender_constrained: " none ".to_string(),
        enforce_refresh_sender_binding: false,
        allowed_grant_types: vec!["authorization_code".to_string()],
        token_endpoint_auth_methods_allowed: vec!["client_secret_basic".to_string()],
        expires_at: Some("  ".to_string()),
    };
    let input = oauth_profile_input_from_create(&req);
    assert_eq!(input.name, "My Profile");
    assert_eq!(input.description, Some("desc".to_string()));
    assert_eq!(input.profile_type, "downstream");
    assert_eq!(input.sender_constrained, "none");
    assert_eq!(input.expires_at, None);
}

#[test]
fn oauth_profile_input_from_update_uses_existing_for_unset() {
    let existing = OAuthProfile {
        id: Uuid::new_v4().to_string(),
        environment_id: Uuid::new_v4().to_string(),
        configuration_version_id: Uuid::new_v4().to_string(),
        name: "Old Name".to_string(),
        description: Some("Old Desc".to_string()),
        profile_type: "DOWNSTREAM".to_string(),
        is_default: false,
        require_pkce: true,
        require_state_parameter: false,
        require_iss_parameter: false,
        sender_constrained: "NONE".to_string(),
        enforce_refresh_sender_binding: false,
        allowed_grant_types: vec!["authorization_code".to_string()],
        token_endpoint_auth_methods_allowed: vec!["client_secret_basic".to_string()],
        expires_at: None,
        status: "ACTIVE".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    let req = UpdateOAuthProfileRequest {
        name: Some(" New Name ".to_string()),
        description: None,
        profile_type: None,
        is_default: None,
        require_pkce: None,
        require_state_parameter: None,
        require_iss_parameter: None,
        sender_constrained: None,
        enforce_refresh_sender_binding: None,
        allowed_grant_types: None,
        token_endpoint_auth_methods_allowed: None,
        expires_at: None,
    };
    let input = oauth_profile_input_from_update(&existing, &req);
    assert_eq!(input.name, "New Name");
    assert_eq!(input.description, Some("Old Desc".to_string()));
    assert_eq!(input.profile_type, "DOWNSTREAM");
}
