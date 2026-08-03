fn valid_client_input() -> ClientInput {
    ClientInput {
        client_identifier: "client-1".to_string(),
        name: "Client One".to_string(),
        client_type: "CONFIDENTIAL".to_string(),
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        allowed_scopes: vec!["read".to_string()],
        token_endpoint_authentication_method: "client_secret_basic".to_string(),
        oauth_profile_id: None,
    }
}

fn valid_client_record(client_type: &str, auth_method: &str) -> Client {
    Client {
        id: Uuid::new_v4().to_string(),
        environment_id: Uuid::new_v4().to_string(),
        oauth_profile_id: None,
        client_identifier: "client-1".to_string(),
        name: "Client One".to_string(),
        client_type: client_type.to_string(),
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        allowed_scopes: vec!["read".to_string()],
        token_endpoint_authentication_method: auth_method.to_string(),
        created_at: "2026-01-01T00:00:00.000Z".to_string(),
        updated_at: "2026-01-01T00:00:00.000Z".to_string(),
    }
}

#[test]
fn validate_management_client_input_normalizes_lists_and_auth_method() {
    let mut input = valid_client_input();
    input.client_identifier = " client-1 ".to_string();
    input.name = " Client One ".to_string();
    input.client_type = " CONFIDENTIAL ".to_string();
    input.allowed_grant_types = vec![
        " AUTHORIZATION_CODE ".to_string(),
        "authorization_code".to_string(),
    ];
    input.allowed_scopes = vec![" read ".to_string(), "read".to_string()];
    input.token_endpoint_authentication_method = " CLIENT_SECRET_POST ".to_string();

    assert!(validate_management_client_input(&mut input, "req-1").is_ok());
    assert_eq!(input.client_identifier, "client-1");
    assert_eq!(input.name, "Client One");
    assert_eq!(input.client_type, "CONFIDENTIAL");
    assert_eq!(input.allowed_grant_types, vec!["authorization_code"]);
    assert_eq!(input.allowed_scopes, vec!["read"]);
    assert_eq!(
        input.token_endpoint_authentication_method,
        "client_secret_post"
    );
}

#[test]
fn validate_management_client_input_rejects_malformed_allowed_scope_entries() {
    let mut blank_scope = valid_client_input();
    blank_scope.allowed_scopes = vec![" ".to_string()];
    assert!(validate_management_client_input(&mut blank_scope, "req-1").is_err());

    let mut joined_scope = valid_client_input();
    joined_scope.allowed_scopes = vec!["read write".to_string()];
    assert!(validate_management_client_input(&mut joined_scope, "req-1").is_err());

    let mut tabbed_scope = valid_client_input();
    tabbed_scope.allowed_scopes = vec!["read\twrite".to_string()];
    assert!(validate_management_client_input(&mut tabbed_scope, "req-1").is_err());
}

#[test]
fn validate_management_client_input_rejects_empty_grants() {
    let mut empty_grants = valid_client_input();
    empty_grants.allowed_grant_types = vec![" ".to_string()];
    assert!(validate_management_client_input(&mut empty_grants, "req-1").is_err());
}

#[test]
fn validate_management_client_input_rejects_unsupported_grants() {
    let mut input = valid_client_input();
    input.allowed_grant_types = vec!["authorization_code".to_string(), "urn:custom".to_string()];

    assert!(validate_management_client_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_management_client_input_rejects_empty_identity_fields() {
    let mut empty_identifier = valid_client_input();
    empty_identifier.client_identifier = " ".to_string();
    assert!(validate_management_client_input(&mut empty_identifier, "req-1").is_err());

    let mut empty_name = valid_client_input();
    empty_name.name = " ".to_string();
    assert!(validate_management_client_input(&mut empty_name, "req-1").is_err());

    let mut empty_type = valid_client_input();
    empty_type.client_type = " ".to_string();
    assert!(validate_management_client_input(&mut empty_type, "req-1").is_err());
}

#[test]
fn validate_management_client_input_enforces_auth_method_by_client_type() {
    let mut public_secret = valid_client_input();
    public_secret.client_type = "PUBLIC".to_string();
    public_secret.token_endpoint_authentication_method = "client_secret_basic".to_string();
    assert!(validate_management_client_input(&mut public_secret, "req-1").is_err());

    let mut confidential_none = valid_client_input();
    confidential_none.token_endpoint_authentication_method = "none".to_string();
    assert!(validate_management_client_input(&mut confidential_none, "req-1").is_err());

    let mut public_none = valid_client_input();
    public_none.client_type = "PUBLIC".to_string();
    public_none.token_endpoint_authentication_method = "none".to_string();
    assert!(validate_management_client_input(&mut public_none, "req-1").is_ok());
}

#[test]
fn client_secret_lifecycle_requires_confidential_secret_method() {
    assert!(client_accepts_client_secrets(&valid_client_record(
        "CONFIDENTIAL",
        "client_secret_basic"
    )));
    assert!(client_accepts_client_secrets(&valid_client_record(
        "CONFIDENTIAL",
        " client_secret_post "
    )));
    assert!(!client_accepts_client_secrets(&valid_client_record(
        "PUBLIC", "none"
    )));
    assert!(!client_accepts_client_secrets(&valid_client_record(
        "CONFIDENTIAL",
        "private_key_jwt"
    )));
    assert!(!client_accepts_client_secrets(&valid_client_record(
        "CONFIDENTIAL",
        "none"
    )));
}

#[test]
fn validate_management_client_input_rejects_pkjwt_without_key_material_support() {
    let mut input = valid_client_input();
    input.token_endpoint_authentication_method = "private_key_jwt".to_string();
    assert!(validate_management_client_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_management_client_input_rejects_empty_redirects_for_authorization_code() {
    let mut input = valid_client_input();
    input.redirect_uris = Vec::new();

    assert!(validate_management_client_input(&mut input, "req-1").is_err());
}

#[test]
fn validate_management_client_input_allows_empty_redirects_without_authorization_code_grant() {
    let mut input = valid_client_input();
    input.redirect_uris = Vec::new();
    input.allowed_grant_types = vec!["client_credentials".to_string()];

    assert!(validate_management_client_input(&mut input, "req-1").is_ok());
}

#[test]
fn validate_management_client_input_rejects_password_grant() {
    let mut input = valid_client_input();
    input.allowed_grant_types = vec!["password".to_string()];

    assert!(validate_management_client_input(&mut input, "req-1").is_err());
}
