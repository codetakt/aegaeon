
// ---------------------------------------------------------------
// P1: validate_oauth_profile_input
// ---------------------------------------------------------------

fn valid_oauth_profile_input() -> OAuthProfileInput {
    OAuthProfileInput {
        name: "Test Profile".to_string(),
        description: None,
        profile_type: "DOWNSTREAM".to_string(),
        is_default: false,
        require_pkce: true,
        require_state_parameter: true,
        require_iss_parameter: false,
        sender_constrained: "NONE".to_string(),
        enforce_refresh_sender_binding: false,
        allowed_grant_types: vec!["authorization_code".to_string()],
        token_endpoint_auth_methods_allowed: vec!["client_secret_basic".to_string()],
        expires_at: None,
    }
}

#[test]
fn validate_oauth_profile_accepts_valid() {
    let policy = default_policy_document();
    let mut input = valid_oauth_profile_input();
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_ok());
}

#[test]
fn validate_oauth_profile_rejects_empty_name() {
    let policy = default_policy_document();
    let mut input = valid_oauth_profile_input();
    input.name = "  ".to_string();
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_rejects_invalid_profile_type() {
    let policy = default_policy_document();
    let mut input = valid_oauth_profile_input();
    input.profile_type = "INVALID".to_string();
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_accepts_upstream_type() {
    let policy = default_policy_document();
    let mut input = valid_oauth_profile_input();
    input.profile_type = " upstream ".to_string();
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_ok());
    assert_eq!(input.profile_type, "UPSTREAM");
}

#[test]
fn validate_oauth_profile_rejects_invalid_sender_constrained() {
    let policy = default_policy_document();
    let mut input = valid_oauth_profile_input();
    input.sender_constrained = "INVALID".to_string();
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_rejects_empty_grant_types() {
    let policy = default_policy_document();
    let mut input = valid_oauth_profile_input();
    input.allowed_grant_types = vec![String::new()];
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_rejects_empty_auth_methods() {
    let policy = default_policy_document();
    let mut input = valid_oauth_profile_input();
    input.token_endpoint_auth_methods_allowed = vec![String::new()];
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_rejects_pkce_false_when_policy_requires() {
    let policy = default_policy_document();
    assert!(policy.pkce_required);
    let mut input = valid_oauth_profile_input();
    input.require_pkce = false;
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_rejects_state_false_when_policy_requires() {
    let mut policy = default_policy_document();
    policy.require_state_parameter = true;
    let mut input = valid_oauth_profile_input();
    input.require_state_parameter = false;
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_always_requires_pkce() {
    let mut policy = default_policy_document();
    policy.pkce_required = false;
    let mut input = valid_oauth_profile_input();
    input.require_pkce = false;
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_rejects_password_grant() {
    let mut policy = default_policy_document();
    policy.allowed_grant_types.push("password".to_string());
    let mut input = valid_oauth_profile_input();
    input.allowed_grant_types = vec!["password".to_string()];
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_refresh_binding_requires_sender() {
    let policy = default_policy_document();
    let mut input = valid_oauth_profile_input();
    input.enforce_refresh_sender_binding = true;
    input.sender_constrained = "NONE".to_string();
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_policy_requires_sender_constrained() {
    let mut policy = default_policy_document();
    policy.dcr_require_sender_constrained = true;
    let mut input = valid_oauth_profile_input();
    input.sender_constrained = "NONE".to_string();
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_grant_types_must_be_policy_subset() {
    let policy = default_policy_document();
    let mut input = valid_oauth_profile_input();
    input.allowed_grant_types = vec!["urn:custom:grant".to_string()];
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_rejects_unsupported_grant_types() {
    let mut policy = default_policy_document();
    policy.allowed_grant_types = vec!["authorization_code".to_string()];
    let mut input = valid_oauth_profile_input();
    input.allowed_grant_types = vec!["authorization_code".to_string(), "urn:custom".to_string()];

    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_rejects_unsupported_auth_method() {
    let policy = default_policy_document();
    let mut input = valid_oauth_profile_input();
    input.token_endpoint_auth_methods_allowed = vec!["mtls".to_string()];
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_rejects_pkjwt_when_policy_disables() {
    let mut policy = default_policy_document();
    policy.private_key_jwt_enabled = false;
    let mut input = valid_oauth_profile_input();
    input.token_endpoint_auth_methods_allowed = vec!["private_key_jwt".to_string()];
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_accepts_pkjwt_when_policy_enables() {
    let mut policy = default_policy_document();
    policy.private_key_jwt_enabled = true;
    let mut input = valid_oauth_profile_input();
    input.token_endpoint_auth_methods_allowed = vec!["private_key_jwt".to_string()];
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_ok());
}

#[test]
fn validate_oauth_profile_rejects_upstream_pkjwt_until_runtime_support_exists() {
    let mut policy = default_policy_document();
    policy.private_key_jwt_enabled = true;
    let mut input = valid_oauth_profile_input();
    input.profile_type = "UPSTREAM".to_string();
    input.token_endpoint_auth_methods_allowed = vec!["private_key_jwt".to_string()];
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_rejects_none_auth_when_policy_requires_client_auth() {
    let mut policy = default_policy_document();
    policy.require_client_auth_token = true;
    let mut input = valid_oauth_profile_input();
    input.token_endpoint_auth_methods_allowed = vec!["none".to_string()];
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_accepts_none_auth_when_policy_allows() {
    let mut policy = default_policy_document();
    policy.require_client_auth_token = false;
    let mut input = valid_oauth_profile_input();
    input.token_endpoint_auth_methods_allowed = vec!["none".to_string()];
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_ok());
}

#[test]
fn validate_oauth_profile_rejects_unimplemented_mtls_sender() {
    let mut policy = default_policy_document();
    policy.mtls_enabled = true;
    policy.dcr_allowed_sender_methods = vec!["mtls".to_string()];
    let mut input = valid_oauth_profile_input();
    input.sender_constrained = "MTLS".to_string();
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}

#[test]
fn validate_oauth_profile_dpop_sender_accepted_when_policy_allows() {
    let policy = default_policy_document();
    let mut input = valid_oauth_profile_input();
    input.sender_constrained = "DPOP".to_string();
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_ok());
}

#[test]
fn validate_oauth_profile_sender_must_be_in_policy_methods() {
    let mut policy = default_policy_document();
    policy.dcr_allowed_sender_methods = Vec::new();
    let mut input = valid_oauth_profile_input();
    input.sender_constrained = "DPOP".to_string();
    assert!(validate_oauth_profile_input(&mut input, &policy, "req-1").is_err());
}
