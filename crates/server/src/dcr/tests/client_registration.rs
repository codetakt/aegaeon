use super::*;

#[test]
fn parse_client_registration_rejects_duplicate_keys() -> DcrTestResult {
    let err = must_err!(
        parse_client_registration(
            br#"{
                "redirect_uris":["https://example.com/callback"],
                "redirect_uris":["https://evil.example/callback"]
            }"#,
        ),
        "duplicate keys must be rejected before registration normalization",
    );

    assert_eq!(
        err,
        ClientRegistrationParseError::PolicyViolation("duplicate-key".to_string())
    );
    Ok(())
}

#[test]
fn parse_client_registration_rejects_alias_duplicates() -> DcrTestResult {
    let err = must_err!(
        parse_client_registration(
            br#"{
                "pkce_required":true,
                "require_pkce":true
            }"#,
        ),
        "semantic duplicates across aliases must be rejected",
    );

    assert_eq!(
        err,
        ClientRegistrationParseError::PolicyViolation("duplicate-key".to_string())
    );
    Ok(())
}

#[test]
fn parse_client_registration_preserves_alias_values() -> DcrTestResult {
    let meta = must_ok!(
        parse_client_registration(
            br#"{
                "oauth_pkce_required":true,
                "sender_constrained_token_methods":["dpop"],
                "dpop_bound_access_tokens":true
            }"#,
        ),
        "aliases should map into canonical client registration fields",
    );

    assert_eq!(meta.pkce_required, Some(true));
    assert_eq!(
        meta.sender_constrained_methods,
        Some(vec!["dpop".to_string()])
    );
    assert_eq!(meta.require_dpop, Some(true));
    Ok(())
}

#[test]
fn parse_client_registration_preserves_scope_metadata() -> DcrTestResult {
    let meta = must_ok!(
        parse_client_registration(br#"{"scope":"openid profile"}"#),
        "scope metadata must be recognized",
    );

    assert_eq!(meta.scope, Some("openid profile".to_string()));
    Ok(())
}

#[test]
fn parse_client_registration_rejects_invalid_scope_type() -> DcrTestResult {
    let err = must_err!(
        parse_client_registration(br#"{"scope":["openid"]}"#),
        "scope must be a string or null",
    );

    assert_eq!(
        err,
        ClientRegistrationParseError::InvalidMetadata(
            "malformed metadata: `scope` must be a string or null".to_string(),
        )
    );
    Ok(())
}

#[test]
fn parse_client_registration_rejects_trailing_bytes_as_invalid_json() -> DcrTestResult {
    let err = must_err!(
        parse_client_registration(
            br#"{
                "redirect_uris":["https://example.com/callback"]
            } trailing"#,
        ),
        "trailing bytes must be rejected before registration normalization",
    );

    assert_eq!(err, ClientRegistrationParseError::InvalidJson);
    Ok(())
}

#[test]
fn parse_client_registration_rejects_non_object_shape_as_invalid_json() -> DcrTestResult {
    let err = must_err!(
        parse_client_registration(br#"["https://example.com/callback"]"#),
        "non-object payloads must be rejected before registration normalization",
    );

    assert_eq!(err, ClientRegistrationParseError::InvalidJson);
    Ok(())
}

#[test]
fn parse_client_registration_rejects_invalid_string_array_types() -> DcrTestResult {
    let err = must_err!(
        parse_client_registration(
            br#"{
                "redirect_uris":["https://example.com/callback", 7]
            }"#,
        ),
        "non-string array entries must be rejected as malformed metadata",
    );

    assert_eq!(
        err,
        ClientRegistrationParseError::InvalidMetadata(
            "malformed metadata: `redirect_uris` must be an array of strings or null".to_string(),
        )
    );
    Ok(())
}

#[test]
fn parse_client_registration_rejects_unknown_backend_override() -> DcrTestResult {
    let _guard = raw_json_env_lock()?;
    let previous = std::env::var("AEGAEON_RAW_JSON_BACKEND_CLIENT_REGISTRATION").ok();
    std::env::set_var("AEGAEON_RAW_JSON_BACKEND_CLIENT_REGISTRATION", "future");

    let result = super::super::parse_client_registration(
        br#"{
                "redirect_uris":["https://example.com/callback"]
            }"#,
    );

    if let Some(prev) = previous {
        std::env::set_var("AEGAEON_RAW_JSON_BACKEND_CLIENT_REGISTRATION", prev);
    } else {
        std::env::remove_var("AEGAEON_RAW_JSON_BACKEND_CLIENT_REGISTRATION");
    }

    let err = must_err!(result, "unknown backend override must fail closed");
    assert!(matches!(
        err,
        ClientRegistrationParseError::Internal(ref msg)
            if msg.contains("unsupported raw JSON backend `future`")
    ));
    Ok(())
}
