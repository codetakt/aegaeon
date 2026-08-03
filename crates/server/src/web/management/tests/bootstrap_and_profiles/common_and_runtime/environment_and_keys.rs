#[test]
fn federation_management_internal_error_maps_to_server_error() {
    let response = federation_management_error_response(
        FederationError::Internal(
            "unsupported raw JSON backend for federation-entity-statement".to_string(),
        ),
        "req-test",
    );

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn environment_scope_queries_exclude_deleted_parent_tenants() {
    assert!(LOAD_ENVIRONMENT_ROW_SQL.contains("t.status <> 'DELETED'"));
    assert!(LOAD_ENVIRONMENT_ROW_SQL.contains("e.status <> 'DELETED'"));
    assert!(LOAD_KEY_STORE_ROW_SQL.contains("t.status <> 'DELETED'"));
    assert!(LOAD_KEY_STORE_ROW_SQL.contains("e.status <> 'DELETED'"));
    for sql in [
        LOAD_VISIBLE_CLIENT_ROW_SQL,
        LIST_CLIENT_ROWS_SQL,
        LOAD_CLIENT_FOR_UPDATE_SQL,
        UPDATE_CLIENT_ROW_SQL,
        DELETE_CLIENT_ROW_SQL,
        LIST_CONNECTION_ROWS_SQL,
        LOAD_CONNECTION_ROW_SQL,
        LIST_OAUTH_PROFILE_ROWS_SQL,
        LOAD_OAUTH_PROFILE_ROW_SQL,
    ] {
        assert!(sql.contains("t.status <> 'DELETED'"));
        assert!(sql.contains("e.status <> 'DELETED'"));
    }
    assert!(LOAD_CONNECTION_ROW_SQL.contains("t.team_id = $3"));
    assert!(LOAD_OAUTH_PROFILE_ROW_SQL.contains("t.team_id = $3"));
    assert!(DELETE_CLIENT_ROW_SQL.contains("c.configuration_version_id = $4"));
    assert!(DELETE_CLIENT_ROW_SQL.contains("e.active_configuration_version_id = $4"));
    for sql in [
        LIST_USER_ROWS_SQL.to_string(),
        UPDATE_USER_FIELDS_ROW_SQL.to_string(),
        load_user_for_status_sql_for_test("AND u.status <> 'DELETED'"),
        update_user_status_sql_for_test(
            "AND u.status <> 'DELETED'",
            "status = 'ACTIVE', updated_at = now()",
        ),
    ] {
        assert!(sql.contains("t.status <> 'DELETED'"));
        assert!(sql.contains("e.status <> 'DELETED'"));
    }
    for sql in [
        LIST_ACCOUNT_LINK_ROWS_SQL,
        LOAD_ACCOUNT_LINK_SUMMARIES_BY_IDS_SQL,
        LOAD_ACCOUNT_LINK_CONFLICT_CANDIDATES_SQL,
        LOAD_ACCOUNT_LINK_SUMMARY_BY_ID_SQL,
        LOAD_ACCOUNT_LINK_SUMMARY_BY_UPSTREAM_SUBJECT_SQL,
        LOAD_ACCOUNT_LINK_TARGET_USER_SQL,
    ] {
        assert!(sql.contains("t.status <> 'DELETED'"));
        assert!(sql.contains("e.status <> 'DELETED'"));
    }
    assert!(LOAD_ACCOUNT_LINK_CONNECTION_SQL.contains("t.status <> 'DELETED'"));
    assert!(LOAD_ACCOUNT_LINK_CONNECTION_SQL.contains("e.status = 'ACTIVE'"));
    assert!(LOAD_ACCOUNT_LINK_CONNECTION_SQL.contains("c.status = 'ACTIVE'"));
    assert!(
        LOAD_ACCOUNT_LINK_CONNECTION_SQL
            .contains("e.active_configuration_version_id = c.configuration_version_id")
    );
    for sql in [
        LIST_CLIENT_SECRET_ROWS_SQL,
        REVOKE_CLIENT_SECRET_ROW_SQL,
        REVOKE_ALL_CLIENT_SECRETS_ROWS_SQL,
        LOAD_USER_IDENTITY_SQL,
        FETCH_CONFIGURATION_VERSION_ROW_SQL,
    ] {
        assert!(sql.contains("t.status <> 'DELETED'"));
        assert!(sql.contains("e.status <> 'DELETED'"));
    }
}

#[test]
fn require_configuration_document_value_fails_closed_when_missing() -> TestResult {
    let response = must_err!(
        require_configuration_document_value(None, "req-1"),
        "missing active configuration document should fail closed"
    );

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}

#[test]
fn require_configuration_document_value_preserves_present_document() -> TestResult {
    let document = serde_json::json!({
        "schemaVersion": 1,
        "issuerHost": "tenant.example.com",
        "issuerUrl": "https://tenant.example.com",
    });

    let loaded = require_configuration_document_value(Some(document.clone()), "req-1")
        .map_err(|_| io::Error::other("configuration document rejected"))?;

    assert_eq!(loaded, document);
    Ok(())
}

fn valid_key_store_request() -> UpdateKeyStoreRequest {
    UpdateKeyStoreRequest {
        type_: "databaseEncrypted".to_string(),
        configuration: serde_json::json!({}),
        base_configuration_version_id: Uuid::new_v4().to_string(),
        comment: Some(" rotate ".to_string()),
        allow_security_downgrade: Some(false),
        reason: Some("planned maintenance".to_string()),
    }
}

#[test]
fn validate_key_store_update_accepts_database_encrypted_public_configuration() -> TestResult {
    let request = valid_key_store_request();
    let validated = must_ok!(
        validate_key_store_update_request(&request, "req-1"),
        "databaseEncrypted public key store config should validate"
    );

    assert_eq!(validated.type_, "databaseEncrypted");
    assert_eq!(validated.comment.as_deref(), Some("rotate"));
    assert_eq!(validated.reason.as_deref(), Some("planned maintenance"));
    assert!(!validated.allow_security_downgrade);
    assert_eq!(validated.configuration, serde_json::json!({}));
    Ok(())
}

#[test]
fn validate_key_store_update_rejects_database_encrypted_public_configuration() {
    let mut request = valid_key_store_request();
    request.configuration = serde_json::json!({
        "rotationPolicy": "manual"
    });

    assert!(validate_key_store_update_request(&request, "req-1").is_err());
}

#[test]
fn validate_key_store_update_rejects_unsupported_type() {
    let mut request = valid_key_store_request();
    request.type_ = "rawFilesystem".to_string();

    assert!(validate_key_store_update_request(&request, "req-2").is_err());
}

#[test]
fn validate_key_store_update_rejects_non_object_configuration() {
    let mut request = valid_key_store_request();
    request.configuration = serde_json::json!("not-an-object");

    assert!(validate_key_store_update_request(&request, "req-3").is_err());
}

#[test]
fn validate_key_store_update_rejects_secret_material_in_public_configuration() {
    let mut request = valid_key_store_request();
    request.configuration = serde_json::json!({
        "nested": {
            "privateKeyPem": "secret"
        }
    });

    assert!(validate_key_store_update_request(&request, "req-4").is_err());
}

#[test]
fn bootstrap_owner_password_uses_local_credential_policy() {
    assert_eq!(
        validate_bootstrap_owner_password("   "),
        Err("Password must not be empty")
    );
    assert_eq!(
        validate_bootstrap_owner_password("short"),
        Err("Password must be at least 12 bytes long")
    );
    assert!(validate_bootstrap_owner_password("long-enough!").is_ok());
}
