//! Actual public helper tests; this API has no online requester authority.
use super::*;
use crate::authcode::types::BearerTokenMetaInput;

fn record(
    store: &TokenStore,
    subject: &str,
    scope: Option<&str>,
    token_type: &str,
    lifetime: u64,
) -> Result<AccessToken, String> {
    let mut access = AccessToken::new(
        "owner".into(),
        subject.into(),
        scope.map(str::to_string),
        lifetime,
    );
    access.token_type = token_type.into();
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(),
        client_id: access.client_id.clone(),
        user_id: access.user_id.clone(),
        audience: "resource".into(),
        granted_scopes: scope
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        sender_binding: None,
        authorization_details: None,
        auth_time_epoch_secs: None,
        acr: None,
        issued_at: access.created_at,
        expires_at: access.created_at + Duration::from_secs(lifetime),
        refresh_parent: None,
    });
    store.store_issued_grant(access.clone(), None, meta)?;
    Ok(access)
}

#[test]
fn legacy_introspection_preserves_optional_scope_and_stored_token_type() -> TestResult {
    let store = TokenStore::new_process_local_for_tests();
    let validator = TokenValidator::new(store.clone(), Arc::new(InMemoryKeyManager::new()));
    for scope in [None, Some("read write"), Some("")] {
        for token_type in ["Bearer", "DPoP"] {
            let access = record(&store, "subject", scope, token_type, 300)?;
            let body = validator.introspect_token(&access.token);
            assert_eq!(body["active"], true);
            assert_eq!(
                body.get("scope"),
                scope.map(serde_json::Value::from).as_ref()
            );
            assert_eq!(body["token_type"], token_type);
            assert_eq!(body["client_id"], "owner");
            assert_eq!(body["sub"], "subject");
            assert!(body.get("username").is_none());
            assert!(body["exp"].is_u64());
            assert!(body.get("cnf").is_none());
            assert!(body.get("iss").is_none());
            store.try_revoke_token(&access.token)?;
            assert_eq!(
                validator.introspect_token(&access.token),
                json!({"active":false})
            );
        }
    }
    assert_eq!(
        validator.introspect_token("unknown"),
        json!({"active":false})
    );
    let mut expired = record(&store, "subject", None, "Bearer", 300)?;
    expired.expires_in = 0;
    store.try_replace_access_token_record(expired.clone())?;
    assert_eq!(
        validator.introspect_token(&expired.token),
        json!({"active":false})
    );
    Ok(())
}

#[test]
fn local_introspection_preserves_exact_subject_without_inventing_username() -> TestResult {
    let store = TokenStore::new_process_local_for_tests();
    let validator = TokenValidator::new(store.clone(), Arc::new(InMemoryKeyManager::new()));
    for subject in [
        "usr:8e354c1d-5094-4ac8-9ad2-993b9013c71b",
        "Alex Reader",
        "利用者/e\u{301}/é/🌊",
    ] {
        let access = record(&store, subject, Some("read"), "Bearer", 300)?;
        let body = validator.introspect_token(&access.token);
        assert_eq!(body["active"], true);
        assert_eq!(body["sub"], subject);
        assert!(body.get("username").is_none());
    }
    Ok(())
}
