use super::*;
use crate::authcode::types::BearerTokenMetaInput;
use crate::policy::client_credentials::ClientCredentialsGrant;

#[test]
fn client_credentials_primitive_introspection_rejects_either_origin_marker() -> TestResult {
    let store = TokenStore::new_process_local_for_tests();
    let validator = TokenValidator::new(store.clone(), Arc::new(InMemoryKeyManager::new()));
    let mut access = AccessToken::new("caller".into(), "caller".into(), Some("read".into()), 300);
    store.try_replace_access_token_record(access.clone())?;
    assert_eq!(
        validator.introspect_token(&access.token)["active"],
        true,
        "legacy unmarked metadata-absent behavior is preserved"
    );
    let grant = ClientCredentialsGrant::fixture(
        "https://issuer.example",
        "caller",
        "api",
        &["read".into()],
    );
    let mut meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(),
        client_id: "caller".into(),
        user_id: "caller".into(),
        audience: "api".into(),
        granted_scopes: vec!["read".into()],
        sender_binding: None,
        authorization_details: None,
        auth_time_epoch_secs: None,
        acr: None,
        issued_at: access.created_at,
        expires_at: access.created_at + Duration::from_secs(300),
        refresh_parent: None,
    });
    store.try_replace_bearer_meta_record(meta.clone())?;
    assert_eq!(validator.introspect_token(&access.token)["active"], true);
    meta.client_credentials_grant = Some(grant.clone());
    store.try_replace_bearer_meta_record(meta.clone())?;
    assert_eq!(
        validator.introspect_token(&access.token)["active"],
        false,
        "metadata-only CC marker must not take the legacy active path"
    );
    access.client_credentials_digest = Some(grant.digest()?);
    store.try_replace_access_token_record(access.clone())?;
    assert_eq!(
        validator.introspect_token(&access.token)["active"],
        false,
        "complete CC record requires the authoritative HTTP path"
    );
    meta.client_credentials_grant = None;
    store.try_replace_bearer_meta_record(meta)?;
    assert_eq!(
        validator.introspect_token(&access.token)["active"],
        false,
        "access-only CC marker must also stay inactive"
    );
    Ok(())
}
