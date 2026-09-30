use super::*;
use crate::policy::client_credentials::ClientCredentialsGrant;

fn subject(store: &TokenStore) -> Result<BearerTokenMeta, String> {
    let mut access = AccessToken::new("caller".into(), "caller".into(), Some("read write".into()), 300);
    let grant = ClientCredentialsGrant::fixture("https://issuer.example", "caller", "api", &["read".into(), "write".into()]);
    access.client_credentials_digest = Some(grant.digest()?);
    let mut meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: access.token.clone(), client_id: "caller".into(), user_id: "caller".into(),
        granted_scopes: grant.scopes.clone(), audience: "api".into(), sender_binding: None,
        authorization_details: None, auth_time_epoch_secs: None, acr: None,
        issued_at: access.created_at, expires_at: access.created_at + Duration::from_secs(300), refresh_parent: None,
    });
    meta.client_credentials_grant = Some(grant);
    store.store_issued_grant(access, None, meta.clone())?;
    Ok(meta)
}

fn output(subject: &BearerTokenMeta) -> Result<(AccessToken, BearerTokenMeta), String> {
    let mut access = AccessToken::new("caller".into(), "caller".into(), Some("read".into()), 60);
    let mut meta = subject.clone();
    meta.token_id = access.token.clone();
    meta.granted_scopes = vec!["read".into()];
    meta.issued_at = access.created_at;
    meta.expires_at = access.created_at + Duration::from_secs(60);
    meta.client_credentials_grant = Some(subject.client_credentials_grant.as_ref()
        .ok_or("subject grant missing")?.attenuate(&meta.granted_scopes)?);
    access.client_credentials_digest = Some(meta.client_credentials_grant.as_ref().ok_or("output grant missing")?.digest()?);
    Ok((access, meta))
}

fn scenarios(store: &TokenStore) -> StoreTestResult {
    let source = subject(store)?;
    let (access, meta) = output(&source)?;
    let output_id = store.store_exchanged_access(access, meta, source.clone())?;
    let stored = store.try_get_bearer_meta(&output_id)?.ok_or("stored output missing")?;
    assert_eq!(stored.granted_scopes, ["read"]);
    assert!(stored.client_credentials_grant.as_ref().ok_or("grant missing")?
        .is_restriction_of(source.client_credentials_grant.as_ref().ok_or("source grant missing")?));
    for case in 0..8 {
        let (mut access, mut meta) = output(&source)?;
        match case {
            0 => { access.client_credentials_digest = None; meta.client_credentials_grant = None; }
            1 => { meta.client_credentials_grant = None; }
            2 => { access.client_credentials_digest = None; }
            3 => { meta.audience = "other".into(); }
            4 => {
                meta.client_credentials_grant.as_mut().ok_or("grant missing")?.configuration_version_id = uuid::Uuid::new_v4();
                access.client_credentials_digest = Some(meta.client_credentials_grant.as_ref().ok_or("grant missing")?.digest()?);
            }
            5 => { meta.granted_scopes = vec!["admin".into()]; access.scope = Some("admin".into()); }
            6 => { meta.refresh_parent = Some("unexpected-refresh".into()); }
            _ => { meta.client_id = "replacement".into(); access.client_id = "replacement".into(); }
        }
        let id = access.token.clone();
        assert!(store.store_exchanged_access(access, meta, source.clone()).is_err(), "case {case}");
        assert!(store.try_verify_access_token(&id)?.is_none(), "case {case} must not publish");
    }
    let (access, meta) = output(&source)?;
    store.try_revoke_token_for_client(&source.token_id, Some("caller"))?;
    assert!(store.store_exchanged_access(access, meta, source).is_err());
    Ok(())
}

#[test]
fn client_credentials_atomic_exchange_preserves_and_attenuates_authority() -> StoreTestResult {
    scenarios(&TokenStore::new_process_local_for_tests())
}

#[test]
#[ignore = "requires private Redis"]
fn client_credentials_redis_exchange_preserves_and_attenuates_authority() -> StoreTestResult {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|e| e.to_string())?;
    scenarios(&redis_token_store_for_test(&url))
}

#[test]
fn client_credentials_initial_storage_rejects_marker_mismatch_and_refresh() -> StoreTestResult {
    let source = subject(&TokenStore::new_process_local_for_tests())?;
    for case in 0..3 {
        let store = TokenStore::new_process_local_for_tests();
        let (mut access, mut meta) = output(&source)?;
        let refresh = match case {
            0 => { meta.client_credentials_grant = None; None }
            1 => { access.client_credentials_digest = None; None }
            _ => Some(RefreshToken::with_ttl(
                RefreshTokenInput { scope: Some("read".into()), resource: Some("api".into()),
                    ..RefreshTokenInput::new("caller".into(), "caller".into()) }, 120,
            )),
        };
        assert!(store.store_issued_grant(access, refresh, meta).is_err(), "case {case}");
    }
    Ok(())
}
