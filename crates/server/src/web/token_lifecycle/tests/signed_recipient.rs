use super::*;

async fn check(
    state: &AppState,
    token: &str,
    caller: &str,
    signed: bool,
    active: bool,
) -> TestResult {
    let (status, body) = introspection(state, token, caller, signed).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    if active {
        assert_eq!(body["active"], true);
    } else {
        assert_eq!(body, json!({"active":false}));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn signed_recipient_restricts_owner_disclosure_and_preserves_json_selection() -> TestResult {
    let mut fixture = Fixture::new(true).await?;
    let result = async {
        let (access, refresh, meta) = grant(&fixture.state, false, None);
        let audience = meta.audience.clone();
        fixture
            .state
            .tokens
            .store
            .store_issued_grant(access.clone(), refresh, meta)?;
        check(&fixture.state, &access.token, OWNER, false, true).await?;
        check(&fixture.state, &access.token, OWNER, true, false).await?;
        for signed in [false, true] {
            check(&fixture.state, &access.token, &audience, signed, true).await?;
            check(&fixture.state, &access.token, OTHER, signed, false).await?;
            check(&fixture.state, "unknown-token", OWNER, signed, false).await?;
        }
        // Owner and RS may coincide under the explicit local direct-ID convention.
        let (same, refresh, mut meta) = grant(&fixture.state, false, None);
        meta.audience = OWNER.into();
        fixture
            .state
            .tokens
            .store
            .store_issued_grant(same.clone(), refresh, meta)?;
        check(&fixture.state, &same.token, OWNER, true, true).await?;
        // Disabling JWT cannot satisfy an explicit JWT-only request. Plain JSON
        // retains its existing owner visibility.
        update_test_policy(&mut fixture.state, |policy| {
            policy.jwt_introspection_enabled = false
        })
        .await?;
        let (status, body) = introspection(&fixture.state, &access.token, OWNER, true).await?;
        assert_eq!(status, StatusCode::NOT_ACCEPTABLE);
        assert_eq!(body["error"], "invalid_request");
        check(&fixture.state, &access.token, OWNER, false, true).await?;
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn signed_recipient_missing_metadata_is_inactive_without_changing_json_owner() -> TestResult {
    let fixture = Fixture::new(true).await?;
    let result = async {
        let (access, refresh, meta) = grant(&fixture.state, false, None);
        fixture
            .state
            .tokens
            .store
            .store_issued_grant(access.clone(), refresh, meta)?;
        let _: usize = fixture
            .connection()?
            .del(fixture.key("bearer", &access.token))?;
        assert!(fixture
            .state
            .tokens
            .store
            .try_get_bearer_meta(&access.token)?
            .is_none());
        check(&fixture.state, &access.token, OWNER, false, false).await?;
        check(&fixture.state, &access.token, OWNER, true, false).await?;
        check(
            &fixture.state,
            &access.token,
            &reader(&fixture.state, true),
            true,
            false,
        )
        .await?;
        // Inactive response signing is still real work and may fail operationally.
        let mut unavailable = fixture.state.clone();
        unavailable.keys.jwt_introspection = Some(Arc::new(crate::kms::InMemoryKeyManager::new()));
        let before = super::failures::metrics()?;
        let (status, _) = introspection(&unavailable, &access.token, OWNER, true).await?;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(super::failures::metrics()?, before);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
