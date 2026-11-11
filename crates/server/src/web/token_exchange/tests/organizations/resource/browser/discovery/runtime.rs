//! Selection and approval retain the browser session and actual serving epoch.
use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;

fn rejected(status: StatusCode, body: &str) -> TestResult {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let value: Value = serde_json::from_str(body)?;
    assert_eq!(value["error"], "invalid_request", "{body}");
    assert!(value.get("code").is_none() && value.get("access_token").is_none());
    assert!(!body.contains("aegaeon-continuation"));
    Ok(())
}

async fn pending(state: &AppState, sid: &str, uri: &str, approval: bool) -> TestResult<String> {
    let (status, picker) = page(state, sid, uri, None).await?;
    assert_eq!(status, StatusCode::OK, "{picker}");
    assert!(picker.contains("Select organization"));
    if !approval {
        return Ok(transaction(&picker)?.to_owned());
    }
    let (status, consent) = page(
        state,
        sid,
        "/auth/consent",
        Some(&[
            ("transaction", transaction(&picker)?),
            ("decision", "select:0"),
        ]),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{consent}");
    assert!(consent.contains("Organization access"));
    assert!(code(&consent, &state.issuer).is_err());
    Ok(transaction(&consent)?.to_owned())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis; actual browser session expiry"]
async fn shared_redis_organizations_selection_and_approval_refuse_expired_browser_session(
) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let mut state = configured_discovery(&f).await?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    state.browser_auth.auth_sessions = Arc::new(crate::web::AuthSessionStore::from_postgres(
        &crate::management::types::PolicyDocument::default(),
        state.db_pool.clone(),
        &namespace,
    )?);
    let result = fixture::in_epoch(
        &state,
        Box::pin(async {
            let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
            let uri = selector_uri(&state, &key)?;
            for approval in [false, true] {
                let sid = session(&state, format!("organization-user-{}", f.users[1])).await?;
                let token = pending(&state, &sid, &uri, approval).await?;
                // Expire this session in the real production PostgreSQL backend.
                // Keep the browser cookie and pending choice/approval unchanged.
                let digest = aegaeon_crypto::hash::sha256_digest(sid.as_bytes());
                let changed = sqlx::query("UPDATE aegaeon.runtime_browser_sessions SET expires_at=statement_timestamp()-interval '1 second' WHERE namespace=$1 AND token_digest=$2")
                    .bind(namespace.flow_namespace("browser", "session"))
                    .bind(digest.as_slice()).execute(&f.pool).await?;
                assert_eq!(changed.rows_affected(), 1);
                assert!(state.browser_auth.auth_sessions.try_get_async(sid.clone()).await?.is_none());
                let form = [
                    ("transaction", token.as_str()),
                    ("decision", if approval { "approve" } else { "select:0" }),
                ];
                let (status, body) = page(&state, &sid, "/auth/consent", Some(&form)).await?;
                rejected(status, &body)?;
                let replacement = session(&state, format!("organization-user-{}", f.users[1])).await?;
                let (status, body) = page(&state, &replacement, "/auth/consent", Some(&form)).await?;
                rejected(status, &body)?;
                let fresh = pending(&state, &replacement, &uri, true).await?;
                let (status, body) = page(&state, &replacement, "/auth/consent", Some(&[("transaction", fresh.as_str()), ("decision", "approve")])).await?;
                assert_eq!(status, StatusCode::OK, "fresh session approval: {body}");
                assert!(code(&body, &state.issuer).is_ok());
            }
            Ok(())
        }),
    ).await;
    let cleanup = fixture::finish(&state).await;
    f.cleanup(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis; actual epoch retirement"]
async fn shared_redis_organizations_selection_and_approval_refuse_retired_epoch() -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured_discovery(&f).await?;
    let mut witness = CallerFixture::with_observed_stores(
        state.environment_id,
        state.db_pool.connect_options().as_ref().clone(),
        redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?,
    )
    .await?;
    let result = epoch_cases(&f, &state, &mut witness).await;
    let cleanup = witness
        .finish()
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() });
    let state_cleanup = fixture::finish(&state).await;
    f.cleanup(result.and(cleanup).and(state_cleanup)).await
}

async fn epoch_cases(f: &Fixture, state: &AppState, witness: &mut CallerFixture) -> TestResult {
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let work = witness.begin().await?;
    let sid = work
        .store_scope(Box::pin(session(
            state,
            format!("organization-user-{}", f.users[1]),
        )))
        .await??;
    assert_eq!(work.complete().await?.pending, 0);
    let uri = selector_uri(state, &key)?;
    for approval in [false, true] {
        let work = witness.begin().await?;
        let token = work
            .store_scope(Box::pin(pending(state, &sid, &uri, approval)))
            .await??;
        assert_eq!(work.complete().await?.pending, 0);
        witness.retire_epoch().await?;
        let form = [
            ("transaction", token.as_str()),
            ("decision", if approval { "approve" } else { "select:0" }),
        ];
        let work = witness.begin().await?;
        let (status, body) = work
            .store_scope(Box::pin(page(state, &sid, "/auth/consent", Some(&form))))
            .await??;
        rejected(status, &body)?;
        assert_eq!(work.complete().await?.pending, 0);
        let work = witness.begin().await?;
        let fresh = work
            .store_scope(Box::pin(pending(state, &sid, &uri, true)))
            .await??;
        assert_eq!(work.complete().await?.pending, 0);
        let form = [("transaction", fresh.as_str()), ("decision", "approve")];
        let work = witness.begin().await?;
        let (status, body) = work
            .store_scope(Box::pin(page(state, &sid, "/auth/consent", Some(&form))))
            .await??;
        assert_eq!(status, StatusCode::OK, "fresh epoch approval: {body}");
        assert!(code(&body, &state.issuer).is_ok());
        assert_eq!(work.complete().await?.pending, 0);
    }
    Ok(())
}
