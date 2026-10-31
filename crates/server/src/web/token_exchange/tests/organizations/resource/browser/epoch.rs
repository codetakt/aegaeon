use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; mounted consent and actual epoch retirement"]
async fn shared_redis_organizations_browser_refuses_approval_after_epoch_retirement() -> TestResult
{
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured(&f).await?;
    let mut witness = CallerFixture::new(state.environment_id).await?;
    let result = Box::pin(exercise(&f, &state, &mut witness)).await;
    let cleanup = witness
        .finish()
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() });
    let state_cleanup = fixture::finish(&state).await;
    f.cleanup(result.and(cleanup).and(state_cleanup)).await
}

async fn exercise(f: &Fixture, state: &AppState, witness: &mut CallerFixture) -> TestResult {
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let work = witness.begin().await?;
    let sid = work
        .store_scope(Box::pin(session(
            state,
            format!("organization-user-{}", f.users[1]),
        )))
        .await??;
    assert_eq!(work.complete().await?.pending, 0);
    let uri = authorize(state, &key)?;
    let work = witness.begin().await?;
    let (status, html) = work
        .store_scope(Box::pin(page(state, &sid, &uri, None)))
        .await??;
    assert_eq!(status, StatusCode::OK, "consent display: {html}");
    assert!(html.contains(IDENTIFIER));
    assert_eq!(work.complete().await?.pending, 0);
    witness.retire_epoch().await?;
    let form = [
        ("transaction", transaction(&html)?),
        ("decision", "approve"),
    ];
    let work = witness.begin().await?;
    let (status, body) = work
        .store_scope(Box::pin(page(state, &sid, "/auth/consent", Some(&form))))
        .await??;
    assert_ne!(
        status,
        StatusCode::OK,
        "retired consent cannot authorize: {body}"
    );
    assert!(code(&body, state.issuer.as_str()).is_err());
    assert_eq!(work.complete().await?.pending, 0);
    // Fresh display and approval after cutover have the new binding.
    let work = witness.begin().await?;
    let (status, html) = work
        .store_scope(Box::pin(page(state, &sid, &uri, None)))
        .await??;
    assert_eq!(status, StatusCode::OK, "fresh display: {html}");
    assert_eq!(work.complete().await?.pending, 0);
    let form = [
        ("transaction", transaction(&html)?),
        ("decision", "approve"),
    ];
    let work = witness.begin().await?;
    let (status, body) = work
        .store_scope(Box::pin(page(state, &sid, "/auth/consent", Some(&form))))
        .await??;
    assert_eq!(status, StatusCode::OK, "fresh approval: {body}");
    assert!(!code(&body, state.issuer.as_str())?.is_empty());
    assert_eq!(work.complete().await?.pending, 0);
    Ok(())
}
