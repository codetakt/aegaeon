use super::*;
use crate::organizations::request_work::{async_store, CapacityClass};
use crate::organizations::witness::tests::caller_fixture::CallerFixture;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; actual witness and mounted resource router"]
async fn shared_redis_organizations_resource_reuses_current_epoch_and_refuses_retired_authority(
) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup(&f).await?;
    let mut witness = CallerFixture::new(state.environment_id).await?;
    let result = Box::pin(exercise(&f, &state, &mut witness)).await;
    let witness_cleanup = witness
        .finish()
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() });
    let state_cleanup = fixture::finish(&state).await;
    f.cleanup(result.and(witness_cleanup).and(state_cleanup))
        .await
}

async fn exercise(f: &Fixture, state: &AppState, witness: &mut CallerFixture) -> TestResult {
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let token = issue_current(f, state, witness, &key).await?;
    for method in [Method::GET, Method::HEAD] {
        inspect(state, witness, &key, &token, method, StatusCode::OK).await?;
    }
    let mut foreign = state.clone();
    foreign.environment_id = uuid::Uuid::new_v4();
    inspect(
        &foreign,
        witness,
        &key,
        &token,
        Method::GET,
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await?;
    for class in [CapacityClass::Revocation, CapacityClass::Snapshot] {
        let work = witness.begin_class(class).await?;
        let signed = proof(state, &key, &token, "GET", json!({}))?;
        let response = work
            .store_scope(Box::pin(get(
                state,
                Method::GET,
                PATH,
                Some(&format!("DPoP {token}")),
                Some(&signed),
                "",
            )))
            .await??;
        assert_eq!(
            response.0,
            StatusCode::SERVICE_UNAVAILABLE,
            "capacity cannot change: {}",
            response.1
        );
        assert_eq!(work.complete().await?.pending, 0);
    }
    witness.retire_epoch().await?;
    inspect(
        state,
        witness,
        &key,
        &token,
        Method::GET,
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    let fresh = issue_current(f, state, witness, &key).await?;
    inspect(state, witness, &key, &fresh, Method::GET, StatusCode::OK).await?;
    inspect(
        state,
        witness,
        &key,
        &token,
        Method::GET,
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    assert_eq!(witness.pending().await?, 0);
    Ok(())
}

async fn issue_current(
    f: &Fixture,
    state: &AppState,
    witness: &CallerFixture,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
) -> TestResult<String> {
    let work = witness.begin().await?;
    let (_, token) = work
        .store_scope(Box::pin(issue(f, state, key, PRIVILEGE)))
        .await??;
    assert_eq!(work.complete().await?.pending, 0);
    Ok(token)
}

async fn inspect(
    state: &AppState,
    witness: &CallerFixture,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    token: &str,
    method: Method,
    expected: StatusCode,
) -> TestResult {
    let work = witness.begin().await?;
    let signed = proof(state, key, token, method.as_str(), json!({}))?;
    let result = work
        .store_scope(Box::pin(async {
            // Reuse is observable even if every global ordinary permit is held.
            let held = (0..crate::organizations::request_work::MAX_REQUESTS)
                .map(|_| crate::organizations::request_work::Admission::try_acquire())
                .collect::<Result<Vec<_>, _>>()?;
            if state.environment_id == work.binding().environment_id() {
                let owner =
                    async_store::route_owner(state.environment_id, CapacityClass::Ordinary)?
                        .ok_or("missing route owner")?;
                assert!(owner.same_work(work.admission()));
            }
            let response = get(
                state,
                method,
                PATH,
                Some(&format!("DPoP {token}")),
                Some(&signed),
                "",
            )
            .await;
            drop(held);
            response
        }))
        .await??;
    assert_eq!(
        result.0, expected,
        "mounted resource response: {}",
        result.1
    );
    assert_eq!(work.complete().await?.pending, 0);
    Ok(())
}
