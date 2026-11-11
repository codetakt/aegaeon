//! Signed Request Objects cross the real selected-runtime worker boundary.
use super::*;
use crate::organizations::{
    lifecycle::{Limits, Runtime, Selection},
    request_work::{async_store, CapacityClass},
};
use crate::request_object_store::RequestObjectReplayError;
use std::time::Duration;
mod fixture;

async fn accepted(state: &AppState, sid: &str, jwt: &str, par: bool) -> TestResult {
    let namespace = async_store::current_owner()?
        .current_runtime()?
        .ok_or("checked runtime")?
        .selection()
        .namespace(state.environment_id)?;
    let request = request_objects::authorization_uri(
        state,
        sid,
        jwt,
        if par { "par-owned" } else { "jar-owned" },
    )
    .await?;
    if par {
        fixture::snapshot(&namespace)?.require_surfaces(&["par"]);
    }
    let (status, body) = send(state, sid, &request, None, None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let response: Value = serde_json::from_str(&body)?;
    assert_eq!(response["state"], RP_STATE);
    let code = response["code"].as_str().ok_or("authorization code")?;
    let issuer = state.tokens.issuer.clone();
    let lookup = code.to_string();
    let stored = async_store::blocking(move || issuer.code_store.try_get_code(&lookup))
        .await??
        .ok_or("stored code")?;
    assert_eq!(stored.client_id, CLIENT);
    assert_eq!(stored.state.as_deref(), Some(RP_STATE));
    assert_eq!(stored.nonce.as_deref(), Some(RP_NONCE));
    assert_eq!(stored.resource.as_deref(), Some(RESOURCE));
    fixture::snapshot(&namespace)?.require_surfaces(&["authcode", "request-object-jti"]);
    let (status, token) = exchange(state, sid, code, CLIENT, REDIRECT, VERIFIER).await?;
    assert_eq!(status, StatusCode::OK, "{token}");
    assert!(token["access_token"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    check_id_token(state, CLIENT, &token, Some(RP_NONCE))?;
    fixture::snapshot(&namespace)?.require_surfaces(&["token-store"]);
    let (status, replay) = exchange(state, sid, code, CLIENT, REDIRECT, VERIFIER).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{replay}");
    assert!(replay.get("access_token").is_none());
    let (status, body) = send(state, sid, &request, None, None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "one-time input: {body}");
    if par {
        let (status, body) = send(
            state,
            sid,
            "/par",
            Some(vec![("client_id", CLIENT), ("request", jwt)]),
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "signed PAR replay: {body}");
    }
    Ok(())
}

async fn scoped_http(
    runtime: &Arc<Runtime>,
    state: &AppState,
    sid: &str,
    jwt: &str,
    allowed: bool,
    par: bool,
) -> TestResult {
    let (state, sid, jwt, expected) = (
        state.clone(),
        sid.to_string(),
        jwt.to_string(),
        runtime.clone(),
    );
    runtime
        .start(
            Some(state.environment_id),
            CapacityClass::Ordinary,
            move || async move {
                let result: TestResult = async {
                    fixture::assert_owner(&expected, state.environment_id)?;
                    if allowed {
                        accepted(&state, &sid, &jwt, par).await
                    } else {
                        let (status, body) = send(
                            &state,
                            &sid,
                            "/par",
                            Some(vec![("client_id", CLIENT), ("request", &jwt)]),
                            None,
                        )
                        .await?;
                        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
                        assert_eq!(
                            serde_json::from_str::<Value>(&body)?["error"],
                            "temporarily_unavailable"
                        );
                        Ok(())
                    }
                }
                .await;
                result.map_err(|error| error.to_string())
            },
        )?
        .result()
        .await??;
    Ok(())
}

async fn refused_workers(runtime: &Arc<Runtime>, state: &AppState, jwt: &str) -> TestResult {
    // Verify the same signed object independently; do not manufacture a JTI
    // unrelated to the successful HTTP request that follows these refusals.
    let claims = state
        .clients
        .verify_request_object_async(CLIENT, jwt, state.issuer.as_str(), state.cfg.crypto_profile)
        .await?
        .claims;
    let jti = claims.jti.ok_or("signed JTI")?;
    let outer = runtime.admit(CapacityClass::Ordinary, Some(state.environment_id))?;
    let foreign = runtime.admit(CapacityClass::Ordinary, Some(state.environment_id))?;
    assert!(!outer.same_work(&foreign));
    let inner = foreign.clone();
    let store = state.protocol.request_object_jti_store.clone();
    let conflict_jti = jti.clone();
    let result = outer
        .blocking(move || {
            let executor = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            executor
                .block_on(inner.store_scope(async {
                    assert!(matches!(
                        async_store::synchronous_owner(),
                        Err(sqlx::Error::Protocol(reason))
                            if reason == "conflicting Organizations proof worker scope"
                    ));
                    assert_eq!(
                        store.check_and_store_for(CLIENT, &conflict_jti, Duration::from_secs(60)),
                        Err(RequestObjectReplayError::RecoveryDeferred)
                    );
                }))
                .map_err(|error| error.to_string())
        })
        .await;
    // Await both actual owners, including the blocking worker, before readback.
    let foreign_completion = foreign.completion_for_test().await;
    let outer_completion = outer.completion_for_test().await;
    result??;
    foreign_completion?;
    outer_completion?;

    let outer = runtime.admit(CapacityClass::Ordinary, Some(state.environment_id))?;
    let closed = outer.clone();
    let store = state.protocol.request_object_jti_store.clone();
    outer
        .blocking(move || {
            closed.close_until_restart();
            assert!(matches!(
                async_store::synchronous_owner(),
                Err(sqlx::Error::PoolClosed)
            ));
            assert_eq!(
                store.check_and_store_for(CLIENT, &jti, Duration::from_secs(60)),
                Err(RequestObjectReplayError::RecoveryDeferred)
            );
        })
        .await?;
    assert!(matches!(outer.ensure_open(), Err(sqlx::Error::PoolClosed)));
    assert!(
        matches!(
            outer.completion_for_test().await,
            Err(sqlx::Error::PoolClosed)
        ),
        "a refused owner must not manufacture a successful completion"
    );
    Ok(())
}

async fn scenario(pool: &PgPool, env: &TestEnvironment, admin: &PgPool) -> TestResult {
    let (mut state, sid) = super::super::fixture(pool, env).await?;
    let mut runtimes = Vec::new();
    let result: TestResult = async {
        let selected = fixture::activate(admin, &state).await?;
        let namespace = selected.namespace(env.environment_id)?;
        request_objects::shared_protocol_stores_in_namespace(&mut state, &namespace).await?;
        let blocked = fixture::bind(&mut state, selected).await?;
        runtimes.push(blocked.clone());
        state.validate_subject_namespace().await?;
        let jwt = signed(&state, &fields(CLIENT, Some(RP_STATE), Some(RP_NONCE)))?;
        let before = fixture::snapshot(&namespace)?;
        assert!(before.is_empty(), "fresh generation's protocol namespace");
        scoped_http(&blocked, &state, &sid, &jwt, false, true).await?;
        assert_eq!(fixture::snapshot(&namespace)?, before, "deferred proof must publish nothing");
        blocked.close().await;
        fixture::release_fence(admin).await?;
        assert!(blocked.start(Some(env.environment_id), CapacityClass::Ordinary, || async {}).is_err());
        // Fixture-only elapsed state; checked runtime must reload the real SQL
        // horizon. No mock clock or production acceptance bypass is installed.
        sqlx::query("UPDATE aegaeon_lifecycle.current SET assertions_after=clock_timestamp()-interval '1 second',request_objects_after=clock_timestamp()-interval '1 second'")
            .execute(admin).await?;
        let recovered = fixture::bind(&mut state, selected).await?;
        runtimes.push(recovered.clone());
        state.validate_subject_namespace().await?;
        refused_workers(&recovered, &state, &jwt).await?;
        assert_eq!(fixture::snapshot(&namespace)?, before, "invalid owner must publish nothing");
        scoped_http(&recovered, &state, &sid, &jwt, true, true).await?;
        let direct = signed(&state, &fields(CLIENT, Some(RP_STATE), Some(RP_NONCE)))?;
        scoped_http(&recovered, &state, &sid, &direct, true, false).await?;
        assert!(!fixture::snapshot(&namespace)?.is_empty(), "actual shared-store publication");
        Ok(())
    }.await;
    for runtime in &runtimes {
        runtime.close().await;
    }
    crate::organizations::lifecycle::close_pool(&state.db_pool).await;
    if let Some(management) = &state.management.database {
        crate::organizations::lifecycle::close_pool(management).await;
    }
    finish_test(
        result,
        fixture::release_fence(admin)
            .await
            .map_err(|error| sqlx::Error::Protocol(error.to_string())),
    )
}

#[tokio::test]
#[ignore = "requires actual PostgreSQL and Redis; checked runtime, signed PAR/JAR and token exchange"]
async fn shared_redis_pg_checked_runtime_par_jar_journey_preserves_proof_admission() -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let admin = crate::web::test_support::test_admin_pool(&pool).await?;
        let result = scenario(&pool, &env, &admin).await;
        crate::organizations::lifecycle::close_pool(&admin).await;
        result
    }
    .await;
    let result = finish_test(result, cleanup_test_environment(&pool, &env).await);
    crate::organizations::lifecycle::close_pool(&pool).await;
    result
}
