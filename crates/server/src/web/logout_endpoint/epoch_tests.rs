use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use crate::web::test_support::{
    cleanup_test_environment, setup_test_environment, test_app_state, test_pg_pool, TestResult,
};
use crate::web::upstream_logout_relay::UpstreamLogoutRelayState;
use uuid::Uuid;

async fn callback(state: &AppState, token: &str) -> Response {
    upstream_logout_callback(
        State(state.clone()),
        ConnectInfo("127.0.0.1:443".parse().unwrap()),
        axum::http::HeaderMap::new(),
        Query(UpstreamLogoutCallbackQuery {
            state: Some(token.into()),
        }),
    )
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual callback refuses legacy relay under Organizations"]
async fn pg_organizations_logout_endpoint_refuses_legacy_relay() -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&pool).await?;
    let state = test_app_state(pool.clone(), &env).await?;
    let witness = CallerFixture::new(env.environment_id).await?;
    let result: TestResult = async {
        for scoped in [false, true] {
            let token = Uuid::new_v4().to_string();
            state
                .upstream
                .logout_relay_store
                .try_insert_async(
                    token.clone(),
                    UpstreamLogoutRelayState {
                        incident_id: None,
                        downstream_redirect_uri: "https://client.example/logout".into(),
                        downstream_state: None,
                    },
                )
                .await?;
            let response = if scoped {
                witness.run(callback(&state, &token)).await?
            } else {
                callback(&state, &token).await
            };
            let expected = if scoped {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::FOUND
            };
            if response.status() != expected {
                return Err(
                    format!("legacy scoped={scoped} callback {}", response.status()).into(),
                );
            }
        }
        Ok(())
    }
    .await;
    state.db_pool.close().await;
    let owner = witness.finish().await.map_err(Into::into);
    let cleanup = cleanup_test_environment(&pool, &env).await;
    pool.close().await;
    result.and(owner).and(cleanup.map_err(Into::into))
}

#[tokio::test]
#[ignore = "requires PostgreSQL; persistent callback failure remains unavailable"]
async fn pg_organizations_logout_endpoint_preserves_store_error() -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&pool).await?;
    let state = test_app_state(pool.clone(), &env).await?;
    state.db_pool.close().await;
    let witness = CallerFixture::new(env.environment_id).await?;
    let result: TestResult = async {
        let response = witness
            .run(callback(&state, &Uuid::new_v4().to_string()))
            .await?;
        if response.status() != StatusCode::SERVICE_UNAVAILABLE {
            return Err(format!("storage failure became {}", response.status()).into());
        }
        Ok(())
    }
    .await;
    let owner = witness.finish().await.map_err(Into::into);
    let cleanup = cleanup_test_environment(&pool, &env).await;
    pool.close().await;
    result.and(owner).and(cleanup.map_err(Into::into))
}

#[tokio::test]
#[ignore = "requires PostgreSQL; creation failure cannot publish volatile relay"]
async fn pg_organizations_logout_endpoint_creation_failure_refuses() -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&pool).await?;
    let state = test_app_state(pool.clone(), &env).await?;
    state.db_pool.close().await;
    let witness = CallerFixture::new(env.environment_id).await?;
    let session = crate::web::auth_session::UpstreamLogoutSession {
        issuer: "https://issuer.example".into(),
        end_session_endpoint: Some("https://issuer.example/logout".into()),
        back_channel: false,
        session_hint_claim: None,
        session_hint_value: None,
        recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
        team_id: Some(env.team_id),
        tenant_id: Some(env.tenant_id),
        environment_id: Some(env.environment_id),
        connection_id: None,
    };
    let result:TestResult=async {
        let response=witness.run(crate::web::upstream_logout_sessions::build_upstream_logout_redirect_target_with_relay(
            &state,&session,None,"https://client.example/logout",None,None,"storage-failure"
        )).await?;
        match response {Err(r) if r.status()==StatusCode::SERVICE_UNAVAILABLE=>Ok(()),_=>Err("persistent creation failure admitted volatile relay".into())}
    }.await;
    let owner = witness.finish().await.map_err(Into::into);
    let cleanup = cleanup_test_environment(&pool, &env).await;
    pool.close().await;
    result.and(owner).and(cleanup.map_err(Into::into))
}
