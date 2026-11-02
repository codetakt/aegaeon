use super::*;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot;

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; actual HTTP cancellation after database commit"]
async fn owner_update_cancel_after_commit_requires_current_projection_or_refuses() -> TestResult {
    for unavailable in [false, true] {
        let db = Database::create(false).await?;
        let result = scenario(&db, unavailable).await;
        let cleanup = db.cleanup().await;
        result?;
        cleanup?;
    }
    Ok(())
}

async fn scenario(db: &Database, unavailable: bool) -> TestResult {
    let env = setup_test_dcr_environment(&db.pool).await?;
    let client = sample_registered_client("commit-recovery");
    create_test_registration(&db.pool, &env, &client, "owner-before-commit").await?;
    let mut state = test_app_state(db.pool.clone(), &env).await?;
    let previous = state.runtime_authority.revision()?;
    let before_redirects = state
        .clients
        .get(&client.client_id)
        .ok_or("loaded client")?
        .redirect_uris;
    let (entered, observed) = oneshot::channel();
    let (release, wait) = oneshot::channel();
    let gate = Arc::new(Mutex::new(Some((entered, wait))));
    let limited = sqlx::postgres::PgPoolOptions::new().max_connections(3)
        .after_release(move |connection,_| {
            let gate = gate.clone();
            Box::pin(async move {
                let committed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM aegaeon.clients WHERE client_identifier='commit-recovery' AND redirect_uris=ARRAY['https://after.example/cb'])").fetch_one(connection).await?;
                let gate = if committed { gate.lock().expect("commit gate").take() } else { None };
                if let Some((entered,wait)) = gate {
                    let _ = entered.send(());
                    tokio::time::timeout(Duration::from_secs(5),wait).await.expect("bounded committed pool return").expect("release committed pool return");
                }
                Ok(true)
            })
        }).connect_lazy_with((*db.pool.connect_options()).clone());
    state.db_pool = limited.clone();
    state.validate_subject_namespace().await?;
    let app = crate::web::router::build_router(state.clone());
    let pending = tokio::spawn(app.clone().oneshot(request(Method::PUT,"/register/commit-recovery",Some("owner-before-commit"),&json!({"client_id":"commit-recovery","redirect_uris":["https://after.example/cb"],"pkce_required":true}))?));
    tokio::time::timeout(Duration::from_secs(5), observed).await??;
    // The pool hook observes the committed row before the detached persistence
    // owner can return to HTTP postcommit synchronization.
    let current =
        crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(
            &db.pool,
            &env.issuer_host,
        )
        .await?;
    assert_ne!(
        previous.active_runtime_client_fingerprint(),
        current.active_runtime_client_fingerprint()
    );
    assert_eq!(state.runtime_authority.revision()?, previous);
    assert_eq!(
        state
            .clients
            .get(&client.client_id)
            .ok_or("old client")?
            .redirect_uris,
        before_redirects
    );
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    release.send(()).map_err(|()| "commit release")?;
    // Observe both actual admission slots returning, rather than sleeping or
    // resetting the process semaphore while a worker may still be active.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let slots = crate::dcr_persistence::admit_http_update(async {
                crate::dcr_persistence::admit_http_update(async {}).await
            })
            .await;
            if matches!(slots, Ok(Ok(()))) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(
        state.runtime_authority.revision()?,
        previous,
        "cancelled HTTP continuation did not synchronize"
    );
    let committed = digest(&db.pool, &env).await?;
    if unavailable {
        limited.close().await;
    }
    let response = app
        .oneshot(request(
            Method::GET,
            "/register/commit-recovery",
            Some("owner-before-commit"),
            &json!({}),
        )?)
        .await?;
    assert_eq!(
        response.status(),
        if unavailable {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::UNAUTHORIZED
        }
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(state.runtime_restart.is_requested(), unavailable);
    if unavailable {
        assert_eq!(state.runtime_authority.revision()?, previous);
    } else {
        assert_eq!(state.runtime_authority.revision()?, current);
        assert_eq!(
            state
                .clients
                .get(&client.client_id)
                .ok_or("current client")?
                .redirect_uris,
            vec!["https://after.example/cb".to_string()]
        );
    }
    assert_eq!(committed, digest(&db.pool, &env).await?);
    limited.close().await;
    Ok(())
}
