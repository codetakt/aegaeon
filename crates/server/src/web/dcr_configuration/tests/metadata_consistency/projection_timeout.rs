use super::*;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot;

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; reload timeout after a completed authority read"]
async fn owner_update_projection_timeout_retries_without_restart_but_postcommit_still_stops(
) -> TestResult {
    let db = Database::create(false).await?;
    let result = async {
        let env = setup_test_dcr_environment(&db.pool).await?;
        let mut state = test_app_state(db.pool.clone(), &env).await?;
        let restart = state.runtime_restart.clone();
        let old_revision = state.runtime_authority.revision()?;
        let client = crate::web::test_support::sample_registered_client("projection-timeout");
        crate::dcr_persistence::create_dynamic_registration(&db.pool, &env.issuer_host, &client, &["code".into()], "projection-owner", "projection-create").await?;
        let current = crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(&db.pool, &env.issuer_host).await?;
        assert!(old_revision.stable_authority_matches(&current));
        assert_ne!(old_revision.active_runtime_client_fingerprint(), current.active_runtime_client_fingerprint());
        let before = digest(&db.pool, &env).await?;
        let (entered, observed) = oneshot::channel();
        let (release, wait) = oneshot::channel();
        let gate = Arc::new(Mutex::new(Some((entered, wait))));
        let limited = sqlx::postgres::PgPoolOptions::new().max_connections(2)
            .after_connect(|connection, _| Box::pin(async move {
                sqlx::query("SET statement_timeout='200ms'").execute(connection).await?;
                Ok(())
            }))
            .after_release(move |_, _| {
                let gate = gate.lock().expect("revision return gate").take();
                Box::pin(async move {
                    if let Some((entered, wait)) = gate {
                        let _ = entered.send(());
                        let _ = tokio::time::timeout(Duration::from_secs(5), wait).await.expect("bounded revision gate");
                    }
                    Ok(true)
                })
            }).connect_lazy_with((*db.pool.connect_options()).clone());
        state.db_pool = limited.clone();
        let app = crate::web::router::build_router(state.clone());
        let pending = tokio::spawn(app.clone().oneshot(request(Method::PUT, "/register/untrusted", None, &json!({}))?));
        tokio::time::timeout(Duration::from_secs(5), observed).await??;
        // The first authority read has committed and is returning its connection.
        // Lock only now, so the refusal must come from the projection reload.
        let mut blocker = db.pool.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.clients IN ACCESS EXCLUSIVE MODE").execute(&mut *blocker).await?;
        release.send(()).map_err(|()| "release revision")?;
        let response = tokio::time::timeout(Duration::from_secs(4), pending).await???;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response_json(response).await?["error"], "temporarily_unavailable");
        assert!(!restart.is_requested(), "pre-mutation projection timeout is request scoped");
        blocker.rollback().await?;
        assert_eq!(state.runtime_authority.revision()?, old_revision);
        let response = app.oneshot(request(Method::PUT, "/register/untrusted", None, &json!({}))?).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.runtime_authority.revision()?, current);
        assert!(!restart.is_requested());
        assert_eq!(before, digest(&db.pool, &env).await?);
        // The same admitted SQL timeout in the actual post-commit sync entry
        // retains its process-restart policy; the committed record is preserved.
        let mut blocker = db.pool.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.clients IN ACCESS EXCLUSIVE MODE").execute(&mut *blocker).await?;
        let response = crate::dcr_persistence::admit_http_update(
            crate::web::dcr_runtime::synchronize_dcr_database_runtime_clients(&state, state.issuer.as_str(), "committed-projection-timeout")
        ).await?.expect_err("postcommit projection refuses");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(restart.is_requested());
        blocker.rollback().await?;
        assert_eq!(before, digest(&db.pool, &env).await?);
        limited.close().await;
        Ok::<(), Box<dyn std::error::Error>>(())
    }.await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}
