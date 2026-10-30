use super::*;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::oneshot;

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; real statement timeout in admitted connection setup"]
async fn owner_update_projection_setup_timeout_refuses_without_restart_and_recovers() -> TestResult
{
    let db = Database::create(false).await?;
    let result = async {
        let env = setup_test_dcr_environment(&db.pool).await?;
        let mut state = test_app_state(db.pool.clone(), &env).await?;
        let restart = state.runtime_restart.clone();
        let old_revision = state.runtime_authority.revision()?;
        let client = crate::web::test_support::sample_registered_client("projection-setup-timeout");
        crate::dcr_persistence::create_dynamic_registration(&db.pool, &env.issuer_host, &client, &["code".into()], "setup-owner", "setup-create").await?;
        let current = crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(&db.pool, &env.issuer_host).await?;
        assert!(old_revision.stable_authority_matches(&current));
        assert_ne!(old_revision.active_runtime_client_fingerprint(), current.active_runtime_client_fingerprint());
        let before = digest(&db.pool, &env).await?;
        // A fixture-only search path wraps the actual setup SQL. Its third call
        // follows the initial authority connection's setup and cleanup, so the
        // real server timeout occurs while setting up the projection connection.
        // The sequence survives statement rollback and identifies that boundary.
        let armed = Arc::new(AtomicBool::new(false));
        let connection_armed = armed.clone();
        let created_armed = armed.clone();
        let limited = sqlx::postgres::PgPoolOptions::new().max_connections(2)
            .before_acquire(move |connection, _| {
                let armed = connection_armed.clone();
                Box::pin(async move {
                    if armed.load(Ordering::Acquire) {
                        sqlx::query("SET statement_timeout='50ms'").execute(connection).await?;
                    }
                    Ok(true)
                })
            })
            .after_connect(move |connection, _| {
                let armed=created_armed.clone();
                Box::pin(async move {
                    sqlx::query("SET search_path=aegaeon,pg_catalog").execute(&mut *connection).await?;
                    if armed.load(Ordering::Acquire) {sqlx::query("SET statement_timeout='50ms'").execute(connection).await?;}
                    Ok(())
                })
            }).connect_lazy_with((*db.pool.connect_options()).clone());
        state.db_pool = limited.clone();
        state.validate_subject_namespace().await?;
        // Drain namespace-validation returns before arming the HTTP-only fault.
        let mut first=limited.acquire().await?;
        let mut second=limited.acquire().await?;
        first.return_to_pool().await;
        second.return_to_pool().await;
        sqlx::raw_sql("CREATE SEQUENCE aegaeon.projection_setup_calls; CREATE FUNCTION aegaeon.set_config(text,text,boolean) RETURNS text LANGUAGE plpgsql AS $$ BEGIN IF pg_catalog.nextval('aegaeon.projection_setup_calls')=3 THEN PERFORM pg_catalog.pg_sleep(1); END IF; RETURN pg_catalog.set_config($1,$2,$3); END $$;").execute(&db.admin).await?;
        let runtime_role: String = sqlx::query_scalar("SELECT current_user").fetch_one(&db.pool).await?;
        let role = format!("\"{}\"", runtime_role.replace('"', "\"\""));
        sqlx::raw_sql(&format!("GRANT USAGE,SELECT ON SEQUENCE aegaeon.projection_setup_calls TO {role}; REVOKE ALL ON FUNCTION aegaeon.set_config(text,text,boolean) FROM PUBLIC; GRANT EXECUTE ON FUNCTION aegaeon.set_config(text,text,boolean) TO {role};")).execute(&db.admin).await?;
        armed.store(true, Ordering::Release);
        let app = crate::web::router::build_router(state.clone());
        let response = tokio::time::timeout(Duration::from_secs(4), app.clone().oneshot(request(Method::PUT, "/register/untrusted", None, &json!({}))?)).await??;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!restart.is_requested(), "projection setup timeout must remain request scoped");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response_json(response).await?["error"], "temporarily_unavailable");
        assert_eq!(state.runtime_authority.revision()?, old_revision);
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                let calls: i64 = sqlx::query_scalar("SELECT last_value FROM aegaeon.projection_setup_calls").fetch_one(&db.pool).await?;
                if calls == 4 { return Ok::<(), sqlx::Error>(()); }
                assert_eq!(calls, 3, "only projection setup and its cleanup have run");
                tokio::task::yield_now().await;
            }
        }).await??;
        let response = app.oneshot(request(Method::PUT, "/register/untrusted", None, &json!({}))?).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.runtime_authority.revision()?, current);
        assert!(!restart.is_requested());
        assert_eq!(before, digest(&db.pool, &env).await?);
        limited.close().await;
        Ok::<(), Box<dyn std::error::Error>>(())
    }.await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

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
        let gate = Arc::new(Mutex::new(None::<(oneshot::Sender<()>, oneshot::Receiver<()>)>));
        let connection_gate = gate.clone();
        let armed = Arc::new(AtomicBool::new(false));
        let connection_armed = armed.clone();
        let created_armed = armed.clone();
        let limited = sqlx::postgres::PgPoolOptions::new().max_connections(2)
            .before_acquire(move |connection, _| {
                let armed = connection_armed.clone();
                Box::pin(async move {
                    if armed.load(Ordering::Acquire) {
                        sqlx::query("SET statement_timeout='200ms'").execute(connection).await?;
                    }
                    Ok(true)
                })
            })
            .after_connect(move |connection,_| {
                let armed=created_armed.clone();
                Box::pin(async move {
                    if armed.load(Ordering::Acquire) {sqlx::query("SET statement_timeout='200ms'").execute(connection).await?;}
                    Ok(())
                })
            })
            .after_release(move |_, _| {
                let gate = &connection_gate;
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
        state.validate_subject_namespace().await?;
        // Drain namespace-validation returns before arming the HTTP-only fault.
        let mut first=limited.acquire().await?;
        let mut second=limited.acquire().await?;
        first.return_to_pool().await;
        second.return_to_pool().await;
        *gate.lock().expect("arm after catalog validation") = Some((entered, wait));
        armed.store(true, Ordering::Release);
        let app = crate::web::router::build_router(state.clone());
        let pending = tokio::spawn(app.clone().oneshot(request(Method::PUT, "/register/untrusted", None, &json!({}))?));
        tokio::time::timeout(Duration::from_secs(5), observed).await.map_err(|_|"authority-return gate was not observed")??;
        // The first authority read has committed and is returning its connection.
        // Lock only now, so the refusal must come from the projection reload.
        let mut blocker = db.pool.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.clients IN ACCESS EXCLUSIVE MODE").execute(&mut *blocker).await?;
        release.send(()).map_err(|()| "release revision")?;
        let response = tokio::time::timeout(Duration::from_secs(4), pending).await.map_err(|_|"projection HTTP request exceeded fixture deadline")???;
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
