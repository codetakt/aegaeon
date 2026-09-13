#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_application_activation_waits_for_identity_deactivation() -> TestResult {
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        seed_configuration_members(&pool, &env).await?;
        sqlx::query("INSERT INTO aegaeon.end_users(environment_id,subject,status) VALUES ($1,'projection-user','ACTIVE')")
            .bind(env.environment_id).execute(&pool).await?;
        let mgmt = test_management_state();
        let sid = mgmt.sessions.create(env.administrator_id, crate::util::now_unix_epoch_secs()?)
            .ok_or_else(|| io::Error::other("session"))?;
        let app = super::super::build_router(test_app_state(pool.clone(), mgmt)?);
        for (update, expected_query) in [
            ("UPDATE aegaeon.clients SET status='DELETED',deleted_at=now() WHERE environment_id=$1 AND client_identifier='bound'", "%SELECT id FROM aegaeon.clients%"),
            ("UPDATE aegaeon.end_users SET status='SUSPENDED' WHERE environment_id=$1 AND subject='projection-user'", "%SELECT id FROM aegaeon.end_users%"),
        ] {
            let mut tx = pool.begin().await?;
            sqlx::query(update).bind(env.environment_id).execute(&mut *tx).await?;
            let payload = serde_json::json!({"clientId":"bound","subject":"projection-user",
                "baseRevision":0,"authority":"operator","sourceRevision":1,
                "audiences":["resource"],"claims":{"roles":["USER"],"organization_roles":[]},
                "enabled":true,"reason":"identity activation serialization"});
            let request = membership_http_request(Method::POST,&env,"application-authorizations",&sid,payload)?;
            let request_app = app.clone();
            let mut task = tokio::spawn(async move { request_app.oneshot(request).await });
            // Observe the real identity query blocked by our transaction, rather
            // than relying on HTTP timing or an unrelated team/environment lock.
            let observed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    sqlx::query("SELECT pg_stat_clear_snapshot()")
                        .execute(&mut *tx).await?;
                    let blocked: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND query LIKE $1 AND wait_event_type='Lock' AND pg_backend_pid()=ANY(pg_blocking_pids(pid)))")
                        .bind(expected_query).fetch_one(&mut *tx).await?;
                    if blocked { return Ok::<_, sqlx::Error>(()); }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }).await;
            if !matches!(observed, Ok(Ok(()))) {
                task.abort(); let _ = task.await; tx.rollback().await?;
                return Err(io::Error::other("activation did not lock the changing identity").into());
            }
            tx.commit().await?;
            let response = match tokio::time::timeout(std::time::Duration::from_secs(5), &mut task).await {
                Ok(joined) => joined??,
                Err(_) => { task.abort(); let _ = task.await; return Err(io::Error::other("activation timed out").into()); }
            };
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response_json(response).await?["errorCode"], "invalid_request");
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.application_authorizations WHERE environment_id=$1")
                .bind(env.environment_id).fetch_one(&pool).await?;
            assert_eq!(count, 0, "a deactivated identity cannot create authority");
            sqlx::query("UPDATE aegaeon.clients SET status='ACTIVE',deleted_at=NULL WHERE environment_id=$1 AND client_identifier='bound'")
                .bind(env.environment_id).execute(&pool).await?;
        }
        Ok(())
    }.await;
    for table in ["application_authorizations", "end_users"] {
        sqlx::query(&format!(
            "DELETE FROM aegaeon.{table} WHERE environment_id=$1"
        ))
        .bind(env.environment_id)
        .execute(&pool)
        .await?;
    }
    finish_runtime_key_pg_test(result, cleanup_configuration_members(&pool, &env).await)
}
