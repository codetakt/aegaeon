// Real DCR deletion must serialize with projection activation, including the
// fresh projection INSERT's environment foreign-key check.
#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_application_activation_serializes_with_dynamic_client_deletion() -> TestResult {
    for (projection_first, repeatable_read) in [(true, false), (false, false), (false, true)] {
        application_dcr_lock_scenario(projection_first, repeatable_read).await?;
    }
    Ok(())
}

async fn application_named_pool(
    name: &str,
    repeatable_read: bool,
) -> Result<sqlx::PgPool, Box<dyn StdError>> {
    let options: sqlx::postgres::PgConnectOptions =
        std::env::var("AEGAEON_DATABASE_URL")?.parse()?;
    Ok(sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |connection, _| {
            Box::pin(async move {
                if repeatable_read {
                    sqlx::query("SET default_transaction_isolation TO 'repeatable read'")
                        .execute(connection)
                        .await?;
                }
                Ok(())
            })
        })
        .connect_with(options.application_name(name))
        .await?)
}

async fn application_wait_blocker(
    pool: &sqlx::PgPool,
    name: &str,
    blocker: i32,
) -> Result<i32, Box<dyn StdError>> {
    Ok(tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND $2=ANY(pg_blocking_pids(pid))")
                .bind(name).bind(blocker).fetch_optional(pool).await?;
            if let Some(pid) = pid { return Ok::<_, sqlx::Error>(pid); }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await??)
}

async fn application_dcr_lock_scenario(
    projection_first: bool,
    repeatable_read: bool,
) -> TestResult {
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let suffix = env.environment_id.simple().to_string();
    let function = format!("projection_gate_{suffix}");
    let table = if projection_first {
        "application_authorizations"
    } else {
        "audit_events"
    };
    let gate = i64::from(env.environment_id.as_fields().0);
    let projection_name = format!("projection-{suffix}");
    let dcr_name = format!("dcr-{suffix}");
    let projection_pool = application_named_pool(&projection_name, repeatable_read).await?;
    let dcr_pool = application_named_pool(&dcr_name, false).await?;
    let mut tasks = tokio::task::JoinSet::new();
    let result: TestResult = async {
        seed_configuration_members(&pool, &env).await?;
        let client = crate::web::test_support::sample_registered_client("projection-dcr");
        crate::dcr_persistence::create_dynamic_registration(&pool, &env.issuer_host, &client,
            &["code".into()], "projection-test-registration", "projection-dcr-create").await?;
        let stored = crate::dcr_persistence::load_dynamic_registration_by_token(&pool,
            &env.issuer_host,"projection-dcr","projection-test-registration").await?.ok_or("DCR client")?;
        let condition = if projection_first { "TRUE" } else { "NEW.event_type='dcr.client.deleted.v1'" };
        sqlx::raw_sql(&format!("CREATE FUNCTION aegaeon.{function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.environment_id='{}'::uuid AND {condition} THEN PERFORM pg_advisory_xact_lock({gate}); END IF; RETURN NEW; END $$; CREATE TRIGGER {function} BEFORE INSERT ON aegaeon.{table} FOR EACH ROW EXECUTE FUNCTION aegaeon.{function}()", env.environment_id))
            .execute(&pool).await?;
        let mut controller = pool.begin().await?;
        let controller_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *controller).await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(gate).execute(&mut *controller).await?;
        let mgmt = test_management_state();
        let sid = mgmt.sessions.create(env.administrator_id, crate::util::now_unix_epoch_secs()?).ok_or("session")?;
        let app = super::super::build_router(test_app_state(projection_pool.clone(), mgmt)?);
        let request = membership_http_request(Method::POST, &env, "application-authorizations", &sid,
            serde_json::json!({"clientId":"projection-dcr","subject":"projection-dcr",
                "baseRevision":0,"authority":"operator","sourceRevision":1,"audiences":["resource"],
                "claims":{"roles":[],"organization_roles":[]},"enabled":true,"reason":"DCR serialization"}))?;
        let projection = async move {
            let response = app.oneshot(request).await.map_err(|err| err.to_string())?;
            Ok::<_, String>(("projection", Some(response)))
        };
        let worker_pool = dcr_pool.clone();
        let deletion = async move {
            crate::dcr_persistence::delete_dynamic_registration(&worker_pool, &stored, "projection-dcr-delete")
                .await.map_err(|err| err.to_string())?;
            Ok::<_, String>(("dcr", None))
        };
        if projection_first {
            tasks.spawn(projection);
            let projection_pid = application_wait_blocker(&pool, &projection_name, controller_pid).await?;
            tasks.spawn(deletion);
            application_wait_blocker(&pool, &dcr_name, projection_pid).await?;
            // DCR must not hold the environment while waiting for our client:
            // projection INSERT will need this compatible FK lock next.
            sqlx::query("SELECT id FROM aegaeon.environments WHERE id=$1 FOR KEY SHARE NOWAIT")
                .bind(env.environment_id).execute(&mut *controller).await?;
        } else {
            tasks.spawn(deletion);
            let dcr_pid = application_wait_blocker(&pool, &dcr_name, controller_pid).await?;
            tasks.spawn(projection);
            application_wait_blocker(&pool, &projection_name, dcr_pid).await?;
        }
        controller.commit().await?;
        while let Some(joined) = tokio::time::timeout(std::time::Duration::from_secs(5), tasks.join_next()).await? {
            let (kind, response) = joined?.map_err(io::Error::other)?;
            if kind == "projection" {
                let response = response.ok_or("projection response")?;
                let status = response.status();
                let body = response_json(response).await?;
                if projection_first { assert_eq!(status, StatusCode::OK, "{body}"); }
                else if repeatable_read { assert!(status.is_server_error(), "{status}: {body}"); }
                else { assert_eq!(status, StatusCode::BAD_REQUEST, "{body}"); assert_eq!(body["errorCode"], "invalid_request"); }
            }
        }
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.application_authorizations WHERE environment_id=$1")
            .bind(env.environment_id).fetch_one(&pool).await?;
        let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='management.application_authorization.updated.v1'")
            .bind(env.environment_id).fetch_one(&pool).await?;
        assert_eq!(rows, i64::from(projection_first));
        assert_eq!(audits, rows);
        Ok(())
    }.await;
    tasks.shutdown().await;
    sqlx::raw_sql(&format!("DROP TRIGGER IF EXISTS {function} ON aegaeon.{table}; DROP FUNCTION IF EXISTS aegaeon.{function}()"))
        .execute(&pool).await?;
    projection_pool.close().await;
    dcr_pool.close().await;
    sqlx::query("DELETE FROM aegaeon.application_authorizations WHERE environment_id=$1")
        .bind(env.environment_id)
        .execute(&pool)
        .await?;
    finish_runtime_key_pg_test(result, cleanup_configuration_members(&pool, &env).await)
}
