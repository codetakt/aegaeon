async fn subject_format_snapshot(
    pool: &sqlx::PgPool,
    environment: Uuid,
) -> Result<serde_json::Value, Box<dyn StdError>> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('users',(SELECT jsonb_agg(to_jsonb(u) ORDER BY id) FROM aegaeon.end_users u WHERE environment_id=$1),'profiles',(SELECT jsonb_agg(to_jsonb(p) ORDER BY end_user_id) FROM aegaeon.end_user_profiles p JOIN aegaeon.end_users u ON u.id=p.end_user_id WHERE u.environment_id=$1),'tokens',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM aegaeon.end_user_recovery_tokens r JOIN aegaeon.end_users u ON u.id=r.end_user_id WHERE u.environment_id=$1),'audit',(SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1))")
        .bind(environment).fetch_one(pool).await?)
}

async fn cleanup_subject_format_users(pool: &sqlx::PgPool, environment: Uuid) -> TestResult {
    sqlx::query("DELETE FROM aegaeon.end_user_recovery_tokens WHERE end_user_id IN (SELECT id FROM aegaeon.end_users WHERE environment_id=$1)").bind(environment).execute(pool).await?;
    sqlx::query("DELETE FROM aegaeon.account_links WHERE environment_id=$1")
        .bind(environment)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM aegaeon.end_users WHERE environment_id=$1")
        .bind(environment)
        .execute(pool)
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn oidc_subject_format_management_routes_are_atomic() -> TestResult {
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        let mgmt = test_management_state();
        let sid = mgmt.sessions.create(env.administrator_id, crate::util::now_unix_epoch_secs()?).ok_or("session")?;
        let app = super::super::build_router(test_app_state(pool.clone(), mgmt)?);
        let response = app.clone().oneshot(membership_http_request(Method::POST, &env, "users", &sid, serde_json::json!({"subject":"  CaseSensitive  "}))?).await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let user = response_json(response).await?;
        assert_eq!(user["subject"], "CaseSensitive");
        let patch = format!("users/{}",user["id"].as_str().ok_or("id")?);
        for invalid in [String::new(), "  ".into(), "é".into(), "x".repeat(256)] {
            for (method, path, body) in [
                (Method::POST, "users", serde_json::json!({"subject":invalid})),
                (Method::POST, "users/invitations", serde_json::json!({"subject":invalid})),
                (Method::PATCH, patch.as_str(), serde_json::json!({"subject":invalid})),
                (Method::POST, "users/importCsv", serde_json::json!({"csv":format!("subject,email\npending,pending@example.com\n{invalid},bad@example.com\n")})),
            ] {
                let before = subject_format_snapshot(&pool,env.environment_id).await?;
                let response = app.clone().oneshot(membership_http_request(method, &env,path,&sid,body)?).await?;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert_eq!(response_json(response).await?["errorCode"], "invalid_request");
                assert_eq!(subject_format_snapshot(&pool,env.environment_id).await?,before);
            }
        }
        for (path, body, expected) in [
            ("users", serde_json::json!({"subject":"A"}), "A".to_string()),
            ("users/invitations", serde_json::json!({"subject":"I".repeat(255)}), "I".repeat(255)),
            ("users/importCsv", serde_json::json!({"csv":format!("subject\n {} \n", "C".repeat(255))}), "C".repeat(255)),
        ] {
            let response = app.clone().oneshot(membership_http_request(Method::POST,&env,path,&sid,body)?).await?;
            assert!(response.status().is_success(), "{path}: {}", response.status());
            let stored: String=sqlx::query_scalar("SELECT subject FROM aegaeon.end_users WHERE environment_id=$1 AND subject=$2").bind(env.environment_id).bind(&expected).fetch_one(&pool).await?;
            assert_eq!(stored,expected);
        }
        let response=app.oneshot(membership_http_request(Method::PATCH,&env,&patch,&sid,serde_json::json!({"subject":" A\tB\u{7f} "}))?).await?;
        assert_eq!(response.status(),StatusCode::OK);
        assert_eq!(response_json(response).await?["subject"],"A\tB\u{7f}");
        Ok(())
    }.await;
    cleanup_subject_format_users(&pool, env.environment_id).await?;
    finish_runtime_key_pg_test(
        result,
        cleanup_runtime_key_test_environment(&pool, &env).await,
    )
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn oidc_subject_format_inventory_preserves_all_statuses() -> TestResult {
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult=async {
        let mut ids=Vec::new();
        for (status,subject) in [("INVITED",String::new()),("ACTIVE","é".into()),("SUSPENDED","x".repeat(256)),("DELETED","日本語".into())] {
            let id:Uuid=sqlx::query_scalar("INSERT INTO aegaeon.end_users(environment_id,subject,status) VALUES ($1,$2,$3::aegaeon.end_user_status) RETURNING id").bind(env.environment_id).bind(subject).bind(status).fetch_one(&pool).await?;
            ids.push(id);
        }
        sqlx::query("UPDATE aegaeon.environments SET status='DELETED' WHERE id=$1").bind(env.environment_id).execute(&pool).await?;
        let before=subject_format_snapshot(&pool,env.environment_id).await?;
        let rows=sqlx::raw_sql(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/../../scripts/operations/inventory-oidc-subject-format.sql"))).fetch_all(&pool).await?;
        let reported: Vec<Uuid>=rows.iter().filter_map(|r|r.try_get("end_user_id").ok()).collect();
        for id in ids {assert!(reported.contains(&id));}
        assert_eq!(subject_format_snapshot(&pool,env.environment_id).await?,before);
        Ok(())
    }.await;
    cleanup_subject_format_users(&pool, env.environment_id).await?;
    finish_runtime_key_pg_test(
        result,
        cleanup_runtime_key_test_environment(&pool, &env).await,
    )
}
