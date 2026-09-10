use super::*;

async fn populate(state: &AppState, login: bool, count: i32, recent: bool) -> TestResult {
    let sql = if login {
        "INSERT INTO aegaeon.authorization_logins
        (environment_id,issuer,client_id,token_sha256,browser_sha256,authorize_uri,request_snapshot,created_at,expires_at)
        SELECT $1,$2,'fixture',gen_random_uuid()::text,'browser','/authorize','{}'::jsonb,
        now()-make_interval(secs=>$4),now()+interval '3 minutes' FROM generate_series(1,$3)"
    } else {
        "INSERT INTO aegaeon.authorization_consents
        (environment_id,issuer,subject,session_sha256,token_sha256,authorize_uri,request_snapshot,created_at,expires_at)
        SELECT $1,$2,'fixture','session',gen_random_uuid()::text,'/authorize','{}'::jsonb,
        now()-make_interval(secs=>$4),now()+interval '3 minutes' FROM generate_series(1,$3)"
    };
    sqlx::query(sql)
        .bind(state.environment_id)
        .bind(state.issuer.as_str())
        .bind(count)
        .bind(if recent { 0.0_f64 } else { 120.0_f64 })
        .execute(&state.db_pool)
        .await?;
    Ok(())
}

async fn rows(state: &AppState, login: bool) -> TestResult<i64> {
    let sql = if login {
        "SELECT count(*) FROM aegaeon.authorization_logins WHERE environment_id=$1"
    } else {
        "SELECT count(*) FROM aegaeon.authorization_consents WHERE environment_id=$1"
    };
    Ok(sqlx::query_scalar(sql)
        .bind(state.environment_id)
        .fetch_one(&state.db_pool)
        .await?)
}

async fn limits(state: &AppState, sid: &str, login: bool, recent: bool) -> TestResult {
    let limit = if recent { 300 } else { 4096 };
    populate(state, login, limit, recent).await?;
    let uri = authorize_uri(state, Some("consent"))?;
    let (status, body) = send(
        state,
        if login { "no-session" } else { sid },
        &uri,
        None,
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(rows(state, login).await?, i64::from(limit));
    if recent {
        let sql = if login {
            "UPDATE aegaeon.authorization_logins SET completed_at=now(),consumed_at=now(),session_snapshot='{}'::jsonb WHERE environment_id=$1"
        } else {
            "UPDATE aegaeon.authorization_consents SET decision='deny',decided_at=now() WHERE environment_id=$1"
        };
        sqlx::query(sql)
            .bind(state.environment_id)
            .execute(&state.db_pool)
            .await?;
        let (status, _) = send(
            state,
            if login { "no-session" } else { sid },
            &authorize_uri(state, Some("consent"))?,
            None,
            None,
        )
        .await?;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "completion must not refund the insertion budget"
        );
    }
    Ok(())
}

async fn expiry(state: &AppState, sid: &str, login: bool) -> TestResult {
    populate(state, login, 3, false).await?;
    let sql = if login {
        "UPDATE aegaeon.authorization_logins SET expires_at=now()-interval '1 second' WHERE environment_id=$1"
    } else {
        "UPDATE aegaeon.authorization_consents SET expires_at=now()-interval '1 second' WHERE environment_id=$1"
    };
    sqlx::query(sql)
        .bind(state.environment_id)
        .execute(&state.db_pool)
        .await?;
    let (status, body) = send(
        state,
        if login { "no-session" } else { sid },
        &authorize_uri(state, Some("consent"))?,
        None,
        None,
    )
    .await?;
    assert_eq!(
        status,
        if login {
            StatusCode::FOUND
        } else {
            StatusCode::OK
        },
        "{body}"
    );
    assert_eq!(
        rows(state, login).await?,
        1,
        "expired request payloads must be removed"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn pg_authorization_transactions_bound_untrusted_writes() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    for login in [true, false] {
        for recent in [true, false] {
            let env = setup_test_environment(&pool).await?;
            let result = async {
                let (state, sid) = fixture(&pool, &env).await?;
                limits(&state, &sid, login, recent).await
            }
            .await;
            finish_test(result, cleanup_test_environment(&pool, &env).await)?;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn pg_authorization_transactions_prune_expired_payloads() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    for login in [true, false] {
        let env = setup_test_environment(&pool).await?;
        let result = async {
            let (state, sid) = fixture(&pool, &env).await?;
            expiry(&state, &sid, login).await
        }
        .await;
        finish_test(result, cleanup_test_environment(&pool, &env).await)?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn pg_authorization_transactions_last_slot_has_one_winner() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (state, _) = fixture(&pool, &env).await?;
        populate(&state, true, 4095, false).await?;
        let a = authorize_uri(&state, Some("consent"))?;
        let b = authorize_uri(&state, Some("consent"))?;
        let (a, b) = tokio::join!(
            send(&state, "no-session", &a, None, None),
            send(&state, "no-session", &b, None, None),
        );
        let statuses = [a?.0, b?.0];
        assert_eq!(
            statuses.iter().filter(|s| **s == StatusCode::FOUND).count(),
            1
        );
        assert!(statuses.iter().all(|s| matches!(
            *s,
            StatusCode::FOUND | StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
        )));
        assert_eq!(rows(&state, true).await?, 4096);
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn pg_authorization_transactions_cleanup_preserves_live_and_foreign() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    let env = setup_test_environment(&pool).await?;
    let foreign = setup_test_environment(&pool).await?;
    let result = async {
        let (state, _) = fixture(&pool, &env).await?;
        let other = test_app_state(pool.clone(), &foreign).await?;
        for (login, table) in [(true, "authorization_logins"), (false, "authorization_consents")] {
            populate(&state, login, 3, false).await?;
            populate(&other, login, 3, false).await?;
            sqlx::query(&format!("UPDATE aegaeon.{table} SET expires_at=now()-interval '1 second' WHERE environment_id=$1 OR id IN (SELECT id FROM aegaeon.{table} WHERE environment_id=$2 LIMIT 1)"))
                .bind(other.environment_id).bind(state.environment_id).execute(&pool).await?;
        }
        assert_eq!(crate::web::cleanup_expired_authorization_transactions(&pool, state.environment_id).await?, 2);
        for login in [true, false] {
            assert_eq!(rows(&state, login).await?, 2);
            assert_eq!(rows(&other, login).await?, 3);
        }
        assert_eq!(crate::web::cleanup_expired_authorization_transactions(&pool, state.environment_id).await?, 0);
        Ok(())
    }.await;
    let result = finish_test(result, cleanup_test_environment(&pool, &foreign).await);
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
