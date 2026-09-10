use super::*;
use crate::web::authorization_transactions::{begin, Kind};
use std::time::Duration;

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn pg_admission_waits_for_short_lived_same_kind_owner() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let snapshot = serde_json::json!({});
        for kind in [Kind::Login, Kind::Consent] {
            let owner = begin(&pool, env.environment_id, kind, "/authorize", &snapshot)
                .await
                .map_err(|r| format!("owner rejected: {}", r.status()))?;
            let waiting = begin(&pool, env.environment_id, kind, "/authorize", &snapshot);
            tokio::pin!(waiting);
            let premature = tokio::time::timeout(Duration::from_millis(100), &mut waiting).await;
            let waited = premature.is_err();
            owner.rollback().await?;
            if !waited {
                return Err(
                    "a short-lived competing admission was rejected instead of queued".into(),
                );
            }
            let admitted = tokio::time::timeout(Duration::from_secs(3), waiting)
                .await?
                .map_err(|r| format!("released waiter rejected: {}", r.status()))?;
            admitted.rollback().await?;
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn pg_admission_login_and_consent_do_not_share_a_lock() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let snapshot = serde_json::json!({});
        let login = begin(
            &pool,
            env.environment_id,
            Kind::Login,
            "/authorize",
            &snapshot,
        )
        .await
        .map_err(|r| format!("login rejected: {}", r.status()))?;
        let consent = tokio::time::timeout(
            Duration::from_millis(500),
            begin(
                &pool,
                env.environment_id,
                Kind::Consent,
                "/authorize",
                &snapshot,
            ),
        )
        .await;
        login.rollback().await?;
        let consent =
            consent?.map_err(|r| format!("independent consent rejected: {}", r.status()))?;
        consent.rollback().await?;
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

async fn insert_fk_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    env: &TestEnvironment,
) -> TestResult {
    sqlx::query("INSERT INTO aegaeon.authorization_logins
        (environment_id,issuer,client_id,token_sha256,browser_sha256,authorize_uri,request_snapshot,created_at,expires_at)
        VALUES ($1,$2,'fixture',gen_random_uuid()::text,'browser','/authorize','{}',now(),now()+interval '3 minutes')")
        .bind(env.environment_id).bind(&env.issuer_url).execute(&mut **tx).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn pg_admission_coexists_with_foreign_key_inserts_in_both_orders() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let snapshot = serde_json::json!({});
        for kind in [Kind::Login, Kind::Consent] {
            let mut foreign = pool.begin().await?;
            insert_fk_row(&mut foreign, &env).await?;
            let admitted = begin(&pool, env.environment_id, kind, "/authorize", &snapshot).await;
            foreign.rollback().await?;
            admitted
                .map_err(|r| format!("in-flight FK insert blocked admission: {}", r.status()))?
                .rollback()
                .await?;

            let owner = begin(&pool, env.environment_id, kind, "/authorize", &snapshot)
                .await
                .map_err(|r| format!("owner rejected: {}", r.status()))?;
            let mut foreign = pool.begin().await?;
            sqlx::query("SET LOCAL lock_timeout='300ms'")
                .execute(&mut *foreign)
                .await?;
            let inserted = insert_fk_row(&mut foreign, &env).await;
            foreign.rollback().await?;
            owner.rollback().await?;
            inserted?;
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

async fn authorize_from(
    state: &AppState,
    last_octet: u8,
    forwarded: Option<&str>,
) -> TestResult<StatusCode> {
    let app = super::super::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, last_octet], 12345)),
    )));
    let mut request = Request::get(authorize_uri(state, None)?);
    if let Some(value) = forwarded {
        request = request.header("forwarded", value);
    }
    let response = app.oneshot(request.body(Body::empty())?).await?;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        assert_eq!(response.headers()[header::RETRY_AFTER], "60");
    }
    Ok(response.status())
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn pg_admission_source_limit_preserves_other_source_access() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (state, _) = fixture(&pool, &env).await?;
        for _ in 0..60 {
            assert_eq!(authorize_from(&state, 1, None).await?, StatusCode::FOUND);
        }
        if authorize_from(&state, 1, None).await? != StatusCode::TOO_MANY_REQUESTS {
            return Err("source budget was not enforced before storage admission".into());
        }
        assert_eq!(
            authorize_from(&state, 1, Some("for=192.0.2.1;proto=https")).await?,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(authorize_from(&state, 2, None).await?, StatusCode::FOUND);
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.authorization_logins WHERE environment_id=$1",
        )
        .bind(env.environment_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(
            count, 61,
            "rejected sources must not consume storage budget"
        );
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn pg_admission_configured_throughput_exceeds_previous_default() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (mut state, _) = fixture(&pool, &env).await?;
        Arc::make_mut(&mut state.cfg)
            .database
            .authorization_admission =
            crate::config::AuthorizationAdmissionLimits::new(8192, 1000, 200)?;
        for i in 0..301 {
            let source = if i % 2 == 0 { 1 } else { 2 };
            if authorize_from(&state, source, None).await? != StatusCode::FOUND {
                return Err("configured throughput was rejected at an old/default bound".into());
            }
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.authorization_logins WHERE environment_id=$1",
        )
        .bind(env.environment_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(count, 301);
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn shared_redis_authorization_source_budget_spans_server_instances() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (mut state, _) = fixture(&pool, &env).await?;
        Arc::make_mut(&mut state.cfg)
            .database
            .authorization_admission = crate::config::AuthorizationAdmissionLimits::new(64, 12, 3)?;
        let namespace = crate::config::RuntimeStateNamespace::for_tests(Uuid::new_v4().to_string());
        let limiter = || {
            crate::device_authz::VerificationRateLimiter::try_from_shared_store_env(
                "AEGAEON_TEST_REDIS_URL",
                "local-login",
                &namespace,
            )
        };
        state.device.local_login_rate_limiter = Arc::new(limiter()?);
        let mut other = state.clone();
        other.device.local_login_rate_limiter = Arc::new(limiter()?);
        assert_eq!(authorize_from(&state, 1, None).await?, StatusCode::FOUND);
        assert_eq!(authorize_from(&other, 1, None).await?, StatusCode::FOUND);
        assert_eq!(authorize_from(&state, 1, None).await?, StatusCode::FOUND);
        assert_eq!(
            authorize_from(&other, 1, None).await?,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(authorize_from(&other, 2, None).await?, StatusCode::FOUND);

        // The authorization override does not change password-login limits.
        for _ in 0..10 {
            assert!(state
                .device
                .local_login_rate_limiter
                .try_check("local-login:control")?);
        }
        assert!(!other
            .device
            .local_login_rate_limiter
            .try_check("local-login:control")?);
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.authorization_logins WHERE environment_id=$1",
        )
        .bind(env.environment_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(count, 4);
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
