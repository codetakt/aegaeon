use super::*;
use crate::web::test_support::{
    cleanup_test_environment, finish_test, setup_test_environment, test_pg_pool, TestResult,
};

async fn seed(pool: &PgPool, environment: Uuid, kind: Kind) -> TestResult {
    let (columns, values) = match kind {
        Kind::Login => (
            "client_id,browser_sha256,authorize_uri",
            "'fixture','browser','/authorize'",
        ),
        Kind::Consent => (
            "subject,session_sha256,authorize_uri",
            "'fixture','session','/authorize'",
        ),
        Kind::Logout => ("browser_sha256", "'browser'"),
    };
    let sql = format!(
        "INSERT INTO {} (environment_id,issuer,token_sha256,request_snapshot,expires_at,{columns})
        SELECT $1,'https://op.example',gen_random_uuid()::text,'{{}}'::jsonb,
        statement_timestamp()-interval '1 second',{values} FROM generate_series(1,514)",
        kind.table()
    );
    sqlx::query(&sql).bind(environment).execute(pool).await?;
    Ok(())
}

async fn bounded(pool: &PgPool, environment: Uuid, kind: Kind, nested: bool) -> TestResult {
    seed(pool, environment, kind).await?;
    // Hold one expired row from another connection. Of the other 513 rows,
    // only 512 may be deleted by a single prune operation.
    let mut locked = pool.begin().await?;
    sqlx::query(&format!(
        "SELECT id FROM {} WHERE environment_id=$1 ORDER BY expires_at,id LIMIT 1 FOR UPDATE",
        kind.table()
    ))
    .bind(environment)
    .fetch_one(&mut *locked)
    .await?;
    let mut tx = pool.begin().await?;
    if nested {
        // Exercise repeated evaluation of a locking IN subquery. All planner
        // settings remain local to this transaction.
        for setting in [
            "enable_hashjoin",
            "enable_mergejoin",
            "enable_hashagg",
            "enable_material",
            "enable_sort",
        ] {
            sqlx::query(&format!("SET LOCAL {setting}=off"))
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("SET LOCAL plan_cache_mode=force_generic_plan")
            .execute(&mut *tx)
            .await?;
    }
    assert_eq!(prune(&mut tx, environment, kind).await?, 512);
    let count: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM {} WHERE environment_id=$1",
        kind.table()
    ))
    .bind(environment)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(
        count, 2,
        "retain the locked row and the 513th available row"
    );
    assert_eq!(prune(&mut tx, environment, kind).await?, 1);
    assert_eq!(prune(&mut tx, environment, kind).await?, 0);
    locked.rollback().await?;
    assert_eq!(prune(&mut tx, environment, kind).await?, 1);
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn pg_authorization_cleanup_bounds_nested_loop_rescans() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        for kind in [Kind::Login, Kind::Consent, Kind::Logout] {
            for nested in [false, true] {
                bounded(&pool, env.environment_id, kind, nested).await?;
            }
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual borrowed transaction statement budget"]
async fn pg_authorization_borrowed_transaction_preserves_stricter_statement_budget() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut connection = pool.acquire().await?;
        for (configured, expected) in [("200ms", "200ms"), ("0", "2s"), ("10s", "2s")] {
            sqlx::query("SELECT set_config('statement_timeout', $1, false)")
                .bind(configured)
                .execute(&mut *connection)
                .await?;
            let mut tx = begin_on_connection_with_limits(
                &mut connection,
                env.environment_id,
                Kind::Consent,
                "/authorize",
                &serde_json::json!({}),
                &AuthorizationAdmissionLimits::default(),
            )
            .await
            .map_err(|response| format!("unexpected status: {}", response.status()))?;
            let budget: String = sqlx::query_scalar("SHOW statement_timeout")
                .fetch_one(&mut *tx)
                .await?;
            assert_eq!(budget, expected);
            tx.rollback().await?;
            let restored: String = sqlx::query_scalar("SHOW statement_timeout")
                .fetch_one(&mut *connection)
                .await?;
            assert_eq!(restored, configured);
        }
        connection.close().await?;
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

mod cleanup_epoch;
