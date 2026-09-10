use super::*;
use crate::web::authorization_transactions::{begin, Kind};

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn pg_authorization_transactions_fix_snapshot_isolation() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        // An operator may change the database default. Admission must still
        // count a fresh snapshot after acquiring its environment lock.
        let strict = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .after_connect(|conn, _| {
                Box::pin(async move {
                    sqlx::query("SET default_transaction_isolation='repeatable read'")
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(pool.connect_options().as_ref().clone())
            .await?;
        let inherited: String = sqlx::query_scalar("SHOW default_transaction_isolation")
            .fetch_one(&strict)
            .await?;
        assert_eq!(inherited, "repeatable read");
        let mut tx = begin(
            &strict,
            env.environment_id,
            Kind::Login,
            "/authorize",
            &serde_json::json!({}),
        )
        .await
        .map_err(|r| format!("admission failed: {}", r.status()))?;
        let actual: String = sqlx::query_scalar("SHOW transaction_isolation")
            .fetch_one(&mut *tx)
            .await?;
        tx.rollback().await?;
        strict.close().await;
        assert_eq!(
            actual, "read committed",
            "counts require a fresh post-lock snapshot"
        );
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn pg_authorization_transactions_enforce_serialized_byte_limits() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let uri = "é".repeat(16_384);
        let snapshot = Value::String("\n".repeat(32_767));
        assert_eq!(uri.len(), 32_768);
        assert_eq!(serde_json::to_vec(&snapshot)?.len(), 65_536);
        for kind in [Kind::Login, Kind::Consent] {
            let tx = begin(&pool, env.environment_id, kind, &uri, &snapshot)
                .await
                .map_err(|r| format!("boundary rejected: {}", r.status()))?;
            tx.rollback().await?;
            for (uri, snapshot) in [
                (format!("{uri}a"), snapshot.clone()),
                (uri.clone(), Value::String("\n".repeat(32_768))),
            ] {
                let response = begin(&pool, env.environment_id, kind, &uri, &snapshot)
                    .await
                    .expect_err("oversized persisted payload must be rejected");
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            }
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn pg_authorization_transactions_lock_failure_is_recoverable() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL test URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let snapshot = serde_json::json!({});
        let owner = begin(
            &pool,
            env.environment_id,
            Kind::Login,
            "/authorize",
            &snapshot,
        )
        .await
        .map_err(|r| format!("owner rejected: {}", r.status()))?;
        let response = begin(
            &pool,
            env.environment_id,
            Kind::Consent,
            "/authorize",
            &snapshot,
        )
        .await
        .expect_err("a competing admission must fail without waiting for the lock");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        owner.rollback().await?;
        let recovered = begin(
            &pool,
            env.environment_id,
            Kind::Consent,
            "/authorize",
            &snapshot,
        )
        .await
        .map_err(|r| format!("lock did not recover: {}", r.status()))?;
        recovered.rollback().await?;
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
