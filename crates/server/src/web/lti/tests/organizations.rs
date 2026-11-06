//! Actual SQL ownership and publication at the Organizations work boundary.
use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use std::time::Duration;

async fn control(f: &Fixture) -> Result<CallerFixture> {
    Ok(CallerFixture::with_test_stores(
        f.state.environment_id,
        f.state.db_pool.connect_options().as_ref().clone(),
    )
    .await?)
}

async fn expire(f: &Fixture) -> Result {
    f.create().await?;
    sqlx::query(
        "UPDATE aegaeon.lti_launch_intents SET created_at=1,expires_at=2 WHERE environment_id=$1",
    )
    .bind(f.state.environment_id)
    .execute(&f.state.db_pool)
    .await?;
    Ok(())
}

async fn count(f: &Fixture) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.lti_launch_intents WHERE environment_id=$1",
    )
    .bind(f.state.environment_id)
    .fetch_one(&f.state.db_pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; actual LTI cleanup and foreign-scope refusal"]
async fn shared_redis_organizations_lti_cleanup_normal_and_foreign_scope() -> Result {
    let f = Fixture::new(false, false).await?;
    expire(&f).await?;
    let witness = control(&f).await?;
    let result = async {
        assert!(witness
            .run(store::cleanup_expired(
                &f.state.db_pool,
                uuid::Uuid::new_v4()
            ))
            .await?
            .is_err());
        assert_eq!(count(&f).await?, 1);
        assert_eq!(
            witness
                .run(store::cleanup_expired(
                    &f.state.db_pool,
                    f.state.environment_id
                ))
                .await??,
            1
        );
        assert_eq!(count(&f).await?, 0);
        assert_eq!(witness.pending().await?, 0);
        Ok(())
    }
    .await;
    witness.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; real blocked DELETE and closure before COMMIT"]
async fn shared_redis_organizations_lti_cleanup_closure_rolls_back_and_retains_pending() -> Result {
    let f = Fixture::new(false, false).await?;
    expire(&f).await?;
    let witness = control(&f).await?;
    let result = async {
        let mut lock = f.state.db_pool.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.lti_launch_intents IN SHARE MODE").execute(&mut *lock).await?;
        let work = witness.begin().await?;
        let owner = work.admission().clone();
        let pool = f.state.db_pool.clone();
        let environment = f.state.environment_id;
        let worker = tokio::spawn(async move {
            let result = work.store_scope(store::cleanup_expired(&pool, environment)).await;
            (work, result)
        });
        let waiting = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND wait_event_type='Lock' AND query LIKE 'DELETE FROM aegaeon.lti_launch_intents%')").fetch_one(&f.state.db_pool).await?;
                if blocked { return Ok::<_, sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await;
        owner.close_until_restart();
        lock.rollback().await?;
        let (work, result) = tokio::time::timeout(Duration::from_secs(5), worker).await??;
        drop(owner);
        waiting??;
        assert!(result.is_err(), "closed caller must not acknowledge a cleanup");
        assert!(work.complete().await.is_err());
        assert_eq!(count(&f).await?, 1, "cleanup must roll back after admission closure");
        assert_eq!(witness.pending().await?, 1);
        Ok(())
    }.await;
    witness.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; launch and signed publication inside observed work"]
async fn shared_redis_organizations_lti_launch_preserves_claims_and_replay() -> Result {
    let mut f = Fixture::new(false, false).await?;
    let witness = control(&f).await?;
    let result = async {
        let audience = format!("{}/lti/launches", f.state.issuer);
        f.access_token = witness.run(f.issue("lti:launch", &audience)).await??;
        let path = witness.run(f.create()).await??;
        let request = witness.run(f.initiate(&path, false)).await??;
        let url = format!("/lti/authorize?{request}");
        let response = body(witness.run(f.send("GET", &url, true, None, None)).await??).await?;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        let token = hidden(&response.1, "id_token")?;
        let claims = f.verify(&token).await?;
        assert_eq!(claims["sub"], "lti-user");
        assert_eq!(claims["nickname"], "Mapped local nickname");
        let replay = body(witness.run(f.send("GET", &url, true, None, None)).await??).await?;
        assert!(!replay.1.contains("name=\"id_token\""));
        assert_eq!(witness.pending().await?, 0);
        Ok(())
    }
    .await;
    witness.finish().await?;
    result
}
