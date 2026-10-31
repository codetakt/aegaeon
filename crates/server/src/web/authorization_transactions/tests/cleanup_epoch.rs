use super::*;
use crate::organizations::{
    repository_tests::Fixture, witness::tests::caller_fixture::CallerFixture,
};
use std::time::Duration;

async fn expired(f: &Fixture) -> TestResult {
    sqlx::query("INSERT INTO aegaeon.authorization_consents(environment_id,issuer,subject,session_sha256,token_sha256,authorize_uri,request_snapshot,expires_at) VALUES($1,$2,'cleanup-commit','session',gen_random_uuid()::text,'/authorize','{}',statement_timestamp()-interval '1 minute')")
        .bind(f.env.environment_id).bind(&f.env.issuer_url).execute(&f.pool).await?;
    Ok(())
}

async fn count(f: &Fixture) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM aegaeon.authorization_consents WHERE environment_id=$1 AND subject='cleanup-commit'")
        .bind(f.env.environment_id).fetch_one(&f.pool).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual expiry deletion and closure before commit"]
async fn pg_organizations_expiry_cleanup_refuses_commit_after_closure() -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::new(f.env.environment_id).await?;
    let result = close_before_commit(&f, &witness).await;
    let cleanup = witness
        .finish()
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() });
    f.cleanup(result.and(cleanup)).await
}

async fn close_before_commit(f: &Fixture, witness: &CallerFixture) -> TestResult {
    expired(f).await?;
    let mut lock = f.pool.begin().await?;
    sqlx::query("LOCK TABLE aegaeon.authorization_consents IN SHARE MODE")
        .execute(&mut *lock)
        .await?;
    let work = witness.begin().await?;
    let owner = work.admission().clone();
    let pool = f.pool.clone();
    let environment = f.env.environment_id;
    let caller = tokio::spawn(async move {
        let result = work
            .store_scope(cleanup_expired_authorization_transactions(
                &pool,
                environment,
            ))
            .await;
        (work, result)
    });
    let observed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND wait_event_type='Lock' AND query LIKE '%DELETE FROM aegaeon.authorization_consents%')").fetch_one(&f.pool).await?;
            if blocked { return Ok::<_, sqlx::Error>(()); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await;
    owner.close_until_restart();
    lock.rollback().await?;
    let (work, result) = tokio::time::timeout(Duration::from_secs(5), caller).await??;
    drop(owner);
    assert!(
        work.complete().await.is_err(),
        "closed work must remain pending"
    );
    observed??;
    assert!(result.is_err());
    if count(f).await? != 1 {
        return Err("expiry deletion committed after closure".into());
    }
    assert_eq!(witness.pending().await?, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual slower deletion under a stricter supplier timeout"]
async fn pg_organizations_expiry_cleanup_preserves_stricter_statement_budget() -> TestResult {
    let f = Fixture::new().await?;
    expired(&f).await?;
    let admin = crate::web::test_support::test_admin_pool(&f.pool).await?;
    let name = format!("cleanup_budget_{}", Uuid::new_v4().simple());
    // A genuine delayed DELETE distinguishes the inherited 100ms budget from
    // the former unconditional two-second override. No wall-clock assertion.
    let create = format!("CREATE FUNCTION aegaeon.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.2); RETURN OLD; END $$; CREATE TRIGGER {name} BEFORE DELETE ON aegaeon.authorization_consents FOR EACH ROW WHEN (OLD.environment_id='{}') EXECUTE FUNCTION aegaeon.{name}();", f.env.environment_id);
    sqlx::raw_sql(&create).execute(&admin).await?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET statement_timeout='100ms'")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(f.pool.connect_options().as_ref().clone())
        .await?;
    let result: TestResult = async {
        let outcome = cleanup_expired_authorization_transactions(&pool, f.env.environment_id).await;
        if !matches!(outcome, Err(sqlx::Error::Database(ref e)) if e.code().as_deref()==Some("57014")) {
            return Err(format!("stricter configured timeout did not cancel expiry deletion: {outcome:?}").into());
        }
        assert_eq!(count(&f).await?, 1);
        let restored: String = sqlx::query_scalar("SHOW statement_timeout").fetch_one(&pool).await?;
        assert_eq!(restored, "100ms");
        Ok(())
    }.await;
    pool.close().await;
    let cleanup = sqlx::raw_sql(&format!(
        "DROP TRIGGER {name} ON aegaeon.authorization_consents; DROP FUNCTION aegaeon.{name}();"
    ))
    .execute(&admin)
    .await;
    admin.close().await;
    f.cleanup(result.and(cleanup.map(|_| ()).map_err(Into::into)))
        .await
}
