//! Actual-store publication ownership regressions.
use super::*;
use crate::{
    dcr_persistence::test_database::Database,
    organizations::witness::tests::caller_fixture::CallerFixture,
    web::test_support::{
        cleanup_test_environment, seed_test_projection, setup_test_environment, TestEnvironment,
    },
};
use std::time::Duration;

#[tokio::test]
#[ignore = "requires PostgreSQL witness and isolated Redis"]
async fn shared_redis_organizations_application_projection_owns_cleanup_and_refuses_foreign_database(
) -> anyhow::Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let environment = setup_test_environment(&pool).await?;
    let witness = CallerFixture::with_test_stores(
        environment.environment_id,
        pool.connect_options().as_ref().clone(),
    )
    .await?;
    let foreign = Database::create(false).await?;
    let result = exercise(&pool, &environment, &witness, &foreign.pool).await;
    let foreign_cleanup = foreign.cleanup().await;
    let witness_cleanup = witness.finish().await;
    let environment_cleanup = cleanup_test_environment(&pool, &environment).await;
    pool.close().await;
    result
        .and(foreign_cleanup)
        .and(witness_cleanup)
        .and(environment_cleanup.map_err(Into::into))
}

async fn exercise(
    pool: &PgPool,
    environment: &TestEnvironment,
    witness: &CallerFixture,
    foreign: &PgPool,
) -> anyhow::Result<()> {
    seed_test_projection(
        pool,
        environment,
        "publication-client",
        "publication-subject",
        serde_json::json!(["publication-resource"]),
        serde_json::json!({"roles":["USER"],"organization_roles":[]}),
    )
    .await
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let grant = capture(
        pool,
        environment.environment_id,
        &environment.issuer_url,
        "publication-client",
        "publication-subject",
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("grant fixture"))?;

    // Normal capture and both explicit completion methods retain their owner,
    // including a guard moved outside its original ambient task scope.
    for commit in [false, true] {
        let work = witness.begin().await?;
        let guard = work
            .store_scope(async {
                let current = capture(
                    pool,
                    environment.environment_id,
                    &environment.issuer_url,
                    "publication-client",
                    "publication-subject",
                )
                .await?;
                anyhow::ensure!(current.as_ref() == Some(&grant));
                lock_current(
                    pool,
                    environment.environment_id,
                    &environment.issuer_url,
                    &grant,
                )
                .await?
                .ok_or_else(|| anyhow::anyhow!("publication guard"))
            })
            .await??;
        if commit {
            guard.commit().await?;
        } else {
            guard.rollback().await?;
        }
        anyhow::ensure!(work.complete().await?.pending == 0);
    }

    foreign_work_guard(pool, environment, witness, &grant).await?;
    cancelled_begin(pool, environment, witness).await?;
    for commit in [false, true] {
        closed_guard(pool, environment, witness, &grant, commit).await?;
    }
    for publication in [false, true] {
        let work = witness.begin().await?;
        let closed = work.admission().closure_probe_for_test();
        let mut refused = false;
        let scoped = work
            .store_scope(async {
                refused = if publication {
                    lock_current(
                        foreign,
                        environment.environment_id,
                        &environment.issuer_url,
                        &grant,
                    )
                    .await
                    .is_err()
                } else {
                    capture(
                        foreign,
                        environment.environment_id,
                        &environment.issuer_url,
                        "publication-client",
                        "publication-subject",
                    )
                    .await
                    .is_err()
                };
            })
            .await;
        anyhow::ensure!(refused && closed.is_closed() && scoped.is_err());
        anyhow::ensure!(work.complete().await.is_err());
        let ordinary: i32 = sqlx::query_scalar("SELECT 1").fetch_one(foreign).await?;
        anyhow::ensure!(
            ordinary == 1,
            "foreign database independently remains usable"
        );
    }
    anyhow::ensure!(witness.pending().await? == 4);
    Ok(())
}

async fn foreign_work_guard(
    pool: &PgPool,
    environment: &TestEnvironment,
    witness: &CallerFixture,
    grant: &Grant,
) -> anyhow::Result<()> {
    let work = witness.begin().await?;
    let guard = work
        .store_scope(lock_current(
            pool,
            environment.environment_id,
            &environment.issuer_url,
            grant,
        ))
        .await??
        .ok_or_else(|| anyhow::anyhow!("publication guard"))?;
    let other = witness.begin().await?;
    anyhow::ensure!(
        other.store_scope(guard.commit()).await?.is_err(),
        "guard must refuse use by another work in the same Environment"
    );
    other.complete().await?;
    anyhow::ensure!(work.complete().await?.pending == 0);
    Ok(())
}

async fn cancelled_begin(
    pool: &PgPool,
    environment: &TestEnvironment,
    witness: &CallerFixture,
) -> anyhow::Result<()> {
    let mut barrier = pool.begin().await?;
    let key = i64::from_be_bytes(uuid::Uuid::new_v4().as_bytes()[..8].try_into()?);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *barrier)
        .await?;
    let work = witness.begin().await?;
    let pid = work.store_scope(async {
        let mut guard = PublicationGuard {
            connection: Some(AdmittedConnection::acquire(pool).await?),
            environment: environment.environment_id,
            owner: async_store::task_owner()?,
        };
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(guard.connection()?).await?;
        // The actual backend has begun a transaction while SQLx has not yet
        // received the complete BEGIN exchange or incremented its depth.
        let mut beginning = Box::pin(guard.begin(
            Some(format!("BEGIN; SELECT pg_advisory_xact_lock({key})").into())));
        let observed = async {
            loop {
                let sleeping: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND xact_start IS NOT NULL AND wait_event_type='Lock')")
                    .bind(pid).fetch_one(pool).await?;
                if sleeping { return Ok::<_, sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::select! {
            result = &mut beginning => anyhow::bail!("BEGIN delay completed before observation: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(3), observed) => { result??; }
        }
        drop(beginning);
        anyhow::ensure!(guard.connection().is_err(), "unresolved BEGIN must prevent new work");
        drop(guard);
        Ok::<_, anyhow::Error>(pid)
    }).await??;
    let mut completion = tokio::spawn(work.complete());
    let early = tokio::time::timeout(Duration::from_millis(50), &mut completion).await;
    let retained = early.is_err() && witness.pending().await? == 1;
    barrier.rollback().await?;
    let completed = match early {
        Ok(result) => result?,
        Err(_) => tokio::time::timeout(Duration::from_secs(5), completion).await??,
    }?;
    anyhow::ensure!(
        retained && completed.pending == 0,
        "uncertain BEGIN cleanup must retain witness"
    );
    let transaction_open: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND xact_start IS NOT NULL)",
    )
    .bind(pid)
    .fetch_one(pool)
    .await?;
    anyhow::ensure!(
        !transaction_open,
        "depth-zero BEGIN must really be rolled back before completion"
    );
    Ok(())
}

async fn closed_guard(
    pool: &PgPool,
    environment: &TestEnvironment,
    witness: &CallerFixture,
    grant: &Grant,
    commit: bool,
) -> anyhow::Result<()> {
    let work = witness.begin().await?;
    let guard = work
        .store_scope(lock_current(
            pool,
            environment.environment_id,
            &environment.issuer_url,
            grant,
        ))
        .await??
        .ok_or_else(|| anyhow::anyhow!("publication guard"))?;
    work.admission().close_until_restart();
    if commit {
        anyhow::ensure!(
            guard.commit().await.is_err(),
            "out-of-scope commit must still refuse a closed retained owner"
        );
    } else {
        drop(guard);
    }
    // Rollback cleanup is allowed after closure, but new authority work is not.
    let mut writer = pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout='3s'")
        .execute(&mut *writer)
        .await?;
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM aegaeon.application_authorizations WHERE environment_id=$1 AND client_id='publication-client' FOR UPDATE")
        .bind(environment.environment_id).fetch_one(&mut *writer).await?;
    writer.rollback().await?;
    anyhow::ensure!(
        revision == 1,
        "closed-owner cleanup must release publication locks"
    );
    anyhow::ensure!(work.complete().await.is_err());
    Ok(())
}
