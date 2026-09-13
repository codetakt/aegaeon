use crate::application_authorization::store::*;
use crate::web::test_support::*;
use serde_json::json;
use uuid::Uuid;
mod identities;

#[tokio::test]
#[ignore = "requires private PostgreSQL"]
async fn pg_application_revision_publication_serializes_without_other_subject_locks() -> TestResult
{
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
            assert!(capture(&pool,env.environment_id,&env.issuer_url,"client","subject").await?.is_none());
            for subject in ["subject", "other"] {
                seed_test_projection(&pool, &env, "client", subject, json!(["service-a"]),
                    json!({"roles":["USER"],"organization_roles":[]})).await?;
            }
            let original = capture(&pool,env.environment_id,&env.issuer_url,"client","subject").await?.ok_or("snapshot")?;
            assert!(is_current(&pool,env.environment_id,&env.issuer_url,&original).await?);
            assert!(!is_current(&pool,Uuid::new_v4(),&env.issuer_url,&original).await?);
            let guard = lock_current(&pool,env.environment_id,&env.issuer_url,&original).await?.ok_or("publication guard")?;
            // A shared lock has no environment-row/FK dependency and serializes only this projection.
            sqlx::query("UPDATE aegaeon.application_authorizations SET revision=2 WHERE environment_id=$1 AND subject='other'")
                .bind(env.environment_id).execute(&pool).await?;
            let (sender,receiver) = tokio::sync::oneshot::channel();
            let worker_pool = pool.clone();
            let environment = env.environment_id;
            let worker = tokio::spawn(async move {
                let mut tx = worker_pool.begin().await?;
                let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *tx).await?;
                let _ = sender.send(pid);
                sqlx::query("UPDATE aegaeon.application_authorizations SET revision=2,source_revision=2,claims=$2 WHERE environment_id=$1 AND subject='subject'")
                    .bind(environment).bind(json!({"roles":["USER","SUPER_ADMIN"],"organization_roles":[]}))
                    .execute(&mut *tx).await?;
                tx.commit().await
            });
            let pid = receiver.await?;
            let mut blocked = false;
            for _ in 0..50 {
                let count: i32 = sqlx::query_scalar("SELECT cardinality(pg_blocking_pids($1))").bind(pid).fetch_one(&pool).await?;
                if count > 0 { blocked = true; break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(blocked, "the actual UPDATE must wait for publication");
            drop(guard);
            worker.await??;
            assert!(!is_current(&pool,env.environment_id,&env.issuer_url,&original).await?);
            assert!(lock_current(&pool,env.environment_id,&env.issuer_url,&original).await?.is_none());
            let new = capture(&pool,env.environment_id,&env.issuer_url,"client","subject").await?.ok_or("new snapshot")?;
            assert!(!new.is_restriction_of(&original), "new authority never upgrades an old grant");
            sqlx::query("UPDATE aegaeon.application_authorizations SET enabled=false,revision=3 WHERE environment_id=$1 AND subject='subject'")
                .bind(env.environment_id).execute(&pool).await?;
            assert!(!is_current(&pool,env.environment_id,&env.issuer_url,&new).await?);
            Ok(())
        }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
