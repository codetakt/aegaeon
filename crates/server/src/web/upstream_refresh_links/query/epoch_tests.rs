use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use crate::web::test_support::{
    cleanup_test_environment, setup_test_environment, test_pg_pool, TestEnvironment, TestResult,
};
use crate::web::upstream_refresh_links::fixture_upstream_refresh_caller;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::Semaphore;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
enum Query {
    Client,
    Link,
    IssuerLink,
}

impl Query {
    async fn call(self, pool: &PgPool, env: &TestEnvironment, client: &str) -> TestResult {
        if matches!(self, Self::Client) {
            let caller = fixture_upstream_refresh_caller("absent-subject".into(), client.into());
            let actual = resolve_caller_environment_id(pool, &caller, &env.issuer_url)
                .await
                .map_err(|r| format!("client lookup {}", r.status()))?;
            assert_eq!(actual, env.environment_id);
        } else {
            let issuer = matches!(self, Self::IssuerLink).then_some("https://issuer.example");
            let row = resolve_upstream_refresh_link_row(
                pool,
                "absent-subject",
                env.environment_id,
                issuer,
            )
            .await
            .map_err(|e| format!("link lookup {e:?}"))?;
            assert!(row.is_none());
        }
        Ok(())
    }
}

async fn seed_client(pool: &PgPool, env: &TestEnvironment, client: &str) -> TestResult {
    sqlx::query("INSERT INTO aegaeon.clients(environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,status) SELECT id,active_configuration_version_id,$2,'refresh ownership fixture','PUBLIC',ARRAY['https://client.example/callback'],ARRAY['authorization_code'],ARRAY['openid'],'none','ACTIVE' FROM aegaeon.environments WHERE id=$1")
        .bind(env.environment_id).bind(client).execute(pool).await?;
    Ok(())
}

async fn owns_return(query: Query) -> TestResult {
    let setup = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&setup).await?;
    let client = Uuid::new_v4().to_string();
    seed_client(&setup, &env, &client).await?;
    let witness = CallerFixture::new(env.environment_id).await?;
    let entered = Arc::new(AtomicBool::new(false));
    let enabled = Arc::new(AtomicBool::new(true));
    let gate = Arc::new(Semaphore::new(0));
    let (seen, active, wait) = (entered.clone(), enabled.clone(), gate.clone());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_release(move |_, _| {
            let (seen, active, wait) = (seen.clone(), active.clone(), wait.clone());
            Box::pin(async move {
                if active.load(Ordering::SeqCst) {
                    seen.store(true, Ordering::SeqCst);
                    wait.acquire_owned().await.unwrap().forget();
                }
                Ok(true)
            })
        })
        .connect_lazy_with(setup.connect_options().as_ref().clone());
    let result: TestResult = async {
        let work = witness.begin().await?;
        work.store_scope(async {
            let mut call = Box::pin(query.call(&pool, &env, &client));
            let observed = async {
                while !entered.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(5)).await; }
            };
            tokio::select! {
                r = &mut call => Err::<(), Box<dyn std::error::Error>>(format!("{query:?} returned before actual pool cleanup: {r:?}").into()),
                r = tokio::time::timeout(Duration::from_secs(5), observed) => { r?; drop(call); Ok(()) }
            }
        }).await??;
        let mut completion = tokio::spawn(work.complete());
        let early = tokio::time::timeout(Duration::from_millis(100), &mut completion).await;
        let pending = witness.pending().await?;
        enabled.store(false, Ordering::SeqCst); gate.add_permits(8);
        if early.is_ok() || pending != 1 { return Err("refresh read released durable ownership before pool return".into()); }
        tokio::time::timeout(Duration::from_secs(5), completion).await???;
        assert_eq!(witness.pending().await?, 0);
        witness.run(query.call(&pool, &env, &client)).await??;
        Ok(())
    }.await;
    enabled.store(false, Ordering::SeqCst);
    gate.add_permits(8);
    pool.close().await;
    let witness_cleanup = witness.finish().await.map_err(Into::into);
    let cleanup = cleanup_test_environment(&setup, &env).await;
    setup.close().await;
    result.and(witness_cleanup).and(cleanup.map_err(Into::into))
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual client lookup, cancellation and pool return"]
async fn pg_organizations_upstream_refresh_client_owns_return() -> TestResult {
    owns_return(Query::Client).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; empty link lookup, cancellation and pool return"]
async fn pg_organizations_upstream_refresh_link_owns_return() -> TestResult {
    owns_return(Query::Link).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; issuer-specific lookup, cancellation and pool return"]
async fn pg_organizations_upstream_refresh_issuer_link_owns_return() -> TestResult {
    owns_return(Query::IssuerLink).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; identical client identifiers and foreign Environment refusal"]
async fn pg_organizations_upstream_refresh_scopes_client_and_link_reads() -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let first = setup_test_environment(&pool).await?;
    let second = setup_test_environment(&pool).await?;
    let client = Uuid::new_v4().to_string();
    seed_client(&pool, &first, &client).await?;
    seed_client(&pool, &second, &client).await?;
    let witness = CallerFixture::new(first.environment_id).await?;
    let result: TestResult = async {
        let caller = fixture_upstream_refresh_caller("absent-subject".into(), client.clone());
        // An unscoped legacy caller still requires a globally unambiguous client.
        if resolve_caller_environment_id(&pool, &caller, &first.issuer_url)
            .await
            .is_ok()
        {
            return Err("ambiguous unscoped client was accepted".into());
        }
        witness
            .run(Query::Client.call(&pool, &first, &client))
            .await??;
        for issuer in [None, Some("https://issuer.example")] {
            let refused = witness
                .run(resolve_upstream_refresh_link_row(
                    &pool,
                    "absent-subject",
                    second.environment_id,
                    issuer,
                ))
                .await?;
            if refused.is_ok() {
                return Err("foreign refresh query was executed".into());
            }
        }
        assert_eq!(witness.pending().await?, 0);
        Ok(())
    }
    .await;
    let witness_cleanup = witness.finish().await.map_err(Into::into);
    let first_cleanup = cleanup_test_environment(&pool, &first).await;
    let second_cleanup = cleanup_test_environment(&pool, &second).await;
    pool.close().await;
    result
        .and(witness_cleanup)
        .and(first_cleanup.map_err(Into::into))
        .and(second_cleanup.map_err(Into::into))
}
