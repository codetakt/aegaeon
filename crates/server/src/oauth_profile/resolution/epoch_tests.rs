use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use crate::web::test_support::{
    cleanup_test_environment, setup_test_environment, test_pg_pool, TestEnvironment, TestResult,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug)]
enum Query {
    Downstream,
    Upstream,
    Default,
    DownstreamTx,
    UpstreamTx,
    ObserveTx,
}

impl Query {
    async fn call(
        self,
        pool: &PgPool,
        env: &TestEnvironment,
        client: &str,
    ) -> Result<Option<String>, String> {
        let result = match self {
            Self::Downstream => resolve_downstream_profile(pool, &env.issuer_url, client).await,
            Self::Upstream => resolve_upstream_profile(pool, &env.issuer_url, client).await,
            Self::Default => resolve_default_profile(pool, &env.issuer_url, "DOWNSTREAM").await,
            _ => return self.in_tx(pool, env, client).await,
        };
        match result {
            Ok(profile) => Ok(Some(profile.id)),
            Err(ProfileError::MissingProfile) => Ok(None),
            Err(error) => Err(format!("{error:?}")),
        }
    }

    async fn in_tx(
        self,
        pool: &PgPool,
        env: &TestEnvironment,
        client: &str,
    ) -> Result<Option<String>, String> {
        let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
        let result = match self {
            Self::DownstreamTx => {
                resolve_downstream_profile_in_tx(&mut tx, &env.issuer_url, client).await
            }
            Self::UpstreamTx => {
                resolve_upstream_profile_in_tx(&mut tx, &env.issuer_url, client).await
            }
            Self::ObserveTx => {
                let result = observe_downstream_profile_in_tx(&mut tx, &env.issuer_host, client)
                    .await
                    .map(|row| row.map(|r| r.effective.id))
                    .map_err(|e| e.to_string());
                tx.rollback().await.map_err(|e| e.to_string())?;
                return result;
            }
            _ => return Err("transaction fixture variant".into()),
        };
        tx.rollback().await.map_err(|e| e.to_string())?;
        match result {
            Ok(profile) => Ok(Some(profile.id)),
            Err(ProfileError::MissingProfile) => Ok(None),
            Err(error) => Err(format!("{error:?}")),
        }
    }
}

async fn seed(pool: &PgPool, env: &TestEnvironment, client: &str) -> TestResult {
    sqlx::query("INSERT INTO aegaeon.clients(environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,status) SELECT id,active_configuration_version_id,$2,'profile ownership fixture','PUBLIC',ARRAY['https://client.example/callback'],ARRAY['authorization_code'],ARRAY['openid'],'none','ACTIVE' FROM aegaeon.environments WHERE id=$1")
        .bind(env.environment_id).bind(client).execute(pool).await?;
    sqlx::query("INSERT INTO aegaeon.oauth_profiles(environment_id,configuration_version_id,name,profile_type,is_default,sender_constrained,allowed_grant_types,token_endpoint_auth_methods_allowed) SELECT id,active_configuration_version_id,'owned-upstream','UPSTREAM',true,'NONE',ARRAY['authorization_code','refresh_token'],ARRAY['none'] FROM aegaeon.environments WHERE id=$1")
        .bind(env.environment_id).execute(pool).await?;
    sqlx::query("INSERT INTO aegaeon.connections(environment_id,configuration_version_id,connection_identifier,name,issuer_url,client_id,client_auth_method,status) SELECT id,active_configuration_version_id,$2,'profile ownership fixture','https://issuer.example','client','none','ACTIVE' FROM aegaeon.environments WHERE id=$1")
        .bind(env.environment_id).bind(client).execute(pool).await?;
    Ok(())
}

async fn scoped(query: Query) -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let first = setup_test_environment(&pool).await?;
    let second = setup_test_environment(&pool).await?;
    let client = Uuid::new_v4().to_string();
    seed(&pool, &first, &client).await?;
    seed(&pool, &second, &client).await?;
    let witness = CallerFixture::new(first.environment_id).await?;
    let result: TestResult = async {
        let own = query
            .call(&pool, &first, &client)
            .await?
            .ok_or("own profile absent")?;
        let foreign = query
            .call(&pool, &second, &client)
            .await?
            .ok_or("foreign profile absent")?;
        assert_ne!(own, foreign);
        assert_eq!(
            witness.run(query.call(&pool, &first, &client)).await??,
            Some(own)
        );
        if witness
            .run(query.call(&pool, &second, &client))
            .await??
            .is_some()
        {
            return Err(format!("{query:?} resolved a foreign Environment profile").into());
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

#[tokio::test]
#[ignore = "requires PostgreSQL; actual profile scope"]
async fn pg_organizations_profile_downstream_scope() -> TestResult {
    scoped(Query::Downstream).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual profile scope"]
async fn pg_organizations_profile_upstream_scope() -> TestResult {
    scoped(Query::Upstream).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual profile scope"]
async fn pg_organizations_profile_default_scope() -> TestResult {
    scoped(Query::Default).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual locked profile scope"]
async fn pg_organizations_profile_downstream_transaction_scope() -> TestResult {
    scoped(Query::DownstreamTx).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual locked profile scope"]
async fn pg_organizations_profile_upstream_transaction_scope() -> TestResult {
    scoped(Query::UpstreamTx).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual observed profile scope"]
async fn pg_organizations_profile_observed_transaction_scope() -> TestResult {
    scoped(Query::ObserveTx).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual profile read, cancellation and pool return"]
async fn pg_organizations_profile_upstream_owns_return() -> TestResult {
    let setup = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&setup).await?;
    let client = Uuid::new_v4().to_string();
    seed(&setup, &env, &client).await?;
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
            let mut call = Box::pin(Query::Upstream.call(&pool, &env, &client));
            let observed = async {
                while !entered.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(5)).await; }
            };
            tokio::select! {
                r = &mut call => Err::<(), Box<dyn std::error::Error>>(format!("profile returned before actual pool cleanup: {r:?}").into()),
                r = tokio::time::timeout(Duration::from_secs(5), observed) => { r?; drop(call); Ok(()) }
            }
        }).await??;
        let mut completion = tokio::spawn(work.complete());
        let early = tokio::time::timeout(Duration::from_millis(100), &mut completion).await;
        let pending = witness.pending().await?;
        enabled.store(false, Ordering::SeqCst); gate.add_permits(8);
        if early.is_ok() || pending != 1 { return Err("profile read released durable ownership before pool return".into()); }
        tokio::time::timeout(Duration::from_secs(5), completion).await???;
        assert_eq!(witness.pending().await?, 0);
        witness.run(Query::Upstream.call(&pool, &env, &client)).await??.ok_or("normal profile absent")?;
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
