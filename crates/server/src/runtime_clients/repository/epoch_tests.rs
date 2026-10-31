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
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
enum Query {
    Projection,
    Identities,
    Federation,
    Authorization,
    Fingerprint,
    Revision,
}

impl Query {
    async fn call(
        self,
        pool: &PgPool,
        env: &TestEnvironment,
        client: &str,
        revision: &RuntimeAuthorityRevision,
    ) -> TestResult {
        let count = match self {
            Self::Projection => load_runtime_client_projection_from_database_guarded(
                pool,
                &env.issuer_host,
                revision,
            )
            .await?
            .synchronized_client_count(),
            // Deliberately no matching caller: a profile lookup cannot mask an unscoped identity read.
            Self::Identities => load_client_identities_guarded(
                pool,
                &env.issuer_host,
                env.environment_id,
                revision,
                &[client.into()],
                "absent-caller",
                &env.issuer_url,
            )
            .await?
            .len(),
            Self::Federation => {
                load_federation_subordinate_entity_ids_page(pool, &env.issuer_host, None, 10)
                    .await?
                    .entity_ids
                    .len()
            }
            _ => return self.in_tx(pool, env, client).await,
        };
        if count != 1 {
            return Err(format!("{self:?} expected one client, received {count}").into());
        }
        Ok(())
    }
    async fn in_tx(self, pool: &PgPool, env: &TestEnvironment, client: &str) -> TestResult {
        // These entrypoints receive an already-owned transaction; the fixture owns its cleanup.
        let mut tx = pool.begin().await?;
        let result: TestResult = async {
            match self {
                Self::Authorization => {
                    let found = load_authorization_client_in_tx(&mut tx, &env.issuer_host, client)
                        .await?
                        .ok_or("client absent")?;
                    if found.environment_id != env.environment_id {
                        return Err("wrong Environment".into());
                    }
                }
                Self::Fingerprint => {
                    load_active_runtime_client_fingerprint_for_issuer_host_in_tx(
                        &mut tx,
                        &env.issuer_host,
                    )
                    .await?;
                }
                Self::Revision => {
                    load_runtime_authority_revision_for_issuer_host_in_tx(
                        &mut tx,
                        &env.issuer_host,
                    )
                    .await?;
                }
                _ => return Err("unexpected transaction variant".into()),
            }
            Ok(())
        }
        .await;
        tx.rollback().await?;
        result
    }
}

async fn seed(pool: &PgPool, env: &TestEnvironment, client: &str) -> TestResult {
    sqlx::query("INSERT INTO aegaeon.clients(environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,status) SELECT id,active_configuration_version_id,$2,'runtime client fixture','PUBLIC',ARRAY['https://client.example/callback'],ARRAY['authorization_code'],ARRAY['openid'],'none','ACTIVE' FROM aegaeon.environments WHERE id=$1")
        .bind(env.environment_id).bind(client).execute(pool).await?;
    Ok(())
}
async fn revision(
    pool: &PgPool,
    env: &TestEnvironment,
) -> Result<RuntimeAuthorityRevision, Box<dyn std::error::Error>> {
    let mut tx = pool.begin().await?;
    let result =
        load_runtime_authority_revision_for_issuer_host_in_tx(&mut tx, &env.issuer_host).await;
    tx.rollback().await?;
    Ok(result?)
}

async fn scoped(query: Query) -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let first = setup_test_environment(&pool).await?;
    let second = setup_test_environment(&pool).await?;
    let client = format!("https://client.example/{}", Uuid::new_v4());
    seed(&pool, &first, &client).await?;
    seed(&pool, &second, &client).await?;
    let own = revision(&pool, &first).await?;
    let foreign = revision(&pool, &second).await?;
    let witness = CallerFixture::new(first.environment_id).await?;
    let result: TestResult = async {
        query.call(&pool, &first, &client, &own).await?;
        query.call(&pool, &second, &client, &foreign).await?;
        witness
            .run(query.call(&pool, &first, &client, &own))
            .await??;
        if witness
            .run(query.call(&pool, &second, &client, &foreign))
            .await?
            .is_ok()
        {
            return Err(format!("{query:?} accepted a foreign Environment").into());
        }
        if witness.pending().await? != 0 {
            return Err("scope read left pending work".into());
        }
        Ok(())
    }
    .await;
    let owner_cleanup = witness.finish().await.map_err(Into::into);
    let first_cleanup = cleanup_test_environment(&pool, &first)
        .await
        .map_err(Into::into);
    let second_cleanup = cleanup_test_environment(&pool, &second)
        .await
        .map_err(Into::into);
    pool.close().await;
    result
        .and(owner_cleanup)
        .and(first_cleanup)
        .and(second_cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual runtime client scope"]
async fn pg_organizations_runtime_client_projection_scope() -> TestResult {
    scoped(Query::Projection).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual runtime client scope"]
async fn pg_organizations_runtime_client_identities_scope() -> TestResult {
    scoped(Query::Identities).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual runtime client scope"]
async fn pg_organizations_runtime_client_federation_scope() -> TestResult {
    scoped(Query::Federation).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual runtime client scope"]
async fn pg_organizations_runtime_client_authorization_scope() -> TestResult {
    scoped(Query::Authorization).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual runtime client scope"]
async fn pg_organizations_runtime_client_fingerprint_scope() -> TestResult {
    scoped(Query::Fingerprint).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual runtime client scope"]
async fn pg_organizations_runtime_client_revision_scope() -> TestResult {
    scoped(Query::Revision).await
}

struct ReturnGate {
    entered: Arc<AtomicBool>,
    enabled: Arc<AtomicBool>,
    gate: Arc<Semaphore>,
}
impl ReturnGate {
    fn pool(setup: &PgPool) -> (PgPool, Self) {
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
        (
            pool,
            Self {
                entered,
                enabled,
                gate,
            },
        )
    }
    fn release(&self) {
        self.enabled.store(false, Ordering::SeqCst);
        self.gate.add_permits(8);
    }
}

async fn owns_return(query: Query) -> TestResult {
    let setup = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&setup).await?;
    let client = format!("https://client.example/{}", Uuid::new_v4());
    seed(&setup, &env, &client).await?;
    let expected = revision(&setup, &env).await?;
    let witness = CallerFixture::new(env.environment_id).await?;
    let (pool, gate) = ReturnGate::pool(&setup);
    let result: TestResult = async {
        let work = witness.begin().await?;
        work.store_scope(async {
            let mut call = Box::pin(query.call(&pool, &env, &client, &expected));
            let observed = async {
                while !gate.entered.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(5)).await; }
            };
            tokio::select! {
                r = &mut call => Err::<(), Box<dyn std::error::Error>>(format!("{query:?} returned before pool cleanup: {r:?}").into()),
                r = tokio::time::timeout(Duration::from_secs(5), observed) => { r?; drop(call); Ok(()) }
            }
        }).await??;
        let mut completion = tokio::spawn(work.complete());
        let early = tokio::time::timeout(Duration::from_millis(100), &mut completion).await;
        let pending = witness.pending().await?;
        gate.release();
        if early.is_ok() || pending != 1 { return Err("runtime read released witness before pool return".into()); }
        tokio::time::timeout(Duration::from_secs(5), completion).await???;
        if witness.pending().await? != 0 { return Err("completed read remained pending".into()); }
        witness.run(query.call(&pool, &env, &client, &expected)).await??;
        Ok(())
    }.await;
    gate.release();
    pool.close().await;
    let owner_cleanup = witness.finish().await.map_err(Into::into);
    let cleanup = cleanup_test_environment(&setup, &env)
        .await
        .map_err(Into::into);
    setup.close().await;
    result.and(owner_cleanup).and(cleanup)
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual runtime read cancellation and pool return"]
async fn pg_organizations_runtime_client_identities_owns_return() -> TestResult {
    owns_return(Query::Identities).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; actual runtime read cancellation and pool return"]
async fn pg_organizations_runtime_client_federation_owns_return() -> TestResult {
    owns_return(Query::Federation).await
}
