use super::*;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Semaphore;

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
async fn owns_return(call: Call) -> TestResult {
    let f = Fixture::new().await?;
    let (pool, gate) = ReturnGate::pool(&f.pool);
    let result: TestResult = async {
        let work = f.witness.begin().await?;
        work.store_scope(async {
            let mut operation = Box::pin(call.run(&pool, f.own.environment_id));
            let observed = async { while !gate.entered.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(5)).await; } };
            tokio::select! {
                r = &mut operation => Err::<(),Box<dyn std::error::Error>>(format!("{call:?} returned before pool cleanup: {r:?}").into()),
                r = tokio::time::timeout(Duration::from_secs(5),observed) => { r?; drop(operation); Ok(()) }
            }
        }).await??;
        let mut completion = tokio::spawn(work.complete());
        let early = tokio::time::timeout(Duration::from_millis(100), &mut completion).await;
        let pending = f.witness.pending().await?; gate.release();
        if early.is_ok() || pending != 1 { return Err("repository released durable work before pool return".into()); }
        tokio::time::timeout(Duration::from_secs(5), completion).await???;
        if f.witness.pending().await? != 0 { return Err("completed repository remained pending".into()); }
        f.witness.run(call.run(&pool, f.own.environment_id)).await??;
        Ok(())
    }.await;
    gate.release();
    pool.close().await;
    f.finish(result).await
}
macro_rules! return_test {
    ($name:ident,$case:ident) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL; actual federation pool cleanup"]
        async fn $name() -> TestResult {
            owns_return(Call::$case).await
        }
    };
}
return_test!(pg_organizations_federation_anchor_list_return, AnchorList);
return_test!(pg_organizations_federation_anchor_get_return, AnchorGet);
return_test!(
    pg_organizations_federation_anchor_upsert_return,
    AnchorUpsert
);
return_test!(
    pg_organizations_federation_anchor_delete_return,
    AnchorDelete
);
return_test!(pg_organizations_federation_entity_get_return, EntityGet);
return_test!(
    pg_organizations_federation_entity_upsert_return,
    EntityUpsert
);
return_test!(pg_organizations_federation_chain_get_return, ChainGet);
return_test!(pg_organizations_federation_chain_upsert_return, ChainUpsert);

async fn closed_commit(call: Call) -> TestResult {
    let f = Fixture::new().await?;
    let application = format!("owned-federation-{}", Uuid::new_v4());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy_with(
            f.pool
                .connect_options()
                .as_ref()
                .clone()
                .application_name(&application),
        );
    let result: TestResult = async {
        let before = f.snapshot(f.own.environment_id).await?;
        let mut lock = f.pool.begin().await?;
        let query = if matches!(call,Call::AnchorUpsert|Call::AnchorDelete) {
            "SELECT id FROM aegaeon.federation_trust_anchors WHERE environment_id=$1 FOR UPDATE"
        } else { "SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE" };
        sqlx::query(query).bind(f.own.environment_id).fetch_one(&mut *lock).await?;
        let work = f.witness.begin().await?;
        let owner = work.admission().clone(); let selected = pool.clone(); let env=f.own.environment_id;
        let operation=tokio::spawn(async move { owner.store_scope(call.run(&selected,env)).await });
        let blocked = tokio::time::timeout(Duration::from_secs(5),async {
            loop {
                let count:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'").bind(&application).fetch_one(&f.pool).await?;
                if count>0 { return Ok::<_,sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await;
        work.admission().close_until_restart();
        lock.rollback().await?;
        let response=tokio::time::timeout(Duration::from_secs(5),operation).await?;
        blocked??;
        if response?.is_ok() { return Err("closed owner returned success".into()); }
        if work.complete().await.is_ok() || f.witness.pending().await?!=1 { return Err("closed operation cleared durable pending work".into()); }
        if before!=f.snapshot(env).await? { return Err(format!("{call:?} committed after admission closed").into()); }
        Ok(())
    }.await;
    pool.close().await;
    f.finish(result).await
}
macro_rules! commit_test {
    ($name:ident,$case:ident) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL; actual blocked federation commit"]
        async fn $name() -> TestResult {
            closed_commit(Call::$case).await
        }
    };
}
commit_test!(
    pg_organizations_federation_anchor_upsert_closed,
    AnchorUpsert
);
commit_test!(
    pg_organizations_federation_anchor_delete_closed,
    AnchorDelete
);
commit_test!(
    pg_organizations_federation_entity_upsert_closed,
    EntityUpsert
);
commit_test!(pg_organizations_federation_chain_upsert_closed, ChainUpsert);
