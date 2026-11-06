use super::*;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Semaphore;

async fn retained(call: Call) -> TestResult {
    let f = Fixture::new().await?;
    let active = Arc::new(AtomicBool::new(true));
    let entered = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(Semaphore::new(0));
    let count = Arc::new(AtomicUsize::new(0));
    let target = if matches!(call, Call::Bearer) { 2 } else { 1 };
    let (a, e, g) = (active.clone(), entered.clone(), gate.clone());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_release(move |_, _| {
            let (a, e, g, c) = (a.clone(), e.clone(), g.clone(), count.clone());
            Box::pin(async move {
                if a.load(Ordering::SeqCst) && c.fetch_add(1, Ordering::SeqCst) + 1 == target {
                    e.store(true, Ordering::SeqCst);
                    g.acquire_owned().await.unwrap().forget();
                }
                Ok(true)
            })
        })
        .connect_lazy_with(f.pool.connect_options().as_ref().clone());
    let result:TestResult=async {
        let row=f.record(&f.own).await?;
        let work=f.witness.begin().await?;
        work.store_scope(async {
            let mut pending=Box::pin(call.run(&pool,&f.own,&row));
            let observe=async {while !entered.load(Ordering::SeqCst) {tokio::time::sleep(Duration::from_millis(5)).await;}};
            tokio::select! {
                result=&mut pending=>Err::<(),Box<dyn std::error::Error>>(format!("{call:?} returned before pool cleanup: {result:?}").into()),
                result=tokio::time::timeout(Duration::from_secs(5),observe)=>{result?;drop(pending);Ok(())}
            }
        }).await??;
        let mut finish=tokio::spawn(work.complete());
        let early=tokio::time::timeout(Duration::from_millis(100),&mut finish).await;
        let pending=f.witness.pending().await?;
        active.store(false,Ordering::SeqCst);gate.add_permits(8);
        if early.is_ok()||pending!=1 {return Err("registration witness completed before actual return".into());}
        tokio::time::timeout(Duration::from_secs(5),finish).await???;
        Ok(())
    }.await;
    active.store(false, Ordering::SeqCst);
    gate.add_permits(8);
    pool.close().await;
    f.finish(result).await
}
macro_rules! return_test {
    ($name:ident,$case:ident) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL; retained registration pool return"]
        async fn $name() -> TestResult {
            retained(Call::$case).await
        }
    };
}
return_test!(
    pg_organizations_registration_environment_return,
    Environment
);
return_test!(pg_organizations_registration_bearer_return, Bearer);
return_test!(pg_organizations_registration_create_return, Create);
return_test!(pg_organizations_registration_update_return, Update);
return_test!(pg_organizations_registration_delete_return, Delete);

mod closed;
