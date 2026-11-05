use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::Semaphore;

#[tokio::test]
#[ignore = "requires PostgreSQL; actual callback commit, cancellation and pool return"]
async fn pg_organizations_logout_callback_owns_cleanup() -> TestResult {
    let f = Fixture::new().await?;
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
        .connect_lazy_with(f.pool.connect_options().as_ref().clone());
    let result:TestResult=async {
        let work=f.witness.begin().await?;
        work.store_scope(async {
            let mut call=Box::pin(process_persisted_logout_incident(&pool,f.incident.clone(),&f.env.issuer_url,"owned-callback"));
            let observed=async {while !entered.load(Ordering::SeqCst) {tokio::time::sleep(Duration::from_millis(5)).await;}};
            tokio::select! {
                r=&mut call=>Err::<(),Box<dyn std::error::Error>>(format!("callback returned before pool cleanup: {}",r.status()).into()),
                r=tokio::time::timeout(Duration::from_secs(5),observed)=>{r?;drop(call);Ok(())}
            }
        }).await??;
        let mut completion=tokio::spawn(work.complete());
        let early=tokio::time::timeout(Duration::from_millis(100),&mut completion).await;
        let pending=f.witness.pending().await?;
        enabled.store(false,Ordering::SeqCst);gate.add_permits(8);
        if early.is_ok() || pending!=1 {return Err("logout completed witness before actual pool return".into());}
        tokio::time::timeout(Duration::from_secs(5),completion).await???;
        check_eq!(f.status().await?,"completed");
        check_eq!(f.response(&pool,f.incident.clone()).await?,StatusCode::BAD_REQUEST);
        Ok(())
    }.await;
    enabled.store(false, Ordering::SeqCst);
    gate.add_permits(8);
    pool.close().await;
    f.finish(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; closed admission before callback commit"]
async fn pg_organizations_logout_callback_refuses_closed_commit() -> TestResult {
    let f = Fixture::new().await?;
    let result:TestResult=async {
        let mut locked=f.pool.begin().await?;
        sqlx::query("SELECT id FROM aegaeon.federation_logout_recovery_incidents WHERE id=$1 FOR UPDATE")
            .bind(f.incident.id).fetch_one(&mut *locked).await?;
        let pool=sqlx::postgres::PgPoolOptions::new().max_connections(1)
            .connect_lazy_with(f.pool.connect_options().as_ref().clone());
        let mut probe=pool.acquire().await?;
        let pid:i32=sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *probe).await?;
        drop(probe);
        let work=f.witness.begin().await?;
        let scoped=work.store_scope(async {
            let owner=crate::organizations::request_work::async_store::current_owner()?;
            let mut call=Box::pin(process_persisted_logout_incident(&pool,f.incident.clone(),&f.env.issuer_url,"closed-callback"));
            let waiting=async {
                loop {
                    let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')")
                        .bind(pid).fetch_one(&f.pool).await?;
                    if blocked {return Ok::<(),sqlx::Error>(());}
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            };
            tokio::select! {
                _=&mut call=>return Err::<(),Box<dyn std::error::Error>>("callback escaped held lock".into()),
                r=tokio::time::timeout(Duration::from_secs(5),waiting)=>{r??;}
            }
            owner.close_until_restart();
            locked.rollback().await?;
            let _=call.await;
            Ok(())
        }).await;
        ensure_test!(scoped.is_err(), "closed callback scope accepted");
        ensure_test!(work.complete().await.is_err(), "closed callback completed witness");
        pool.close().await;
        check_eq!(f.status().await?,"pending");
        check_eq!(f.witness.pending().await?,1);
        Ok(())
    }.await;
    f.finish(result).await
}
