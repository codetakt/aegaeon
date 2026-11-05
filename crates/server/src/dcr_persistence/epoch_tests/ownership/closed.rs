use super::*;
async fn closed(call: Call) -> TestResult {
    let f = Fixture::new().await?;
    let name = format!("registration-close-{}", Uuid::new_v4());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy_with(
            f.pool
                .connect_options()
                .as_ref()
                .clone()
                .application_name(&name),
        );
    let result:TestResult=async {
        let row=f.record(&f.own).await?;
        let before=f.snapshot(f.own.environment_id).await?;
        let mut lock=f.pool.begin().await?;
        sqlx::query("SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE").bind(f.own.environment_id).fetch_one(&mut *lock).await?;
        let work=f.witness.begin().await?;
        let work_label = work.admission().store_label()?.ok_or("missing work label")?.to_owned();
        let owner=work.admission().clone();
        let mut reached_lock=false;
        let observed=work.store_scope(async {
            let mut pending=Box::pin(call.run(&pool,&f.own,&row));
            let wait=async {loop {
                let locked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')").bind(&work_label).fetch_one(&f.pool).await?;
                if locked {return Ok::<(),sqlx::Error>(());}
                tokio::time::sleep(Duration::from_millis(5)).await;
            }};
            let reached=tokio::select! {
                result=&mut pending=>Err::<(),Box<dyn std::error::Error>>(format!("{call:?} ended before row lock: {result:?}").into()),
                result=tokio::time::timeout(Duration::from_secs(5),wait)=>{result??;Ok(())}
            };
            owner.close_until_restart();lock.rollback().await?;reached?;reached_lock=true;
            if pending.await.is_ok() {return Err("registration committed after admission closed".into());}
            Ok::<(),Box<dyn std::error::Error>>(())
        }).await;
        drop(owner);
        // Closed scope refuses even when its inner future returns normally.
        let _=observed;
        if !reached_lock {return Err("registration row-lock precondition was not observed".into());}
        let completion=work.complete().await;
        if completion.is_ok() {return Err("closed registration completed witness".into());}
        if before!=f.snapshot(f.own.environment_id).await? {return Err("registration committed after admission closed".into());}
        if f.witness.pending().await?!=1 {return Err("uncertain registration admission was cleared".into());}
        Ok(())
    }.await;
    pool.close().await;
    f.finish(result).await
}
macro_rules! closed_test {
    ($name:ident,$case:ident) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL; actual close before registration commit"]
        async fn $name() -> TestResult {
            closed(Call::$case).await
        }
    };
}
closed_test!(pg_organizations_registration_create_closed, Create);
closed_test!(pg_organizations_registration_update_closed, Update);
closed_test!(pg_organizations_registration_delete_closed, Delete);
