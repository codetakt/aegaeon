use super::*;
#[tokio::test]
#[ignore = "requires PostgreSQL; expiry after an observed device-row lock wait rolls back publication"]
async fn pg_device_expiry_during_publication_lock_wait() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result=async {
        let(store,code)=f.create(2,None).await?;let commit=f.prepare(&store,&code).await?;
        let mut held=f.pool.begin().await?;
        sqlx::query("SELECT 1 FROM aegaeon.runtime_device_codes FOR UPDATE").execute(&mut *held).await?;
        let tokens=f.tokens();let job=tokio::spawn(async move{let(a,m)=grant();tokens.store_device_grant_async(a,m,Some(commit)).await});
        let mut waiting=false;
        for _ in 0..100 {
            waiting=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT * FROM aegaeon.runtime_device_codes%')").fetch_one(&f.pool).await?;
            if waiting {break;}tokio::time::sleep(Duration::from_millis(10)).await;
        }
        anyhow::ensure!(waiting,"publication lock wait must be observed");
        tokio::time::sleep(Duration::from_millis(2100)).await;held.commit().await?;
        anyhow::ensure!(job.await?.is_err());anyhow::ensure!(f.count().await?==(1,0));
        store.cleanup_async().await.map_err(anyhow::Error::msg)?;anyhow::ensure!(f.count().await?==(0,0));
        Ok(())
    }.await;
    f.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL; 8193-row cleanup and locked remainder preserve live device state"]
async fn pg_device_bounded_cleanup_and_live_count() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result=async {
        let(store,_)=f.create(60,None).await?;
        sqlx::query("INSERT INTO aegaeon.runtime_device_codes(namespace,device_digest,user_digest,client_id,expires_us,interval_secs) SELECT $1,decode(lpad(to_hex(n),64,'0'),'hex'),decode(lpad(to_hex(n),64,'0'),'hex'),'expired',1,5 FROM generate_series(1,8193) n").bind(f.database.namespace.as_ref()).execute(&f.pool).await?;
        let mut held=f.pool.begin().await?;
        sqlx::query("SELECT 1 FROM aegaeon.runtime_device_codes WHERE expires_us=1 ORDER BY device_digest LIMIT 1 FOR UPDATE").execute(&mut *held).await?;
        store.cleanup_async().await.map_err(anyhow::Error::msg)?;anyhow::ensure!(f.count().await?==(2,0));
        anyhow::ensure!(store.active_count_async().await.map_err(anyhow::Error::msg)?==1);
        held.rollback().await?;store.cleanup_async().await.map_err(anyhow::Error::msg)?;anyhow::ensure!(f.count().await?==(1,0));
        Ok(())
    }.await;
    f.finish().await?;
    result
}
