use super::*;

async fn last_used(f: &Fixture) -> ResultTest<String> {
    Ok(
        sqlx::query_scalar("SELECT last_used_at::text FROM aegaeon.account_links WHERE id=$1")
            .bind(f.link_id)
            .fetch_one(&f.pool)
            .await?,
    )
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_refresh_context_pg_last_use_never_regresses() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
        let claims=f.claims()?;
        f.store_callback(&f.callback(&claims,Some("private-refresh-original"))?).await.map_err(error)?;
        let link=f.load().await.map_err(error)?;
        let mut older=f.pool.begin().await?;
        let older_time:String=sqlx::query_scalar("SELECT now()::text").fetch_one(&mut *older).await?;
        f.refresh(&link,None,None).await.map_err(error)?;
        let newer_time=last_used(f).await?;
        let distinct:bool=sqlx::query_scalar("SELECT $1::text::timestamptz > $2::text::timestamptz")
            .bind(&newer_time).bind(&older_time).fetch_one(&f.pool).await?;
        assert!(distinct,"fixture must establish distinct ordered transaction times");
        super::super::persistence::lock_current_connection(&mut older,&link,&f.profile,&f.env.issuer_url).await.map_err(error)?;
        super::super::persistence::persist_locked_upstream_refresh_exchange(&mut older,&link,&Fixture::response(None,None),&f.env.issuer_url).await.map_err(error)?;
        older.commit().await?;
        assert_eq!(last_used(f).await?,newer_time);
        // Also cover both branches with a stored timestamp ahead of the clock.
        for rotation in [None,Some("private-refresh-next")] {
            sqlx::query("UPDATE aegaeon.account_links SET last_used_at=clock_timestamp()+interval '1 hour' WHERE id=$1")
                .bind(f.link_id).execute(&f.pool).await?;
            let future=last_used(f).await?;
            let link=f.load().await.map_err(error)?;
            f.refresh(&link,None,rotation).await.map_err(error)?;
            assert_eq!(last_used(f).await?,future);
        }
        Ok(())
    })
    })
}
