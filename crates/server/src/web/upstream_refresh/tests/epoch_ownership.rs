use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::Semaphore;

async fn original(f: &Fixture) -> ResultTest<UpstreamRefreshLink> {
    f.store_callback(&f.callback(&f.claims()?, Some("private-refresh-original"))?)
        .await
        .map_err(error)?;
    Ok(f.load().await.map_err(error)?)
}

#[test]
#[ignore = "requires PostgreSQL; actual rotation, response cancellation and pool return"]
fn pg_organizations_upstream_refresh_rotation_owns_return() -> ResultTest {
    run(false, |rt, f| rt.block_on(owns_return(f)))
}

async fn owns_return(f: &Fixture) -> ResultTest {
    let link = original(f).await?;
    let before = f.stored().await?;
    let witness = CallerFixture::new(f.env.environment_id).await?;
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
    let response = Fixture::response(None, Some("private-refresh-owned"));
    let result: ResultTest = async {
        let work = witness.begin().await?;
        work.store_scope(async {
            let mut call = Box::pin(persist_upstream_refresh_exchange(&pool, &link, &response, &f.profile, &f.env.issuer_url));
            let observed = async {
                while !entered.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(5)).await; }
            };
            tokio::select! {
                r = &mut call => Err::<(), Box<dyn Error>>(format!("rotation returned before actual pool cleanup: {}", r.is_ok()).into()),
                r = tokio::time::timeout(Duration::from_secs(5), observed) => { r?; drop(call); Ok(()) }
            }
        }).await??;
        let mut completion = tokio::spawn(work.complete());
        let early = tokio::time::timeout(Duration::from_millis(100), &mut completion).await;
        let pending = witness.pending().await?;
        enabled.store(false, Ordering::SeqCst); gate.add_permits(8);
        if early.is_ok() || pending != 1 { return Err("rotation completed witness before pool return".into()); }
        tokio::time::timeout(Duration::from_secs(5), completion).await???;
        let after = f.stored().await?;
        assert_eq!(after.1, before.1 + 1);
        assert_ne!(after.0, before.0);
        let replay = witness.run(persist_upstream_refresh_exchange(&pool, &link, &response, &f.profile, &f.env.issuer_url)).await?;
        assert_eq!(replay.err().ok_or("stale rotation replay accepted")?.status(), StatusCode::CONFLICT);
        assert_eq!(f.stored().await?, after);
        let current = f.load().await.map_err(error)?;
        witness.run(persist_upstream_refresh_exchange(&pool, &current, &Fixture::response(None, None), &f.profile, &f.env.issuer_url)).await?.map_err(error)?;
        assert_eq!(witness.pending().await?, 0);
        Ok(())
    }.await;
    enabled.store(false, Ordering::SeqCst);
    gate.add_permits(8);
    pool.close().await;
    let cleanup = witness.finish().await;
    result.and(cleanup.map_err(Into::into))
}

#[test]
#[ignore = "requires PostgreSQL; foreign owner cannot rotate linked credentials"]
fn pg_organizations_upstream_refresh_rotation_refuses_foreign_owner() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            let link = original(f).await?;
            let before = f.stored().await?;
            let witness = CallerFixture::new(Uuid::new_v4()).await?;
            let response = Fixture::response(None, Some("private-refresh-foreign"));
            let result: ResultTest = async {
                let outcome = witness
                    .run(persist_upstream_refresh_exchange(
                        &f.pool,
                        &link,
                        &response,
                        &f.profile,
                        &f.env.issuer_url,
                    ))
                    .await?;
                if outcome.is_ok() || f.stored().await? != before {
                    return Err("foreign owner changed refresh credentials".into());
                }
                Ok(())
            }
            .await;
            let cleanup = witness.finish().await;
            result.and(cleanup.map_err(Into::into))
        })
    })
}

#[test]
#[ignore = "requires PostgreSQL; row-lock race and rollback after admission closure"]
fn pg_organizations_upstream_refresh_rotation_refuses_closed_commit() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            let link = original(f).await?;
            let witness = CallerFixture::new(f.env.environment_id).await?;
            let result = closed_commit(f, &link, &witness).await;
            let cleanup = witness.finish().await;
            result.and(cleanup.map_err(Into::into))
        })
    })
}

async fn closed_commit(
    f: &Fixture,
    link: &UpstreamRefreshLink,
    witness: &CallerFixture,
) -> ResultTest {
    let before = f.stored().await?;
    let mut lock = f.pool.begin().await?;
    sqlx::query("SELECT id FROM aegaeon.account_links WHERE id=$1 FOR UPDATE")
        .bind(link.account_link_id)
        .fetch_one(&mut *lock)
        .await?;
    let work = witness.begin().await?;
    let response = Fixture::response(None, Some("private-refresh-closed"));
    let mut call = Box::pin(work.store_scope(persist_upstream_refresh_exchange(
        &f.pool,
        link,
        &response,
        &f.profile,
        &f.env.issuer_url,
    )));
    let observed = async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND wait_event_type='Lock' AND query LIKE '%UPDATE aegaeon.account_links%')")
                .fetch_one(&f.state.db_pool).await?;
            if blocked {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    let (blocked, completed) = tokio::select! {
        r = &mut call => (Err("refresh completed before the controlled row lock".into()), Some(r)),
        r = tokio::time::timeout(Duration::from_secs(3), observed) => (r.map_err(Box::<dyn Error>::from).and_then(|r| r.map_err(Into::into)), None),
    };
    work.admission().close_until_restart();
    lock.rollback().await?;
    let result = match completed {
        Some(result) => Ok(result),
        None => tokio::time::timeout(Duration::from_secs(5), &mut call).await,
    };
    drop(call);
    let completion = work.complete().await;
    blocked?;
    if result?.is_ok() || completion.is_ok() || f.stored().await? != before {
        return Err("refresh committed replacement credentials after admission closed".into());
    }
    assert_eq!(witness.pending().await?, 1);
    Ok(())
}
