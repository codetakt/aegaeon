use super::*;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::oneshot;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn organizations_admission_is_nonwaiting_and_shared_until_last_owner() -> TestResult {
    let limit = Arc::new(Semaphore::new(1));
    let lease = Admission::from_limit(&limit)?;
    let owner = lease.clone();
    assert!(Admission::from_limit(&limit).is_err());
    drop(lease);
    assert!(Admission::from_limit(&limit).is_err());
    drop(owner);
    assert!(Admission::from_limit(&limit).is_ok());
    Ok(())
}

async fn pool(options: PgPoolOptions) -> Result<PgPool, Box<dyn std::error::Error>> {
    Ok(options
        .max_connections(1)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?)
}

async fn settings(connection: &mut PgConnection) -> Result<Vec<i64>, sqlx::Error> {
    sqlx::query_scalar("SELECT array_agg(setting::bigint ORDER BY name) FROM pg_settings WHERE name IN ('statement_timeout','lock_timeout','idle_in_transaction_session_timeout','transaction_timeout')")
        .fetch_one(connection).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 18"]
async fn pg_organizations_request_limits_preserve_stricter_values_and_restore_pool() -> TestResult {
    let pool = pool(PgPoolOptions::new()).await?;
    let result = async {
        for (statement, lock, idle, transaction) in [(0, 0, 0, 0), (200, 100, 300, 400)] {
            let mut original = pool.acquire().await?;
            sqlx::query("SELECT set_config('statement_timeout',$1,false),set_config('lock_timeout',$2,false),set_config('idle_in_transaction_session_timeout',$3,false),set_config('transaction_timeout',$4,false)")
                .bind(statement.to_string()).bind(lock.to_string()).bind(idle.to_string()).bind(transaction.to_string())
                .execute(&mut *original).await?;
            original.return_to_pool().await;
            let limit = Arc::new(Semaphore::new(1));
            let lease = Admission::from_limit(&limit)?;
            let mut connection = lease.connection(&pool).await?;
            drop(lease);
            assert!(Admission::from_limit(&limit).is_err());
            let expected = if statement == 0 { vec![10000, 1000, 5000, 20000] } else { vec![300, 100, 200, 400] };
            assert_eq!(settings(connection.as_mut()?).await?, expected);
            connection.release().await;
            assert!(Admission::from_limit(&limit).is_ok());
            let mut returned = pool.acquire().await?;
            assert_eq!(settings(&mut returned).await?, vec![idle, lock, statement, transaction]);
            returned.return_to_pool().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }.await;
    pool.close().await;
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 18; distinct snapshot and mutation budgets"]
async fn pg_organizations_snapshot_limits_restore_pool_without_extending_mutations() -> TestResult {
    let pool = pool(PgPoolOptions::new()).await?;
    let result = async {
        let mut connection=pool.acquire().await?;
        sqlx::query("SELECT set_config('statement_timeout','0',false),set_config('lock_timeout','0',false),set_config('idle_in_transaction_session_timeout','0',false),set_config('transaction_timeout','0',false)")
            .execute(&mut *connection).await?;
        connection.return_to_pool().await;
        let snapshot=Admission::try_acquire_snapshot()?;
        assert!(Admission::try_acquire_snapshot().is_err());
        let mut read=snapshot.connection(&pool).await?;
        assert_eq!(settings(read.as_mut()?).await?,vec![30000,1000,5000,3600000]);
        let ordinary=snapshot.current_snapshot_authority()?;
        drop(snapshot);
        assert!(Admission::try_acquire_snapshot().is_err());
        read.release().await;
        assert!(Admission::try_acquire_snapshot().is_err(), "live authority retains the export lease");
        let mut write=ordinary.connection(&pool).await?;
        drop(ordinary);
        assert_eq!(settings(write.as_mut()?).await?,vec![10000,1000,5000,20000]);
        write.release().await;
        let mut returned=pool.acquire().await?;
        assert_eq!(settings(&mut returned).await?,vec![0,0,0,0]);
        returned.return_to_pool().await;
        assert!(Admission::try_acquire_snapshot().is_ok());
        Ok::<(),Box<dyn std::error::Error>>(())
    }.await;
    pool.close().await;
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 18"]
async fn pg_organizations_cancelled_checkout_keeps_lease_until_pool_finishes() -> TestResult {
    let pool = pool(PgPoolOptions::new().acquire_timeout(Duration::from_secs(1))).await?;
    let mut held = pool.acquire().await?;
    let limit = Arc::new(Semaphore::new(1));
    let lease = Admission::from_limit(&limit)?;
    let waiting_pool = pool.clone();
    let (started, observe) = oneshot::channel();
    let caller = tokio::spawn(async move {
        let mut acquisition = Box::pin(lease.connection(&waiting_pool));
        tokio::select! {
            biased;
            result = &mut acquisition => result,
            () = tokio::task::yield_now() => {
                let _ = started.send(());
                acquisition.await
            }
        }
    });
    observe.await?;
    caller.abort();
    assert!(caller.await.is_err());
    assert!(Admission::from_limit(&limit).is_err());
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(lease) = Admission::from_limit(&limit) {
                break lease;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(pool.size(), 1);
    assert_eq!(pool.num_idle(), 0);
    held.return_to_pool().await;
    pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 18"]
async fn pg_organizations_cancelled_statement_drains_server_timeout_and_recovers() -> TestResult {
    let pool = pool(PgPoolOptions::new().after_connect(|connection, _| {
        Box::pin(async move {
            sqlx::query("SET statement_timeout='1s'")
                .execute(connection)
                .await?;
            Ok(())
        })
    }))
    .await?;
    let mut observer = PgConnection::connect_with(&pool.connect_options()).await?;
    let limit = Arc::new(Semaphore::new(1));
    let lease = Admission::from_limit(&limit)?;
    let mut connection = lease.connection(&pool).await?;
    drop(lease);
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection.as_mut()?)
        .await?;
    let caller = tokio::spawn(async move {
        sqlx::query("SELECT pg_sleep(30)")
            .execute(connection.as_mut()?)
            .await
    });
    let entered = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let sleeping: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event='PgSleep')")
                .bind(pid).fetch_one(&mut observer).await?;
            if sleeping { break Ok::<(), sqlx::Error>(()); }
            tokio::task::yield_now().await;
        }
    }).await;
    caller.abort();
    let _ = caller.await;
    let retained = Admission::from_limit(&limit).is_err();
    let recovered = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if let Ok(lease) = Admission::from_limit(&limit) {
                break lease;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let answer: i32 = sqlx::query_scalar("SELECT 1").fetch_one(&pool).await?;
    drop(recovered);
    observer.close().await?;
    pool.close().await;
    entered??;
    assert!(retained, "in-flight statement must keep its lease");
    assert_eq!(answer, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 18"]
async fn pg_organizations_cancelled_transaction_rolls_back_before_releasing_lease() -> TestResult {
    let (entered, observed) = oneshot::channel();
    let (release, wait) = oneshot::channel();
    let gate = Arc::new(std::sync::Mutex::new(Some((entered, wait))));
    let pool = pool(PgPoolOptions::new().after_release(move |_, _| {
        let gate = gate.lock().unwrap().take();
        Box::pin(async move {
            if let Some((entered, wait)) = gate {
                let _ = entered.send(());
                let _ = tokio::time::timeout(Duration::from_secs(10), wait).await;
            }
            Ok(true)
        })
    }))
    .await?;
    let limit = Arc::new(Semaphore::new(1));
    let lease = Admission::from_limit(&limit)?;
    let mut connection = lease.connection(&pool).await?;
    drop(lease);
    let mut tx = connection.as_mut()?.begin().await?;
    // The actual open transaction holds an advisory lock. Dropping it must
    // queue rollback; the cleanup owner must drain that before pool release.
    sqlx::query("SELECT pg_advisory_xact_lock(71290301)")
        .execute(&mut *tx)
        .await?;
    drop(tx);
    drop(connection);
    tokio::time::timeout(Duration::from_secs(3), observed).await??;
    let retained = Admission::from_limit(&limit).is_err();
    release.send(()).map_err(|_| "cleanup gate lost")?;
    let recovered = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(lease) = Admission::from_limit(&limit) {
                break lease;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let mut returned = pool.acquire().await?;
    let in_transaction: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory')",
    )
    .fetch_one(&mut *returned)
    .await?;
    returned.return_to_pool().await;
    drop(recovered);
    pool.close().await;
    assert!(retained, "pool cleanup must retain admission");
    assert!(
        !in_transaction,
        "cancelled transaction lock survived cleanup"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 18"]
async fn pg_organizations_failed_store_never_yields_a_connection_or_loses_capacity() -> TestResult {
    let pool = pool(PgPoolOptions::new()).await?;
    let limit = Arc::new(Semaphore::new(1));
    let lease = Admission::from_limit(&limit)?;
    pool.close().await;
    assert!(matches!(
        lease.connection(&pool).await,
        Err(sqlx::Error::PoolClosed)
    ));
    drop(lease);
    assert!(Admission::from_limit(&limit).is_ok());
    Ok(())
}

#[test]
#[ignore = "requires isolated PostgreSQL 18"]
fn pg_organizations_runtime_shutdown_cannot_reschedule_cleanup_or_reopen_admission() -> TestResult {
    for drop_outside_runtime in [false, true] {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let limit = Arc::new(Semaphore::new(1));
        let (pool, outstanding) = runtime.block_on(async {
            let pool = pool(PgPoolOptions::new().min_connections(1)).await?;
            let lease = Admission::from_limit(&limit)?;
            let connection = lease.connection(&pool).await?;
            drop(lease);
            assert!(Admission::from_limit(&limit).is_err());
            // The current-thread scheduler cannot poll the cleanup after this
            // drop until we return control. Shutdown cancels that queued owner.
            let outstanding = if drop_outside_runtime {
                Some(connection)
            } else {
                drop(connection);
                None
            };
            Ok::<_, Box<dyn std::error::Error>>((pool, outstanding))
        })?;
        drop(runtime);
        drop(outstanding);
        assert!(
            limit.is_closed(),
            "unconfirmed cleanup must close admission"
        );
        let replacement = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        replacement.block_on(async {
            assert!(Admission::from_limit(&limit).is_err());
            tokio::time::timeout(Duration::from_secs(3), pool.close()).await
        })?;
    }
    Ok(())
}

#[test]
#[ignore = "requires isolated PostgreSQL 18"]
fn pg_organizations_shutdown_during_pool_hook_closes_admission() -> TestResult {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let limit = Arc::new(Semaphore::new(1));
    let (entered, observed) = oneshot::channel();
    let entered = Arc::new(std::sync::Mutex::new(Some(entered)));
    let pool = runtime.block_on(async {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |_, _| {
                let sender = entered.lock().unwrap().take();
                Box::pin(async move {
                    if let Some(sender) = sender {
                        let _ = sender.send(());
                        std::future::pending::<()>().await;
                    }
                    Ok(())
                })
            })
            .connect_lazy(&std::env::var("AEGAEON_DATABASE_URL")?)?;
        let lease = Admission::from_limit(&limit)?;
        let worker_pool = pool.clone();
        tokio::spawn(async move { lease.connection(&worker_pool).await });
        tokio::time::timeout(Duration::from_secs(3), observed).await??;
        assert!(Admission::from_limit(&limit).is_err());
        Ok::<_, Box<dyn std::error::Error>>(pool)
    })?;
    drop(runtime);
    assert!(
        limit.is_closed(),
        "shutdown interrupted a real connection hook"
    );
    assert!(Admission::from_limit(&limit).is_err());
    let replacement = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    replacement
        .block_on(async { tokio::time::timeout(Duration::from_secs(3), pool.close()).await })?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; failed actual pool return and retained lease"]
async fn pg_organizations_cleanup_panic_closes_retained_connections_without_double_panic(
) -> TestResult {
    let ordinary = pool(PgPoolOptions::new()).await?;
    let fault = PgPoolOptions::new()
        .max_connections(1)
        .after_release(|_, _| {
            Box::pin(async { panic!("fixture interrupts Organizations pool return") })
        })
        .connect_lazy(&std::env::var("AEGAEON_DATABASE_URL")?)?;
    let limit = Arc::new(Semaphore::new(1));
    let lease = Admission::from_limit(&limit)?;
    let mut outstanding = lease.connection(&ordinary).await?;
    let connection = lease.connection(&fault).await?;
    connection.release().await;
    assert!(limit.is_closed());
    assert!(matches!(lease.ensure_open(), Err(sqlx::Error::PoolClosed)));
    assert!(matches!(outstanding.as_mut(), Err(sqlx::Error::PoolClosed)));
    assert!(matches!(
        lease.connection(&ordinary).await,
        Err(sqlx::Error::PoolClosed)
    ));
    outstanding.release().await;
    tokio::time::timeout(Duration::from_secs(5), fault.close()).await?;
    tokio::time::timeout(Duration::from_secs(5), ordinary.close()).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; commit decision ordered against cleanup closure"]
async fn pg_organizations_commit_admission_orders_closure_without_undoing_commits() -> TestResult {
    for commit_first in [false, true] {
        let pool = pool(PgPoolOptions::new().max_connections(1)).await?;
        let limit = Arc::new(Semaphore::new(1));
        let lease = Admission::from_limit(&limit)?;
        let mut connection = lease.connection(&pool).await?;
        sqlx::query("CREATE TEMP TABLE organization_commit_boundary(value integer)")
            .execute(connection.as_mut()?)
            .await?;
        let mut tx = connection.as_mut()?.begin().await?;
        sqlx::query("INSERT INTO organization_commit_boundary VALUES(1)")
            .execute(&mut *tx)
            .await?;
        let admitted = if commit_first {
            let result = lease.admit_commit();
            lease.close_until_restart();
            result
        } else {
            lease.ensure_open()?;
            lease.close_until_restart();
            lease.admit_commit()
        };
        assert_eq!(admitted.is_ok(), commit_first);
        if admitted.is_ok() {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        // Test-only direct observation after closure; production cannot obtain
        // a connection from this retained closed lease.
        let raw = connection.connection.as_deref_mut().ok_or("connection")?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM organization_commit_boundary")
            .fetch_one(raw)
            .await?;
        assert_eq!(count, i64::from(commit_first));
        assert!(connection.as_mut().is_err());
        connection.release().await;
        tokio::time::timeout(Duration::from_secs(5), pool.close()).await?;
    }
    Ok(())
}
