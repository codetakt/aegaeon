use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Semaphore;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL, Redis and TLS delivery; observed pool cleanup"]
async fn shared_redis_organizations_delivery_retains_epoch_until_actual_pool_return() -> TestResult
{
    let f = setup::undelivered().await?;
    configure(&f).await?;
    let transport = TransportFixture::new(204, vec![], Duration::ZERO, false)?;
    let enabled = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(Semaphore::new(0));
    let (active, observed, wait) = (enabled.clone(), entered.clone(), gate.clone());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_release(move |_, _| {
            let (active, observed, wait) = (active.clone(), observed.clone(), wait.clone());
            Box::pin(async move {
                if active.load(Ordering::SeqCst) {
                    observed.store(true, Ordering::SeqCst);
                    wait.acquire_owned().await.unwrap().forget();
                }
                Ok(true)
            })
        })
        .connect_lazy_with(f.base.pool.connect_options().as_ref().clone());
    let mut state = f.state.clone();
    state.db_pool = pool.clone();
    let result = exercise(&f, &mut state, &enabled, &entered, &gate).await;
    enabled.store(false, Ordering::SeqCst);
    gate.add_permits(8);
    pool.close().await;
    let envelopes = transport.received.lock().unwrap().len();
    drop(transport);
    let result = result.and(if envelopes == 1 {
        Ok(())
    } else {
        Err("expected one real TLS delivery".into())
    });
    f.finish(result).await
}

async fn exercise(
    f: &RecipientFixture,
    state: &mut AppState,
    enabled: &AtomicBool,
    entered: &AtomicBool,
    gate: &Semaphore,
) -> TestResult {
    state.validate_subject_namespace().await?;
    // Finish validation's return hook before enabling the observed delivery gate.
    let mut ready = state.db_pool.acquire().await?;
    ready.return_to_pool().await;
    enabled.store(true, Ordering::SeqCst);
    let work = f.witness.begin().await?;
    let delivery = work.store_scope(async {
        let mut call = Box::pin(state.deliver_organization_invitation(request(f, None)));
        let waiting = async {
            while !entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::select! {
            result = &mut call => Err::<(), Box<dyn std::error::Error>>(format!("delivery returned before controlled cleanup: {result:?}").into()),
            result = tokio::time::timeout(Duration::from_secs(10), waiting) => {
                result?;
                // Drop the response waiter while the actual pool-return task
                // still owns the connection. No timeout clears its durable slot.
                drop(call);
                Ok(())
            }
        }
    }).await;
    delivery??;
    let mut completion = tokio::spawn(async move { work.complete().await });
    let early = tokio::time::timeout(Duration::from_millis(100), &mut completion).await;
    let pending = f.witness.pending().await?;
    enabled.store(false, Ordering::SeqCst);
    gate.add_permits(1);
    let premature = match early {
        Ok(result) => {
            result??;
            true
        }
        Err(_) => {
            tokio::time::timeout(Duration::from_secs(5), completion).await???;
            false
        }
    };
    if premature || pending != 1 {
        return Err("delivery completed its witness before actual pool cleanup".into());
    }
    assert_eq!(f.witness.pending().await?, 0);
    Ok(())
}
