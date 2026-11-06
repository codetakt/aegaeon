//! Real LISTEN/reconnect checks, with durable observed work and no idle lease.
use super::*;
use crate::{
    organizations::{repository_tests::Fixture, witness::tests::caller_fixture::CallerFixture},
    runtime_restart::RuntimeRestartRequest,
    web::test_support::{test_app_state, TestResult},
};
use sqlx::ConnectOptions;
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

fn stop(restart: &crate::runtime_restart::RuntimeRestartState) {
    restart.request_restart(RuntimeRestartRequest::runtime_authority_unavailable(
        "notification-test",
        "issuer.example",
        "notification-test",
    ));
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; initial, reconnected and notified checks own separate work"]
async fn shared_redis_organizations_runtime_assembly_notifications_reconnect() -> TestResult {
    let f = Fixture::new().await?;
    let mut control = super::tests::witness(&f).await?;
    let state = test_app_state(f.pool.clone(), &f.env).await?;
    let result = async {
        let configuration = super::tests::loaded(&f).await?;
        let monitor = RuntimeConfigMonitor::from_state(&state, &configuration);
        let mut endpoint = f.pool.connect_options().to_url_lossy();
        let application = format!("organization-notifications-{}", uuid::Uuid::new_v4());
        endpoint.query_pairs_mut().append_pair("application_name", &application);
        let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
        let count = AtomicUsize::new(0);
        let caller: &CallerFixture = &control;
        let count_ref = &count;
        let runner = notifications::run(endpoint.as_str(), &f.env.issuer_host, &state.runtime_restart, || {
            let monitor = monitor.clone();
            let send = send.clone();
            async move {
                caller.run(monitor.check_revision()).await?;
                send.send(count_ref.fetch_add(1, Ordering::SeqCst) + 1)?;
                Ok(())
            }
        });
        let drive = async {
            anyhow::ensure!(receive.recv().await == Some(1));
            anyhow::ensure!(control.pending().await? == 0, "idle listener retained work");
            let terminated: Vec<bool> = sqlx::query_scalar(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name=$1 AND pid<>pg_backend_pid()",
            ).bind(&application).fetch_all(&f.pool).await?;
            anyhow::ensure!(terminated == [true], "listener connection not uniquely identified");
            anyhow::ensure!(receive.recv().await == Some(2), "reconnect did not check current authority");
            anyhow::ensure!(control.pending().await? == 0);
            let payload = serde_json::json!({"issuerHosts": [f.env.issuer_host]}).to_string();
            sqlx::query("SELECT pg_notify('aegaeon_runtime_authority_changed',$1)")
                .bind(payload).execute(&f.pool).await?;
            anyhow::ensure!(receive.recv().await == Some(3));
            stop(&state.runtime_restart);
            Ok::<_, anyhow::Error>(())
        };
        let (listen, driven) = tokio::time::timeout(Duration::from_secs(12), async {
            tokio::join!(runner, drive)
        }).await?;
        listen?;
        driven?;
        anyhow::ensure!(count.load(Ordering::SeqCst) == 3 && control.pending().await? == 0);
        anyhow::ensure!(control.observed_generation().await? == 3);
        Ok(())
    }.await;
    state.db_pool.close().await;
    let cleanup = control.finish().await.map_err(Into::into);
    f.cleanup(result.map_err(Into::into).and(cleanup)).await
}

#[tokio::test]
async fn organization_runtime_assembly_notification_stop_during_connect() -> TestResult {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let endpoint = format!("postgres://nobody:unused@{address}/unused?sslmode=disable");
    let restart = crate::runtime_restart::RuntimeRestartState::new();
    let run = notifications::run(&endpoint, "issuer.example", &restart, || async {
        anyhow::bail!("stalled unauthenticated connection must not call an authority check")
    });
    let stop_after_accept = async {
        let (_socket, _) = listener.accept().await?;
        stop(&restart);
        Ok::<_, std::io::Error>(())
    };
    let (run, stop) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(run, stop_after_accept)
    })
    .await?;
    run?;
    stop?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL; a failed check ends the listener without an ordinary fallback"]
async fn postgres_organizations_runtime_assembly_notification_failure_stops() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let endpoint = f.pool.connect_options().to_url_lossy();
        let count = AtomicUsize::new(0);
        let restart = crate::runtime_restart::RuntimeRestartState::new();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            notifications::run(endpoint.as_str(), &f.env.issuer_host, &restart, || async {
                count.fetch_add(1, Ordering::SeqCst);
                anyhow::bail!("injected admission refusal")
            }),
        )
        .await?;
        anyhow::ensure!(result.is_err() && count.load(Ordering::SeqCst) == 1);
        Ok(())
    }
    .await;
    f.cleanup(result.map_err(Into::into)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; restart waits for actual notification work completion"]
async fn shared_redis_organizations_runtime_assembly_notification_drain() -> TestResult {
    let f = Fixture::new().await?;
    let control = super::tests::witness(&f).await?;
    let state = test_app_state(f.pool.clone(), &f.env).await?;
    let result = async {
        let endpoint = f.pool.connect_options().to_url_lossy();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = tokio::sync::oneshot::channel();
        let mut inputs = Some((entered, wait));
        let caller = &control;
        let finished = std::sync::atomic::AtomicBool::new(false);
        let run = async {
            let result = notifications::run(
                endpoint.as_str(),
                &f.env.issuer_host,
                &state.runtime_restart,
                || {
                    let (entered, wait) = inputs.take().expect("only one check before shutdown");
                    async move {
                        caller
                            .run(async move {
                                let _ = entered.send(());
                                wait.await
                            })
                            .await??;
                        Ok(())
                    }
                },
            )
            .await;
            finished.store(true, Ordering::SeqCst);
            result
        };
        let drive = async {
            ready.await?;
            anyhow::ensure!(control.pending().await? == 1);
            stop(&state.runtime_restart);
            tokio::time::sleep(Duration::from_millis(50)).await;
            let returned_early = finished.load(Ordering::SeqCst);
            let retained = control.pending().await? == 1;
            // Release the real worker even when the early-completion mutant fails.
            let _ = release.send(());
            anyhow::ensure!(
                !returned_early && retained,
                "restart returned before observed work drained"
            );
            Ok::<_, anyhow::Error>(())
        };
        let (listen, driven) =
            tokio::time::timeout(Duration::from_secs(8), async { tokio::join!(run, drive) })
                .await?;
        listen?;
        driven?;
        anyhow::ensure!(control.pending().await? == 0);
        Ok(())
    }
    .await;
    state.db_pool.close().await;
    let cleanup = control.finish().await.map_err(Into::into);
    f.cleanup(result.map_err(Into::into).and(cleanup)).await
}
