//! Production background assembly: initial work, parent fence and retained shutdown.
use super::*;
use crate::runtime_restart::RuntimeRestartRequest;
use crate::server_runtime::ObservedBackgroundTasks;

#[test]
#[ignore = "requires owned independent TLS PostgreSQL clusters, v8 catalog and TLS Redis"]
fn organization_production_background_initial_work_and_shutdown() -> Result<()> {
    exercise(false)
}

#[test]
#[ignore = "requires owned independent TLS PostgreSQL clusters, v8 catalog and TLS Redis"]
fn organization_production_background_parent_fence_stops_checks() -> Result<()> {
    exercise(true)
}

fn exercise(fence: bool) -> Result<()> {
    with_environment(tokio::runtime::Builder::new_current_thread(), || async {
        let super::fixture::Context {
            prepared,
            mut control,
            deployment,
            scope,
            ..
        } = super::fixture::prepare(true).await?;
        let pool = prepared.startup.pool.clone();
        let result = async {
        let (runtime, dispatcher) = super::fixture::build_for_fixture(prepared).await?;
        let tasks = ObservedBackgroundTasks::start(&runtime.state, &runtime.database_runtime_config, dispatcher, 3600, 3600).await?;
        anyhow::ensure!(control.pending(deployment).await?.state.pending == 0);
        anyhow::ensure!(control.environment_maintenance()?.pending(scope).await?.state.pending == 0);
        if fence {
            control.fence(deployment, Uuid::new_v4(), 3).await?;
            // Out-of-band fixture hint, not an admitted product mutation. The real
            // listener must acquire new authority before its authoritative read.
            sqlx::query("SELECT pg_notify('aegaeon_runtime_authority_changed',$1)")
                .bind(serde_json::json!({"issuerHosts":[runtime.database_runtime_config.issuer_host]}).to_string())
                .execute(&pool).await?;
            tokio::time::timeout(Duration::from_secs(10), runtime.state.runtime_restart.notified()).await?;
            anyhow::ensure!(tasks.drain().await.is_err());
        } else {
            runtime.state.runtime_restart.request_restart(RuntimeRestartRequest::runtime_critical_mutation(
                "background-test", runtime.database_runtime_config.issuer_host.clone(), "fixture_shutdown",
            ));
            tasks.drain().await?;
        }
        anyhow::ensure!(control.pending(deployment).await?.state.pending == 0);
        anyhow::ensure!(control.environment_maintenance()?.pending(scope).await?.state.pending == 0);
        Ok::<_, anyhow::Error>(())
    }.await;
        tokio::time::timeout(Duration::from_secs(10), pool.close()).await?;
        control.close().await?;
        result
    })
}
