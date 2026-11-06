//! Actual production startup under deployment and Environment ownership.
use super::fixture::Context;
use super::*;

#[test]
#[ignore = "requires owned independent TLS PostgreSQL clusters, v8 catalog and TLS Redis"]
fn organization_production_startup_uses_parent_child_and_releases_actual_stores(
) -> anyhow::Result<()> {
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime.worker_threads(2);
    with_environment(runtime, || async {
        let Context {
            prepared,
            mut control,
            deployment,
            scope,
            initialized,
            issuer,
            ..
        } = super::fixture::prepare(false).await?;
        let pool = prepared.startup.pool.clone();
        let result = async {
            let (runtime, dispatcher) = prepared.build().await?;
            anyhow::ensure!(runtime.state.environment_id == initialized.environment_id);
            anyhow::ensure!(runtime.state.issuer.as_str() == issuer);
            anyhow::ensure!(control.pending(deployment).await?.state.pending == 0);
            anyhow::ensure!(
                control
                    .environment_maintenance()?
                    .pending(scope)
                    .await?
                    .state
                    .pending
                    == 0
            );
            let state = runtime.state.clone();
            dispatcher
                .start(CapacityClass::Ordinary, move || async move {
                    // Exercise the actual loaded runtime under a fresh work scope.
                    let owner =
                        crate::organizations::request_work::async_store::current_epoch_owner(
                            state.environment_id,
                        )?;
                    let mut connection = owner.connection(&state.db_pool).await?;
                    let environment: Uuid =
                        sqlx::query_scalar("SELECT id FROM aegaeon.environments WHERE id=$1")
                            .bind(state.environment_id)
                            .fetch_one(connection.as_mut()?)
                            .await?;
                    anyhow::ensure!(environment == state.environment_id);
                    connection.release().await;
                    Ok::<_, anyhow::Error>(())
                })?
                .result()
                .await??;
            anyhow::ensure!(control.pending(deployment).await?.state.pending == 0);
            anyhow::ensure!(
                control
                    .environment_maintenance()?
                    .pending(scope)
                    .await?
                    .state
                    .pending
                    == 0
            );
            // A real subsequent fence prevents the same constructor from serving again.
            control.fence(deployment, Uuid::new_v4(), 3).await?;
            anyhow::ensure!(dispatcher
                .start(CapacityClass::Ordinary, || async { true })?
                .result()
                .await
                .is_err());
            Ok::<_, anyhow::Error>(())
        }
        .await;
        tokio::time::timeout(Duration::from_secs(10), pool.close()).await?;
        control.close().await?;
        result
    })
}
