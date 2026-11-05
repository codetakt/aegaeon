//! Exercise the actual monitor operation within retained, observed store work.
use super::*;
use crate::{
    organizations::{repository_tests::Fixture, witness::tests::caller_fixture::CallerFixture},
    runtime_restart::RuntimeRestartReason,
    web::test_support::{test_app_state, TestResult},
};

pub(super) async fn witness(f: &Fixture) -> anyhow::Result<CallerFixture> {
    CallerFixture::with_observed_stores(
        f.env.environment_id,
        f.pool.connect_options().as_ref().clone(),
        redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?,
    )
    .await
}

pub(super) async fn loaded(f: &Fixture) -> anyhow::Result<DatabaseRuntimeConfiguration> {
    Ok(
        crate::runtime_configuration::load_database_runtime_configuration(
            &f.pool,
            &f.env.issuer_host,
        )
        .await?,
    )
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; actual observed monitor detects current policy change"]
async fn shared_redis_organizations_observed_monitor_normal_and_policy_change() -> TestResult {
    let f = Fixture::new().await?;
    let mut control = witness(&f).await?;
    let state = test_app_state(f.pool.clone(), &f.env)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let result = async {
        let configuration = loaded(&f).await?;
        let monitor = RuntimeConfigMonitor::from_state(&state, &configuration);
        control.run(monitor.check_revision()).await?;
        if state.runtime_restart.is_requested() || control.pending().await? != 0
            || control.observed_generation().await? != 1
            || control.completed_parent_generation().await? != 1 {
            return Err("normal observed monitor did not finish its first pass".into());
        }

        let mut document: serde_json::Value = sqlx::query_scalar(
            "SELECT configuration_document FROM aegaeon.active_runtime_environments WHERE environment_id=$1",
        ).bind(f.env.environment_id).fetch_one(&f.pool).await?;
        let original = document["policy"]["cleanupIntervalSeconds"].as_u64().ok_or("cleanup interval")?;
        document["policy"]["cleanupIntervalSeconds"] = serde_json::json!(if original == 61 { 62 } else { 61 });
        sqlx::query("UPDATE aegaeon.configuration_versions SET configuration_document=$1 WHERE environment_id=$2 AND status='ACTIVE'")
            .bind(document).bind(f.env.environment_id).execute(&f.pool).await?;
        control.run(monitor.check_revision()).await?;
        if !state.runtime_restart.is_requested()
            || !matches!(state.runtime_restart.request().ok_or("restart request")?.reason(), RuntimeRestartReason::RuntimeAuthorityDrift { .. })
            || control.pending().await? != 0 || control.observed_generation().await? != 2
            || control.completed_parent_generation().await? != 2 {
            return Err("policy drift did not request restart and complete its observed pass".into());
        }
        // The stale process requests restart; it does not replace its loaded policy.
        if state.runtime_authority.revision()?.active_configuration_document_fingerprint() != configuration.active_configuration_document_fingerprint {
            return Err("monitor replaced loaded policy instead of requesting restart".into());
        }
        Ok(())
    }.await;
    state.db_pool.close().await;
    let cleanup = control.finish().await.map_err(Into::into);
    f.cleanup(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; actual observed monitor stops after store failure"]
async fn shared_redis_organizations_observed_monitor_store_failure_requests_restart() -> TestResult
{
    let f = Fixture::new().await?;
    let control = witness(&f).await?;
    let state = test_app_state(f.pool.clone(), &f.env)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let result = async {
        let configuration = loaded(&f).await?;
        let monitor = RuntimeConfigMonitor::from_state(&state, &configuration);
        let before = state.runtime_authority.revision()?;
        state.db_pool.close().await;
        let completion = control.run(monitor.check_revision()).await;
        if !state.runtime_restart.is_requested()
            || !matches!(
                state
                    .runtime_restart
                    .request()
                    .ok_or("restart request")?
                    .reason(),
                RuntimeRestartReason::RuntimeAuthorityUnavailable { .. }
            )
            || state.runtime_authority.revision()? != before
            || control.pending().await? != u32::from(completion.is_err())
        {
            return Err("failed monitor did not retain safe restart/completion state".into());
        }
        Ok(())
    }
    .await;
    state.db_pool.close().await;
    let cleanup = control.finish().await.map_err(Into::into);
    f.cleanup(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; bootstrap reads require the selected Environment"]
async fn shared_redis_organizations_runtime_assembly_bootstrap_reads() -> TestResult {
    let f = Fixture::new().await?;
    let control = witness(&f).await?;
    let result = async {
        let config = control.run(loaded(&f)).await??;
        anyhow::ensure!(config.environment_id == f.env.environment_id);
        let state = test_app_state(f.pool.clone(), &f.env)
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let authority = config
            .derive_authorization_runtime(state.cfg.as_ref().clone())
            .await?;
        control
            .run(authority.observe(
                &f.pool,
                f.env.environment_id,
                &config.issuer_url,
                "unknown-client",
                &state.clients,
                None,
            ))
            .await??;
        let receipt = control
            .run(crate::web::namespace_runtime::validate_database_inputs(
                &f.pool,
                f.env.environment_id,
                &config.issuer_url,
            ))
            .await??;
        anyhow::ensure!(!receipt.is_nil() && control.pending().await? == 0);
        Ok(())
    }
    .await;
    let cleanup = control.finish().await.map_err(Into::into);
    f.cleanup(result.map_err(Into::into).and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; a selected foreign Environment cannot hydrate authority"]
async fn shared_redis_organizations_runtime_assembly_foreign_bootstrap_refused() -> TestResult {
    let f = Fixture::new().await?;
    let control = CallerFixture::with_observed_stores(
        uuid::Uuid::new_v4(),
        f.pool.connect_options().as_ref().clone(),
        redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?,
    )
    .await?;
    let result = async {
        let config = loaded(&f).await?;
        anyhow::ensure!(
            control.run(loaded(&f)).await?.is_err(),
            "foreign owner loaded policy"
        );
        anyhow::ensure!(
            control
                .run(crate::web::namespace_runtime::validate_database_inputs(
                    &f.pool,
                    f.env.environment_id,
                    &config.issuer_url,
                ))
                .await?
                .is_err(),
            "foreign owner received a namespace receipt"
        );
        anyhow::ensure!(control.pending().await? == 0);
        Ok(())
    }
    .await;
    let cleanup = control.finish().await.map_err(Into::into);
    f.cleanup(result.map_err(Into::into).and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; unbound work must not bypass startup connection ownership"]
async fn postgres_organizations_runtime_assembly_unbound_bootstrap_refused() -> TestResult {
    let f = Fixture::new().await?;
    let result: anyhow::Result<()> = async {
        let configuration = loaded(&f).await?;
        let state = test_app_state(f.pool.clone(), &f.env)
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let authority = configuration
            .derive_authorization_runtime(state.cfg.as_ref().clone())
            .await?;
        let local = crate::organizations::request_work::Admission::isolated_for_test()?;
        local
            .store_scope(async {
                anyhow::ensure!(loaded(&f).await.is_err(), "unbound owner loaded policy");
                anyhow::ensure!(
                    authority
                        .observe(
                            &f.pool,
                            f.env.environment_id,
                            &configuration.issuer_url,
                            "unknown-client",
                            &state.clients,
                            None
                        )
                        .await
                        .is_err(),
                    "unbound owner observed authorization"
                );
                anyhow::ensure!(
                    crate::web::namespace_runtime::validate_database_inputs(
                        &f.pool,
                        f.env.environment_id,
                        &configuration.issuer_url,
                    )
                    .await
                    .is_err(),
                    "unbound owner received namespace receipt"
                );
                Ok::<_, anyhow::Error>(())
            })
            .await??;
        Ok(())
    }
    .await;
    f.cleanup(result.map_err(Into::into)).await
}
