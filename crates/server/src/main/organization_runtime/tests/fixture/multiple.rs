//! Two real namespaces and current checkpoints before the owned cutover journey.
use super::*;

pub(in crate::server_runtime::organization_runtime::tests) async fn add_environment(
    context: &mut Context,
) -> Result<()> {
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(std::env::var(
        "AEGAEON_TEST_ORGANIZATION_STARTUP_FIXTURE",
    )?)?)?;
    let initialized = crate::web::management::initialization::fixtures::second_environment(
        &context.prepared.startup.pool,
        &context.initialized,
    )
    .await?;
    super::super::delivery_setup::enable_policy(&context.prepared.startup.pool, &initialized)
        .await?;
    let mut document: serde_json::Value = serde_json::from_slice(&context.configuration)?;
    let mut selection: Selection = serde_json::from_value(document["selection"].clone())?;
    let parent_epoch = selection.epoch;
    selection.epoch = Uuid::new_v4();
    let scope = Scope {
        environment_id: initialized.environment_id,
        deployment_id: context.deployment.uuid(),
    };
    let operation = Uuid::new_v4();
    let options = PgConnectOptions::from_str(&fixture.primary)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(&fixture.ca);
    let mut primary = Postgres::observe(sqlx::PgConnection::connect_with(&options).await?).await?;
    let redis = redis::Client::build_with_tls(
        fixture.token.as_str(),
        redis::TlsCertificates {
            client_tls: None,
            root_cert: Some(std::fs::read(&fixture.ca)?),
        },
    )?;
    let mut token = Redis::observe(redis.get_multiplexed_async_connection().await?).await?;
    let control = &mut context.control;
    control
        .environment_maintenance()?
        .initialize(scope, operation)
        .await?;
    control
        .environment_maintenance()?
        .prepare(scope, operation, 1, &selection)
        .await?;
    control
        .environment_maintenance()?
        .pin_store_progress(scope, operation, 2, &mut primary, &mut token)
        .await?;
    control
        .bind_child(
            context.deployment,
            parent_epoch,
            scope.environment_id,
            selection.epoch,
        )
        .await?;
    control
        .environment_maintenance()?
        .activate(scope, operation, 2, &selection.acceptance_sha256)
        .await?;
    primary.close().await?;
    token.close();
    document["environments"].as_array_mut().ok_or_else(|| anyhow::anyhow!("fixture environments missing"))?.push(json!({
        "id": initialized.environment_id, "issuer": format!("https://{}", initialized.issuer_host), "selection": selection_json(&selection)
    }));
    context.configuration = serde_json::to_vec(&document)?;
    Ok(())
}
