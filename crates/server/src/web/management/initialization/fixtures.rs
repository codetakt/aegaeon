//! Explicit test provisioning through the same environment/configuration writer.
use super::*;

pub(crate) async fn second_environment(
    pool: &PgPool,
    initialized: &InitializationOutput,
) -> Result<InitializationOutput> {
    let request = "independent-multiple-environment-fixture";
    let (slug, region): (String, String) =
        sqlx::query_as("SELECT slug,region FROM aegaeon.tenants WHERE id=$1 AND team_id=$2")
            .bind(initialized.tenant_id)
            .bind(initialized.team_id)
            .fetch_one(pool)
            .await?;
    let scope = ManagementTenantScope {
        team: initialized.team_id,
        tenant: initialized.tenant_id,
        slug,
        region,
    };
    let environment = CreateEnvironmentInput {
        slug: "secondary".into(),
        name: "Secondary fixture".into(),
    };
    let configuration =
        build_initial_environment_configuration("example.test", &scope, &environment, request)
            .map_err(response_error)?;
    let mut connection = transactions::connection(pool, request)
        .await
        .map_err(response_error)?;
    let mut tx = begin_bootstrap_transaction(&mut connection, request)
        .await
        .map_err(response_error)?;
    let created = create_environment_with_initial_configuration(
        &mut tx,
        &scope,
        &environment,
        &configuration,
        initialized.administrator_id,
        request,
    )
    .await
    .map_err(response_error)?;
    let committed = commit_management_transaction(tx, request).await;
    transactions::finish(committed, connection, request)
        .await
        .map_err(response_error)?;
    Ok(InitializationOutput {
        administrator_id: initialized.administrator_id,
        team_id: initialized.team_id,
        tenant_id: initialized.tenant_id,
        environment_id: created.environment_id,
        configuration_version_id: created.configuration_version_id,
        issuer_host: configuration.issuer_host,
    })
}
