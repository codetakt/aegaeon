mod audit;
mod persistence;

use super::super::ManagementTenantScope;
use super::{CreateEnvironmentInput, CreatedEnvironmentState, InitialEnvironmentConfiguration};
use crate::web::management::configuration_version_store::persist_environment_configuration_state;
use audit::write_environment_created_audit_event;
use axum::response::Response;
use persistence::{
    activate_environment_configuration, insert_environment_record,
    insert_initial_configuration_version, lock_active_tenant_for_environment_creation,
};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn create_environment_with_initial_configuration(
    tx: &mut Transaction<'_, Postgres>,
    scope: &ManagementTenantScope,
    input: &CreateEnvironmentInput,
    configuration: &InitialEnvironmentConfiguration,
    administrator_id: Uuid,
    request_id: &str,
) -> Result<CreatedEnvironmentState, Response> {
    let (environment_id, created_at) = insert_environment_record(
        tx,
        scope.tenant,
        input,
        &configuration.issuer_host,
        request_id,
    )
    .await?;
    let configuration_version_id = insert_initial_configuration_version(
        tx,
        environment_id,
        administrator_id,
        configuration,
        request_id,
    )
    .await?;
    let updated_at = activate_environment_configuration(
        tx,
        environment_id,
        configuration_version_id,
        request_id,
    )
    .await?;
    persist_environment_configuration_state(
        tx,
        environment_id,
        configuration_version_id,
        &configuration.state,
        request_id,
    )
    .await?;
    write_environment_created_audit_event(
        tx,
        scope,
        environment_id,
        configuration_version_id,
        &configuration.issuer_host,
        administrator_id,
        request_id,
    )
    .await?;

    Ok(CreatedEnvironmentState {
        environment_id,
        configuration_version_id,
        created_at,
        updated_at,
    })
}

pub(in crate::web::management) async fn lock_environment_creation_parent(
    tx: &mut Transaction<'_, Postgres>,
    scope: &ManagementTenantScope,
    request_id: &str,
) -> Result<Option<ManagementTenantScope>, Response> {
    let Some((slug, region)) =
        lock_active_tenant_for_environment_creation(tx, scope.team, scope.tenant, request_id)
            .await?
    else {
        return Ok(None);
    };

    Ok(Some(ManagementTenantScope {
        team: scope.team,
        tenant: scope.tenant,
        slug,
        region,
    }))
}
