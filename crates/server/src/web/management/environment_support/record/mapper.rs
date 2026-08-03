use axum::response::Response;
use uuid::Uuid;

use super::super::super::{management_internal_error, ManagementEnvironmentScope};
use super::super::types::{EnvironmentRow, ManagementEnvironmentRecord};

pub(super) fn management_environment_record_from_row(
    team_id: Uuid,
    environment_id: Uuid,
    row: EnvironmentRow,
    request_id: &str,
) -> Result<ManagementEnvironmentRecord, Response> {
    let (
        tenant_id,
        name,
        slug,
        issuer_host,
        issuer_url,
        active_configuration_version_id,
        created_at,
        updated_at,
    ) = row;

    let Some(active_configuration_version_id) = active_configuration_version_id else {
        return Err(management_internal_error(
            request_id,
            "Environment is missing an active configuration version",
        ));
    };

    Ok(ManagementEnvironmentRecord {
        scope: ManagementEnvironmentScope {
            team: team_id,
            tenant: tenant_id,
            environment: environment_id,
        },
        name,
        slug,
        issuer_host,
        issuer_url,
        active_configuration_version_id,
        created_at,
        updated_at,
    })
}
