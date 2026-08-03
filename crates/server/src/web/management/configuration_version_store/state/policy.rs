mod bind;

use super::super::super::configuration_documents::UPDATE_ENVIRONMENT_POLICY_SQL;
use super::super::super::management_internal_error;
use crate::management::types::PolicyDocument;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn update_environment_policy_state(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        r"
INSERT INTO aegaeon.environment_policies (environment_id, configuration_version_id)
VALUES ($1, $2)
ON CONFLICT (environment_id) DO NOTHING
        ",
    )
    .bind(environment_id)
    .bind(configuration_version_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to prepare environment policy"))?;

    let result = bind::bind_policy_update_fields(
        sqlx::query(UPDATE_ENVIRONMENT_POLICY_SQL)
            .bind(environment_id)
            .bind(configuration_version_id),
        policy,
        request_id,
    )?
    .execute(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to update environment policy"))?;
    if result.rows_affected() != 1 {
        return Err(management_internal_error(
            request_id,
            "Environment policy projection is missing",
        ));
    }

    Ok(())
}
