mod key_store;
mod policy;
mod scope;

use super::super::configuration_documents::EnvironmentConfigurationState;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn persist_environment_configuration_state(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    state: &EnvironmentConfigurationState,
    request_id: &str,
) -> Result<(), Response> {
    policy::update_environment_policy_state(
        tx,
        environment_id,
        configuration_version_id,
        &state.policy,
        request_id,
    )
    .await?;
    scope::replace_environment_scope_allowlist_state(
        tx,
        environment_id,
        configuration_version_id,
        &state.scope_allowlist,
        request_id,
    )
    .await?;
    key_store::upsert_environment_key_store_state(
        tx,
        environment_id,
        configuration_version_id,
        state,
        request_id,
    )
    .await
}
