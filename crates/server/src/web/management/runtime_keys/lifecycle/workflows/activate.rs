use super::super::super::super::key_stores::normalize_key_store_audit_note;
use super::super::super::super::runtime_key_store::{
    activate_next_runtime_key_row, load_next_runtime_key_row_for_update,
    retire_active_runtime_keys, runtime_key_from_row, runtime_key_retiring_retention_seconds,
};
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, ensure_base_configuration_matches,
    environment_from_management_record, load_management_environment_record_for_update,
    parse_uuid_param, require_team_lifecycle_role, require_team_lifecycle_role_in_transaction,
    TeamEnvironmentPath,
};
use super::super::super::audit::{write_runtime_key_lifecycle_audit, RuntimeKeyLifecycleAudit};
use super::super::super::create::ensure_runtime_key_algorithm_allowed_by_policy;
use super::super::super::input::{normalize_runtime_key_algorithm, parse_runtime_key_usage};
use super::scope::runtime_key_not_found;
use crate::management::types::{ActivateRuntimeKeyRequest, RuntimeKeyMutationResponse};
use crate::web::management::configuration_version_store::load_environment_policy_document_in_transaction;
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

pub(in crate::web::management) async fn activate_next_runtime_key_inner(
    pool: &PgPool,
    path: &TeamEnvironmentPath,
    req: &ActivateRuntimeKeyRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<RuntimeKeyMutationResponse, Response> {
    let (team_id, environment_id) = path.ids(request_id)?;
    require_team_lifecycle_role(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions for runtime key operations",
    )
    .await?;
    let base_configuration_version_id = parse_uuid_param(
        &req.base_configuration_version_id,
        "baseConfigurationVersionId",
        request_id,
    )?;
    let usage = parse_runtime_key_usage(&req.usage, request_id)?;
    let algorithm = activation_algorithm(usage, req.algorithm.as_deref(), request_id)?;
    let comment = normalize_key_store_audit_note(req.comment.as_deref(), "comment", request_id)?;

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        team_id,
        session,
        request_id,
        "Insufficient permissions for runtime key operations",
    )
    .await?;
    let environment =
        load_management_environment_record_for_update(&mut tx, team_id, environment_id, request_id)
            .await?;
    ensure_base_configuration_matches(base_configuration_version_id, &environment, request_id)?;
    let policy = load_environment_policy_document_in_transaction(
        &mut tx,
        environment.scope.environment,
        request_id,
    )
    .await?;
    let next_runtime_key = select_next_runtime_key(
        &mut tx,
        environment.scope.environment,
        usage,
        algorithm.as_deref(),
        request_id,
    )
    .await?;
    let next_key_id = parse_uuid_param(&next_runtime_key.id, "runtimeKeyId", request_id)?;
    ensure_runtime_key_algorithm_allowed_by_policy(
        usage,
        &next_runtime_key.algorithm,
        &policy.allowed_signing_algorithms,
        request_id,
    )?;
    let retiring_retention_seconds = runtime_key_retiring_retention_seconds(&policy, usage);
    retire_active_runtime_keys(
        &mut tx,
        environment.scope.environment,
        usage,
        &next_runtime_key.algorithm,
        retiring_retention_seconds,
        request_id,
    )
    .await?;
    let Some(row) = activate_next_runtime_key_row(
        &mut tx,
        environment.scope.environment,
        usage,
        &next_runtime_key.algorithm,
        next_key_id,
        request_id,
    )
    .await?
    else {
        return Err(runtime_key_not_found(
            request_id,
            "NEXT runtime key disappeared during activation",
        ));
    };
    let runtime_key = runtime_key_from_row(&row, request_id)?;
    write_runtime_key_lifecycle_audit(
        &mut tx,
        &environment,
        session.administrator_id,
        request_id,
        RuntimeKeyLifecycleAudit {
            runtime_key: &runtime_key,
            event_type: "management.runtimeKey.activated.v1",
            operation: "ACTIVATE_NEXT",
            comment,
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(RuntimeKeyMutationResponse {
        runtime_key,
        environment: environment_from_management_record(&environment),
    })
}

async fn select_next_runtime_key(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    environment_id: uuid::Uuid,
    usage: super::super::super::input::RuntimeKeyUsageInput,
    algorithm: Option<&str>,
    request_id: &str,
) -> Result<crate::management::types::RuntimeKey, Response> {
    let next_key_rows =
        load_next_runtime_key_row_for_update(tx, environment_id, usage, algorithm, request_id)
            .await?;
    let Some(next_key_row) = next_key_rows.first() else {
        return Err(runtime_key_not_found(
            request_id,
            "No NEXT runtime key to activate for usage",
        ));
    };
    if next_key_rows.len() > 1 {
        return Err(crate::web::management::error_response(
            axum::http::StatusCode::CONFLICT,
            "invalid_request",
            "Multiple NEXT runtime keys exist; select an algorithm",
            Some(
                serde_json::json!({"usage": usage.as_db_str(), "allowedAlgorithms": ["RS256", "EdDSA"]}),
            ),
            Some(request_id),
        ));
    }
    runtime_key_from_row(next_key_row, request_id)
}

fn activation_algorithm(
    usage: super::super::super::input::RuntimeKeyUsageInput,
    algorithm: Option<&str>,
    request_id: &str,
) -> Result<Option<String>, Response> {
    algorithm
        .map(|algorithm| {
            if algorithm.trim().is_empty() {
                return Err(super::super::super::input::runtime_key_bad_request(
                    request_id,
                    "algorithm must be non-empty",
                    None,
                ));
            }
            normalize_runtime_key_algorithm(usage, Some(algorithm), request_id)
        })
        .transpose()
}
