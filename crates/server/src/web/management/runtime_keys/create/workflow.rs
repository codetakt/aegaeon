use super::super::audit::write_runtime_key_created_audit;
use super::super::input::{
    prepare_runtime_key_create_input_async, runtime_key_bad_request, RuntimeKeyUsageInput,
};
use crate::management::types::{CreateRuntimeKeyRequest, RuntimeKeyMutationResponse};
use crate::runtime_keys::canonical_runtime_signing_algorithm_name;
use crate::web::management::configuration_version_store::load_environment_policy_document_in_transaction;
use crate::web::management::runtime_key_store::{
    insert_runtime_key_row, retire_active_runtime_keys, runtime_key_from_row,
    runtime_key_retiring_retention_seconds,
};
use crate::web::management::state::ManagementSession;
use crate::web::management::{
    begin_management_transaction, commit_management_transaction, ensure_base_configuration_matches,
    environment_from_management_record, load_management_environment_record,
    load_management_environment_record_for_update, parse_uuid_param, require_team_lifecycle_role,
    require_team_lifecycle_role_in_transaction, required_row_value, TeamEnvironmentPath,
};
use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

pub(in crate::web::management) async fn create_runtime_key_inner(
    pool: &PgPool,
    path: &TeamEnvironmentPath,
    req: &CreateRuntimeKeyRequest,
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
    let environment =
        load_management_environment_record(pool, team_id, environment_id, request_id).await?;
    ensure_base_configuration_matches(base_configuration_version_id, &environment, request_id)?;
    let create_input =
        prepare_runtime_key_create_input_async(req, environment.scope.environment, request_id)
            .await?;

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
    ensure_runtime_key_algorithm_allowed_by_policy(
        create_input.usage,
        &create_input.algorithm,
        &policy.allowed_signing_algorithms,
        request_id,
    )?;
    if create_input.initial_status == "ACTIVE" {
        let retiring_retention_seconds =
            runtime_key_retiring_retention_seconds(&policy, create_input.usage);
        retire_active_runtime_keys(
            &mut tx,
            environment.scope.environment,
            create_input.usage,
            retiring_retention_seconds,
            request_id,
        )
        .await?;
    }

    let row = insert_runtime_key_row(&mut tx, &environment, &create_input, request_id).await?;
    let runtime_key_id: Uuid =
        required_row_value(&row, "id", request_id, "Failed to read runtime key id")?;
    write_runtime_key_created_audit(
        &mut tx,
        &environment,
        session.administrator_id,
        request_id,
        runtime_key_id,
        &create_input,
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(RuntimeKeyMutationResponse {
        runtime_key: runtime_key_from_row(&row, request_id)?,
        environment: environment_from_management_record(&environment),
    })
}

pub(in crate::web::management) fn ensure_runtime_key_algorithm_allowed_by_policy(
    usage: RuntimeKeyUsageInput,
    algorithm: &str,
    allowed_signing_algorithms: &[String],
    request_id: &str,
) -> Result<(), Response> {
    match usage {
        RuntimeKeyUsageInput::OidcIdTokenSigning
        | RuntimeKeyUsageInput::JwtAccessTokenSigning
        | RuntimeKeyUsageInput::JwtIntrospectionSigning => {
            ensure_runtime_key_signing_algorithm_allowed(
                algorithm,
                allowed_signing_algorithms,
                request_id,
            )
        }
        RuntimeKeyUsageInput::OidcRequestObjectDecryption => {
            ensure_runtime_key_decryption_algorithm_supported(algorithm, request_id)
        }
    }
}

pub(in crate::web::management) fn ensure_runtime_key_signing_algorithm_allowed(
    algorithm: &str,
    allowed_signing_algorithms: &[String],
    request_id: &str,
) -> Result<(), Response> {
    let Some(canonical) = canonical_runtime_signing_algorithm_name(algorithm) else {
        return Err(runtime_key_bad_request(
            request_id,
            "Unsupported runtime key signing algorithm",
            Some(serde_json::json!({
                "algorithm": algorithm,
            })),
        ));
    };
    let allowed = allowed_signing_algorithms
        .iter()
        .map(|value| {
            canonical_runtime_signing_algorithm_name(value).ok_or_else(|| {
                runtime_key_bad_request(
                    request_id,
                    "Invalid runtime key signing algorithm in active policy",
                    Some(serde_json::json!({
                        "invalidPolicyAlgorithm": value,
                        "allowedSigningAlgorithms": allowed_signing_algorithms,
                    })),
                )
            })
        })
        .collect::<Result<std::collections::BTreeSet<_>, Response>>()?;
    if allowed.contains(canonical) {
        return Ok(());
    }
    Err(runtime_key_bad_request(
        request_id,
        "Runtime key signing algorithm is not allowed by the active policy",
        Some(serde_json::json!({
            "algorithm": canonical,
            "allowedSigningAlgorithms": allowed_signing_algorithms,
        })),
    ))
}

fn ensure_runtime_key_decryption_algorithm_supported(
    algorithm: &str,
    request_id: &str,
) -> Result<(), Response> {
    if algorithm.trim().eq_ignore_ascii_case("RSA-OAEP+A256GCM") {
        return Ok(());
    }
    Err(runtime_key_bad_request(
        request_id,
        "Unsupported runtime key decryption algorithm",
        Some(serde_json::json!({
            "algorithm": algorithm,
            "supportedAlgorithms": ["RSA-OAEP+A256GCM"],
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_runtime_key_algorithm_allowed_by_policy,
        ensure_runtime_key_signing_algorithm_allowed, RuntimeKeyUsageInput,
    };

    #[test]
    fn runtime_key_signing_algorithm_allows_canonical_policy_match() {
        let allowed = vec!["RS256".to_string(), "EdDSA".to_string()];

        assert!(ensure_runtime_key_signing_algorithm_allowed("eddsa", &allowed, "req-1").is_ok());
    }

    #[test]
    fn runtime_key_signing_algorithm_rejects_unknown_requested_algorithm() {
        let allowed = vec!["RS256".to_string(), "EdDSA".to_string()];

        assert!(ensure_runtime_key_signing_algorithm_allowed("PS256", &allowed, "req-1").is_err());
    }

    #[test]
    fn runtime_key_signing_algorithm_rejects_unknown_policy_algorithm() {
        let allowed = vec!["RS256".to_string(), "PS256".to_string()];

        assert!(ensure_runtime_key_signing_algorithm_allowed("RS256", &allowed, "req-1").is_err());
    }

    #[test]
    fn runtime_key_policy_allows_request_object_decryption_without_signing_allowlist_entry() {
        let allowed = vec!["RS256".to_string(), "EdDSA".to_string()];

        assert!(ensure_runtime_key_algorithm_allowed_by_policy(
            RuntimeKeyUsageInput::OidcRequestObjectDecryption,
            "RSA-OAEP+A256GCM",
            &allowed,
            "req-1",
        )
        .is_ok());
    }

    #[test]
    fn runtime_key_policy_rejects_unknown_request_object_decryption_algorithm() {
        let allowed = vec!["RS256".to_string(), "EdDSA".to_string()];

        assert!(ensure_runtime_key_algorithm_allowed_by_policy(
            RuntimeKeyUsageInput::OidcRequestObjectDecryption,
            "RSA-OAEP",
            &allowed,
            "req-1",
        )
        .is_err());
    }
}
