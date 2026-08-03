use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::management::types::PolicyDocument;
use crate::oidc::OidcConfig;
use crate::runtime_keys::{
    load_runtime_key_set_for_environment_in_tx, RuntimeKeySet, RuntimeKeyUsage,
};
use crate::web::management::configuration_documents::{
    ActivatedEnvironmentConfiguration, LockedEnvironmentMutationContext,
};
use crate::web::management::configuration_version_store::{
    persist_environment_configuration_state, switch_active_configuration_version,
};
use crate::web::management::{
    ensure_no_revocation_conflicts, error_response, management_internal_error,
};

pub(super) async fn persist_activation_state(
    tx: &mut Transaction<'_, Postgres>,
    environment: &LockedEnvironmentMutationContext,
    configuration_version_id: Uuid,
    activated_configuration: &ActivatedEnvironmentConfiguration,
    request_id: &str,
) -> Result<String, Response> {
    ensure_no_revocation_conflicts(
        tx,
        environment.scope.environment,
        &activated_configuration.configuration_document,
        request_id,
    )
    .await?;
    ensure_runtime_keys_compatible_with_policy(
        tx,
        environment.scope.environment,
        &environment.issuer_url,
        &activated_configuration.state.policy,
        request_id,
    )
    .await?;
    persist_environment_configuration_state(
        tx,
        environment.scope.environment,
        configuration_version_id,
        &activated_configuration.state,
        request_id,
    )
    .await?;
    switch_active_configuration_version(
        tx,
        environment.scope.environment,
        environment.active_configuration_version_id,
        configuration_version_id,
        request_id,
    )
    .await
}

async fn ensure_runtime_keys_compatible_with_policy(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    issuer_url: &str,
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    let runtime_keys = load_runtime_key_set_for_environment_in_tx(tx, environment_id)
        .await
        .map_err(|error| {
            tracing::error!(
                target: "management_configuration_activation",
                request_id,
                environment_id = %environment_id,
                error = %error,
                "failed to load runtime keys before configuration activation"
            );
            management_internal_error(request_id, "Failed to validate runtime keys")
        })?;

    runtime_keys
        .validate_allowed_signing_algorithms(&policy.allowed_signing_algorithms)
        .map_err(|error| {
            tracing::warn!(
                target: "management_configuration_activation",
                request_id,
                environment_id = %environment_id,
                error = %error,
                "configuration activation rejected because active runtime keys are incompatible with the requested signing policy"
            );
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Active runtime keys are incompatible with the requested signing policy",
                None,
                Some(request_id),
            )
        })?;
    ensure_required_runtime_keys_present(&runtime_keys, policy, environment_id, request_id)?;
    ensure_runtime_constructors_accept_policy(
        &runtime_keys,
        policy,
        issuer_url,
        environment_id,
        request_id,
    )
    .await
}

fn ensure_required_runtime_keys_present(
    runtime_keys: &RuntimeKeySet,
    policy: &PolicyDocument,
    environment_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    let missing = required_runtime_key_usages(policy)
        .into_iter()
        .filter(|usage| runtime_keys.active_key(*usage).is_none())
        .map(RuntimeKeyUsage::as_db_str)
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(());
    }

    tracing::warn!(
        target: "management_configuration_activation",
        request_id,
        environment_id = %environment_id,
        missing_runtime_keys = ?missing,
        "configuration activation rejected because enabled runtime features are missing ACTIVE runtime keys"
    );
    Err(error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "Configuration enables runtime features without required ACTIVE runtime keys",
        Some(serde_json::json!({
            "missingRuntimeKeys": missing,
        })),
        Some(request_id),
    ))
}

fn required_runtime_key_usages(policy: &PolicyDocument) -> Vec<RuntimeKeyUsage> {
    [
        (policy.oidc_enabled, RuntimeKeyUsage::OidcIdTokenSigning),
        (
            policy.jwt_access_tokens_enabled,
            RuntimeKeyUsage::JwtAccessTokenSigning,
        ),
        (
            policy.jwt_introspection_enabled,
            RuntimeKeyUsage::JwtIntrospectionSigning,
        ),
    ]
    .into_iter()
    .filter_map(|(required, usage)| required.then_some(usage))
    .collect()
}

async fn ensure_runtime_constructors_accept_policy(
    runtime_keys: &RuntimeKeySet,
    policy: &PolicyDocument,
    issuer_url: &str,
    environment_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    ensure_oidc_runtime_constructible(runtime_keys, policy, issuer_url, environment_id, request_id)
        .await?;
    ensure_jwt_key_managers_constructible(runtime_keys, policy, environment_id, request_id)
}

async fn ensure_oidc_runtime_constructible(
    runtime_keys: &RuntimeKeySet,
    policy: &PolicyDocument,
    issuer_url: &str,
    environment_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    OidcConfig::from_management_snapshot_async(issuer_url, policy, runtime_keys)
        .await
        .map(|_| ())
        .map_err(|error| {
            tracing::warn!(
                target: "management_configuration_activation",
                request_id,
                environment_id = %environment_id,
                error = %error,
                "configuration activation rejected because OIDC runtime construction failed"
            );
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Configuration cannot be constructed as an OIDC runtime snapshot",
                None,
                Some(request_id),
            )
        })
}

fn ensure_jwt_key_managers_constructible(
    runtime_keys: &RuntimeKeySet,
    policy: &PolicyDocument,
    environment_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    if policy.jwt_access_tokens_enabled {
        ensure_jwt_key_manager_constructible(
            runtime_keys,
            RuntimeKeyUsage::JwtAccessTokenSigning,
            environment_id,
            request_id,
        )?;
    }
    if policy.jwt_introspection_enabled {
        ensure_jwt_key_manager_constructible(
            runtime_keys,
            RuntimeKeyUsage::JwtIntrospectionSigning,
            environment_id,
            request_id,
        )?;
    }
    Ok(())
}

fn ensure_jwt_key_manager_constructible(
    runtime_keys: &RuntimeKeySet,
    usage: RuntimeKeyUsage,
    environment_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    crate::kms::ManagedJwtKeyManager::try_from_runtime_keys(runtime_keys, usage)
        .map(|_| ())
        .map_err(|error| {
            tracing::warn!(
                target: "management_configuration_activation",
                request_id,
                environment_id = %environment_id,
                runtime_key_usage = usage.as_db_str(),
                error = %error,
                "configuration activation rejected because JWT runtime key manager construction failed"
            );
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Configuration cannot be constructed with the active JWT runtime keys",
                None,
                Some(request_id),
            )
        })
}
