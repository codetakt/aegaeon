use super::super::configuration_federation::validate_federation_policy_for_environment;
use super::super::{management_internal_error, policy_patch};
use super::{
    load_policy_from_configuration_snapshot, parse_activated_environment_configuration,
    validate_patched_policy, LockedEnvironmentMutationContext, PolicyPatchDraft,
};
use crate::management::types::PolicyPatchRequest;
use axum::response::Response;

pub(in crate::web::management) fn policy_patch_comment(
    request: &PolicyPatchRequest,
) -> Option<&str> {
    request
        .comment
        .as_deref()
        .or(request.reason.as_deref())
        .or(Some("Policy update"))
}

pub(in crate::web::management) fn build_policy_patch_configuration(
    mut configuration_document: serde_json::Value,
    environment: &LockedEnvironmentMutationContext,
    request: &PolicyPatchRequest,
    request_id: &str,
) -> Result<PolicyPatchDraft, Response> {
    let policy_before =
        load_policy_from_configuration_snapshot(&configuration_document, request_id)?;
    let policy = policy_patch::apply_policy_patch(policy_before.clone(), request);
    let downgraded_fields = policy_patch::require_security_downgrade_authorization(
        &policy_before,
        &policy,
        policy_patch::SecurityDowngradeAuthorization {
            allowed: request.allow_security_downgrade == Some(true),
            reason: request.reason.as_deref(),
        },
        request_id,
    )?;
    validate_patched_policy(&policy, request_id)?;
    validate_federation_policy_for_environment(&policy, &environment.issuer_url, request_id)?;

    let Some(document) = configuration_document.as_object_mut() else {
        return Err(management_internal_error(
            request_id,
            "Invalid configuration snapshot",
        ));
    };
    let policy_value = serde_json::to_value(&policy)
        .map_err(|_| management_internal_error(request_id, "Failed to serialize policy"))?;
    document.insert("policy".to_string(), policy_value);
    document.insert(
        "issuerHost".to_string(),
        serde_json::Value::String(environment.issuer_host.clone()),
    );
    document.insert(
        "issuerUrl".to_string(),
        serde_json::Value::String(environment.issuer_url.clone()),
    );
    document.insert(
        "schemaVersion".to_string(),
        serde_json::Value::Number(serde_json::Number::from(1)),
    );

    let configuration = parse_activated_environment_configuration(
        configuration_document,
        &environment.issuer_host,
        &environment.issuer_url,
        request_id,
    )?;
    Ok(PolicyPatchDraft {
        configuration,
        downgraded_fields,
    })
}
