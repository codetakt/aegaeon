use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::management::types::PolicyDocument;
use crate::web::management::configuration_documents::{
    load_policy_from_configuration_snapshot, parse_activated_environment_configuration,
    ActivatedEnvironmentConfiguration, LockedEnvironmentMutationContext,
};
use crate::web::management::configuration_federation::{
    federation_configuration_audit_snapshot, FederationConfigurationAuditSnapshot,
};
use crate::web::management::configuration_version_store::{
    load_configuration_document_for_update, load_configuration_document_required,
};
use crate::web::management::load_locked_environment_mutation_context;

pub(super) struct ActivationLoadedContext {
    pub(super) environment: LockedEnvironmentMutationContext,
    pub(super) previous_policy: PolicyDocument,
    pub(super) previous_audit_snapshot: FederationConfigurationAuditSnapshot,
    pub(super) activated_configuration: ActivatedEnvironmentConfiguration,
}

pub(super) async fn load_activation_context(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    request_id: &str,
) -> Result<ActivationLoadedContext, Response> {
    let environment =
        load_locked_environment_mutation_context(tx, team_id, environment_id, request_id).await?;
    let previous_configuration_document = load_configuration_document_required(
        tx,
        environment.scope.environment,
        environment.active_configuration_version_id,
        request_id,
    )
    .await?;
    let previous_policy =
        load_policy_from_configuration_snapshot(&previous_configuration_document, request_id)?;
    let previous_audit_snapshot =
        federation_configuration_audit_snapshot(&previous_configuration_document);
    let configuration_document = load_configuration_document_for_update(
        tx,
        environment.scope.environment,
        configuration_version_id,
        request_id,
    )
    .await?;
    let activated_configuration = parse_activated_environment_configuration(
        configuration_document,
        &environment.issuer_host,
        &environment.issuer_url,
        request_id,
    )?;

    Ok(ActivationLoadedContext {
        environment,
        previous_policy,
        previous_audit_snapshot,
        activated_configuration,
    })
}
