use uuid::Uuid;

use crate::management::types::{Environment, RuntimeActivationStatus};

use super::super::LockedEnvironmentMutationContext;
use super::types::ManagementEnvironmentRecord;

pub(in crate::web::management) fn environment_from_locked_context(
    context: &LockedEnvironmentMutationContext,
    active_configuration_version_id: Uuid,
    updated_at: String,
) -> Environment {
    Environment {
        id: context.scope.environment.to_string(),
        team_id: context.scope.team.to_string(),
        tenant_id: context.scope.tenant.to_string(),
        name: context.name.clone(),
        slug: context.slug.clone(),
        issuer_host: context.issuer_host.clone(),
        issuer_url: context.issuer_url.clone(),
        active_configuration_version_id: active_configuration_version_id.to_string(),
        created_at: context.created_at.clone(),
        updated_at,
    }
}

pub(in crate::web::management) fn environment_from_management_record(
    context: &ManagementEnvironmentRecord,
) -> Environment {
    Environment {
        id: context.scope.environment.to_string(),
        team_id: context.scope.team.to_string(),
        tenant_id: context.scope.tenant.to_string(),
        name: context.name.clone(),
        slug: context.slug.clone(),
        issuer_host: context.issuer_host.clone(),
        issuer_url: context.issuer_url.clone(),
        active_configuration_version_id: context.active_configuration_version_id.to_string(),
        created_at: context.created_at.clone(),
        updated_at: context.updated_at.clone(),
    }
}

pub(in crate::web::management) fn runtime_activation_status_for_management_database_write(
) -> RuntimeActivationStatus {
    RuntimeActivationStatus {
        runtime_reloaded: false,
        runtime_authority: "management-database-startup-snapshot".to_string(),
        persistence_authority: "management-database".to_string(),
        message: "Configuration was persisted and activated in the management database; running processes monitor the active configuration version and request a graceful restart for the current issuer so the supervisor can reload the new snapshot.".to_string(),
    }
}
